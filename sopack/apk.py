"""APK / AAB repackaging + self-signing.

Flow: for each selected native library inside the container, inject (encrypt + stub),
write it back, strip the old signature, then align and sign.

The container is DETECTED from the input (`container.detect`), never declared - there is no
`--aab` flag and no config key for it. Only five things differ between the two, all of them read
off the `Container` descriptor: the entry pattern, where added artifacts go, whether an injected
library is stored uncompressed, whether the zip is 16 KB-aligned, and whether sopack signs at
all. See sopack/container.py.

  APK: entries are lib/<abi>/*.so; injected libraries are written STORED (uncompressed) so they
       stay page-mappable, the zip is `zipalign -P 16`ed, and it is self-signed with `apksigner`
       using a generated keystore.
  AAB: entries are <module>/lib/<abi>/*.so; entry compression is preserved and no alignment or
       signing happens, because bundletool - not sopack - generates the installable APKs from a
       bundle and makes those choices itself. The output is unsigned BY DESIGN; the operator
       signs it with `jarsigner` and their own upload key.

Selection is either an explicit list (libraries.include) or, when that list is omitted,
every native library in the input for the selected ABIs. Exclusion patterns always
win over selection; see ALWAYS_EXCLUDE_PATTERNS below.

Re-signing (APK only) changes the signing identity: the output is effectively a new app and
cannot be installed as an update over the original.
"""
from __future__ import annotations

import fnmatch
import glob
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from . import detect as detect_packed
from . import diag
from .container import APK as APK_CONTAINER, Container, detect as detect_container
from .errors import AlreadyPackedError, ToolMissingError
from .elf_inject import InjectError, InjectResult, inject_so
from .stubs import DEFAULT_ABIS, SUPPORTED_ABIS

# Excluded UNCONDITIONALLY: not overridable by naming one in libraries.include, and not
# removable by leaving them out of libraries.exclude. Patterns are fnmatch globs on the
# basename; a trailing ".so" is optional, so "libflutter" matches "libflutter.so".
#
# These two entries are here for DIFFERENT reasons - the old comment described only the
# first and was therefore untrue of the tuple it sat above:
#
#   libsopk_*        sopack's OWN injected artifacts - the shared provider
#                    (rt_meta.PROVIDER_SONAME) and the per-target thin helpers, emitted as
#                    libsopk_rt_<target>.so. Auto-selecting them on an already-packed APK
#                    would encrypt the very code that does the decrypting. This one is a
#                    correctness invariant of the tool, not a preference.
#   libvosWrapperEx  the V-Key/V-OS wrapper, which ships in the APKs this tool is used on
#                    and is already self-protected, so packing it buys nothing and risks
#                    interfering with its own integrity checks.
#
# Both are ALSO written into every generated config's `libraries.exclude` so a reader of the
# config can see them (config.LibraryConfig.exclude). That listing is for visibility only:
# this tuple is what makes deleting them there a no-op. build_excludes() de-duplicates, so
# appearing in both places costs nothing.
ALWAYS_EXCLUDE_PATTERNS = ("libsopk_*", "libvosWrapperEx")


# ---- external tool discovery ------------------------------------------------------
def _sdk_root() -> str | None:
    for var in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        v = os.environ.get(var)
        if v and os.path.isdir(v):
            return v
    return None


def find_tool(name: str) -> str:
    """Locate a build tool: PATH first, then the newest SDK build-tools dir."""
    p = shutil.which(name)
    if p:
        return p
    sdk = _sdk_root()
    if sdk:
        cands = sorted(glob.glob(os.path.join(sdk, "build-tools", "*", name)))
        if cands:
            return cands[-1]
    raise ToolMissingError(
        f"could not find '{name}'. Put it on PATH or set ANDROID_SDK_ROOT to your SDK."
    )


def find_keytool() -> str:
    p = shutil.which("keytool")
    if p:
        return p
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cand = os.path.join(jh, "bin", "keytool")
        if os.path.exists(cand):
            return cand
    raise ToolMissingError("could not find 'keytool'. Install a JDK or set JAVA_HOME.")


def apksigner_cmd() -> list[str]:
    """Command prefix to run apksigner. Order: SOPACK_APKSIGNER_JAR (java -jar), the
    `apksigner` launcher on PATH / in the SDK, else apksigner.jar found under the SDK."""
    jar = os.environ.get("SOPACK_APKSIGNER_JAR")
    if jar:
        return [shutil.which("java") or "java", "-jar", jar]
    launcher = shutil.which("apksigner")
    if launcher:
        return [launcher]
    sdk = _sdk_root()
    if sdk:
        for pat in ("build-tools/*/apksigner", "build-tools/*/lib/apksigner.jar"):
            cands = sorted(glob.glob(os.path.join(sdk, pat)))
            if cands:
                if cands[-1].endswith(".jar"):
                    return [shutil.which("java") or "java", "-jar", cands[-1]]
                return [cands[-1]]
    raise ToolMissingError(
        "could not find apksigner. Set SOPACK_APKSIGNER_JAR to apksigner.jar, or put "
        "apksigner on PATH, or set ANDROID_SDK_ROOT.")


# ---- keystore ---------------------------------------------------------------------
# Where a pack signs from when the caller names no keystore. A module constant rather than
# an inline literal because cli.py now builds a KeystoreInfo unconditionally (the config
# file always has keystore settings, even if they are all defaults) and both places have to
# mean the same file.
DEFAULT_KEYSTORE_PATH = os.path.join(os.path.expanduser("~"), ".sopack", "debug.keystore")


@dataclass
class KeystoreInfo:
    path: str
    alias: str = "sopack"
    store_pass: str = "sopack"
    key_pass: str = "sopack"


def ensure_keystore(ks: KeystoreInfo) -> KeystoreInfo:
    if os.path.exists(ks.path):
        return ks
    os.makedirs(os.path.dirname(os.path.abspath(ks.path)) or ".", exist_ok=True)
    cmd = [
        find_keytool(), "-genkeypair", "-v",
        "-keystore", ks.path, "-alias", ks.alias,
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "10000",
        "-storepass", ks.store_pass, "-keypass", ks.key_pass,
        "-dname", "CN=sopack, O=sopack, C=US",
    ]
    diag.debug(f"generating a keystore at {ks.path} (alias {ks.alias})")
    diag.log_subprocess(cmd)
    subprocess.run(cmd, check=True)
    return ks


class NothingPackedError(RuntimeError):
    """The pack ran but protected zero libraries.

    Its own class so `cli.main` can map it to a dedicated exit code instead of the generic 1 -
    "your APK came out with nothing encrypted" is a completely different thing for a caller to
    handle than "the packer crashed", and it used to be indistinguishable.

    Still a RuntimeError, so `cli.main`'s pre-existing except-tuple keeps catching it and nothing
    that calls `repackage` as a library has to change.

    Note this is deliberately NOT exit code 0. Making "nothing was encrypted" a success would
    invert what `set -e` and every CI runner read 0 as, guaranteeing that the one case most worth
    flagging is the one that goes unnoticed.

    **It carries the partial `RepackResult`.** Raising loses the accumulated per-library skips
    otherwise, and those ARE the diagnosis - the message itself ends with "see the per-library
    reasons above", which is terminal output, i.e. exactly what the run record exists to stop
    people depending on. With this, a code-6 report.json lists every candidate and why it was
    not packed.
    """

    def __init__(self, message: str, result: "RepackResult | None" = None) -> None:
        super().__init__(message)
        self.result = result


class SelectionError(NothingPackedError):
    """Nothing matched an EXPLICIT `libraries.include`.

    Narrower than its parent, and separated because the fix differs: this one means the names in
    the config do not match the APK's contents (a typo, or the wrong ABI), whereas a bare
    NothingPackedError means selection worked and every candidate was then excluded or failed.
    """


# ---- target selection -------------------------------------------------------------
@dataclass
class RepackResult:
    injected: list[InjectResult] = field(default_factory=list)
    # (entry, reason) for every native-library entry we deliberately did not select.
    untouched: list[tuple[str, str]] = field(default_factory=list)
    # (entry, InjectError message) for libraries that were selected but could not be
    # injected. Only ever populated in auto-select mode - an explicitly named library
    # still aborts the whole pack.
    failed: list[tuple[str, str]] = field(default_factory=list)
    output: str = ""
    # False when the output was left UNSIGNED. THREE different situations produce it and only the
    # first two are degradations:
    #   * signing.sign: false          - the caller asked for it
    #   * no apksigner on this machine - best-effort; the pack itself is done
    #   * the output is an AAB         - sopack never signs a bundle (see the signing block below)
    #   * the pack was a passthrough   - nothing was rewritten, so the input's OWN signature is
    #                                    still on it (see `passthrough` below)
    # An unsigned APK cannot be installed until something signs it, so the CLI has to say so
    # rather than letting a successful-looking pack imply an installable artifact. Consequence for
    # anyone consuming report.json: `signed: false` is NOT on its own a "this pack went wrong"
    # signal - read it together with `container`, or every bundle looks like a failure.
    signed: bool = True
    # Which container this was, as container.Container.kind ("apk" | "aab"). Recorded so the run
    # report and the CLI's closing advice can differ without re-detecting the format.
    container: str = APK_CONTAINER.kind
    # The O-MVLL seed this pack's stub was built with, when `obfuscate: true`. It is the only
    # handle that makes a given pack's stub reproducible afterwards, so it belongs in the run
    # record - not because it is secret (it is not; the stub ships) but because "which shape
    # did THIS app get?" is otherwise unanswerable.
    obf_seed: int | None = None
    # True when a TRACING helper was allowed into the output (logging.allow-helper-log). Such a
    # helper narrates the whole protocol in cleartext English format strings - target soname,
    # .text RVA and size, per-stage timings - which is exactly the leak HARDENING.md Method 5
    # exists to prevent. This has demonstrably reached a real output APK once
    # (docs/technical/STATIC-ANALYSIS-REVIEW.md S5), so the artifact is marked rather than
    # relying on whoever ran the pack to remember.
    helper_log_allowed: bool = False
    # Protected libraries that ALSO ship, unencrypted, under an ABI this pack did not cover -
    # in the SAME container. Each entry is (protected_entry, [cleartext_entry, ...]).
    #
    # This is not a warning about coverage, it is a bypass: under a static-analysis threat model
    # an analyst reading lib/armeabi-v7a/libfoo.so gets the same code the arm64 encryption was
    # protecting, for the cost of one unzip. Measured on a real shipped output, 20 of 21
    # protected libraries had such a counterpart.
    #
    # sopack does NOT close this (that would mean protecting every ABI, or dropping them from
    # the container - both are the operator's call, not the packer's). It reports it, so the
    # exposure is measured on every pack instead of invisible.
    cross_abi_cleartext: list[tuple[str, list[str]]] = field(default_factory=list)
    # True when the container held NO native libraries at all, so there was nothing sopack
    # could ever have protected and the input was copied through byte-for-byte. Not a
    # degradation and not an error - a pure-Java/Kotlin APK is a normal input for a pipeline
    # that packs every build - but it does change what the artifact IS, so it has to be
    # visible rather than inferred from `encrypted_count: 0`.
    #
    # It is also the third thing that sets `signed: false`, and the only one where that does
    # NOT mean "you must sign this before installing": the ORIGINAL signature is still intact,
    # because nothing was rewritten. Read `signed` together with `container` AND this.
    passthrough: bool = False


def find_cross_abi_cleartext(all_entries, protected, cont) -> list[tuple[str, list[str]]]:
    """Protected libraries whose SAME BASENAME also ships unencrypted elsewhere in the container.

    `all_entries` is every entry name from the input; `protected` the entries actually injected.
    Matching is by (module, basename) so a bundle's feature module cannot be confused with the
    base module - two modules may legitimately ship different libraries under one name.

    Uses `cont.lib_re`, the container's own pattern, rather than a second path parser. That is
    deliberate: the APK and AAB patterns are kept separate on purpose (a union would make sopack
    start matching `assets/lib/<abi>/*.so` in APKs), and a private parser here would be a third
    spelling of the same rule, free to drift from both.
    """
    protected_set = set(protected)
    by_key: dict[tuple[str, str], list[str]] = {}
    for name in all_entries:
        m = cont.lib_re.match(name)
        if not m:
            continue
        mod = m["mod"] if cont.has_module else ""
        by_key.setdefault((mod, m["so"]), []).append(name)

    out: list[tuple[str, list[str]]] = []
    for name in protected:
        m = cont.lib_re.match(name)
        if not m:
            continue
        mod = m["mod"] if cont.has_module else ""
        others = [e for e in by_key.get((mod, m["so"]), []) if e not in protected_set]
        if others:
            out.append((name, sorted(others)))
    return sorted(out)


def build_excludes(exclude_libs=None) -> tuple[str, ...]:
    """Assemble the effective exclusion pattern list, most-authoritative first.

    ALWAYS_EXCLUDE_PATTERNS is prepended unconditionally, so a caller that passes an empty
    list - or one that dropped `libsopk_*` from its config - still cannot select sopack's
    own decryptor. De-duplicated because every generated config already lists those
    patterns: without this the CLI's "excluding:" line would name each of them twice, which
    reads as a bug.
    """
    return tuple(dict.fromkeys(list(ALWAYS_EXCLUDE_PATTERNS) + list(exclude_libs or ())))


def _match_lib_pattern(entry: str, so: str, pat: str) -> bool:
    """fnmatch on the basename with an optional .so suffix; full paths also match.

    "Full path" means two things for a bundle, and both have to work. The entry there is
    `base/lib/arm64-v8a/libapp.so`, but every doc, every generated config and every user's muscle
    memory writes `lib/arm64-v8a/libapp.so` - so the module-relative form is matched too. Without
    it, moving from an APK to the AAB of the same app would silently stop matching an
    `include:`/`exclude:` entry that was written as a path, and silently NOT matching an exclude
    is how sopack's own decryptor would get packed.
    """
    # rindex on "/lib/", not index on "lib/": a module named "mylib" would otherwise be sliced
    # mid-name into "lib/lib/arm64-v8a/…". An APK entry has no leading segment, so rel == entry
    # and the extra clause below is a no-op there - the APK matcher is unchanged by design.
    rel = entry[entry.rindex("/lib/") + 1:] if "/lib/" in entry else entry
    return (fnmatch.fnmatch(so, pat)
            or fnmatch.fnmatch(so, pat + ".so")
            or fnmatch.fnmatch(entry, pat)
            or fnmatch.fnmatch(rel, pat))


def _classify(entry: str, abi: str, so: str, wanted: set[str] | None,
              abis: set[str], excludes: tuple[str, ...]) -> tuple[bool, str]:
    """(select?, reason-if-not). `wanted is None` means auto-select everything.

    Exclusion is checked before selection, so an excluded name is never packed even when
    it was named explicitly in libraries.include.
    """
    if abi not in abis:
        # Distinguish "you could widen `abis:` for this" from "sopack has no stub for it":
        # the entry pattern matches any <abi> directory name, including lib/x86/ and
        # lib/mips/ that `abis:` would reject outright.
        return False, ("abi not selected" if abi in SUPPORTED_ABIS
                       else "abi not supported by sopack")
    for pat in excludes:
        if _match_lib_pattern(entry, so, pat):
            return False, f"excluded by {pat!r}"
    if wanted is None:
        return True, ""
    # Same matcher as the exclusion loop above, deliberately: a full APK path, a bare
    # basename (which then applies to every ABI), an optional trailing ".so", and fnmatch
    # globs all work in BOTH lists. This used to be exact set membership, so `include:
    # [libapp]` silently matched nothing and the pack aborted with "no .so entries matched"
    # while `exclude: [libflutter]` - written the same way, two lines below it in the same
    # config - worked fine. One matcher is the only way that stays true as the file is edited.
    if any(_match_lib_pattern(entry, so, pat) for pat in wanted):
        return True, ""
    return False, "not requested"


def repackage(in_apk: str, out_apk: str, wanted_libs: list[str] | None,
              # This is the LIBRARY default and is unreachable from the CLI, which always
              # passes cipher= explicitly from the config. sopack/config.py owns the
              # user-facing default (wbaes). Do not "align" the two: flipping this to wbaes
              # fires the find_wb_keygen preflight below in every test that calls repackage
              # without a cipher, on machines that have no white-box build.
              cipher: str = "chacha20",
              abis: tuple[str, ...] = DEFAULT_ABIS,
              keystore: KeystoreInfo | None = None,
              min_sdk: int | None = None,
              log: bool = False,
              wb_keygen: str | None = None,
              allow_helper_log: bool = False,
              exclude_libs: list[str] | None = None,
              # Recompile a freshly-seeded, O-MVLL-obfuscated stub for THIS pack, instead of
              # injecting the prebuilt one. See sopack/obfuscate.py: the prebuilt stub is
              # byte-identical in every app, which makes its whitening key a public constant.
              # Stub ciphers only - wbaes does not use the stub at all.
              obfuscate: bool = False,
              no_sign: bool = False,
              # Proceed even when the input is recognisably a sopack OUTPUT. Off by default:
              # re-packing is destructive in wbaes mode and uncharacterised in the stub modes
              # (see sopack/detect.py). The escape hatch exists because detection reads
              # evidence out of arbitrary third-party binaries, and an operator who knows
              # better than the detector needs a way through that is not "edit the packer".
              allow_repack: bool = False,
              logger=print,
              # None means "look at the file". Detection is by content, so a library caller
              # normally leaves this alone; it exists so cli.py, which has already detected the
              # format in order to print it, does not have to re-read the central directory of a
              # 150 MB bundle. Additive, so every existing caller keeps working.
              container: Container | None = None) -> RepackResult:
    # Checked FIRST, before any file is opened: an argument contradiction should be reported as
    # such, not as whatever I/O error happens to come first. config.py rejects this combination
    # too, but repackage() is library API and can be called directly.
    if obfuscate and cipher == "wbaes":
        raise ValueError(
            "obfuscate is only meaningful for the stub ciphers; `cipher: wbaes` does not "
            "inject a stub at all, and already has per-pack key diversity.")
    # `None` means auto-select every native library; an empty list is NOT the same thing
    # (config.py rejects `libraries.include: []` rather than silently widening the scope).
    auto = wanted_libs is None
    wanted = None if auto else set(wanted_libs)
    excludes = build_excludes(exclude_libs)
    abis_set = set(abis)
    cont = container or detect_container(in_apk)
    result = RepackResult(output=out_apk, container=cont.kind,
                          helper_log_allowed=allow_helper_log)
    if allow_helper_log:
        diag.warn(
            "logging.allow-helper-log is set: a TRACING helper may be injected. Such a helper "
            "prints the target soname, its .text address and size, and per-stage timings to "
            "logcat, and ships those strings in cleartext in every packed library. The result "
            "is a diagnostic artifact - DO NOT SHIP IT.")

    # ---- central-directory pre-scan --------------------------------------------------
    # One read of the entry list, answering two questions that must both be settled BEFORE the
    # wbaes preflight below. Both would otherwise be reported as something they are not.
    with zipfile.ZipFile(in_apk, "r") as zpre:
        entry_names = zpre.namelist()

    # 1. Is this already one of our own outputs? The cheap tier only - it needs no
    #    decompression and catches every wbaes pack, which is the default cipher. The
    #    per-library tier runs inside the entry loop, where the bytes are already in hand.
    if not allow_repack:
        packed_entries = detect_packed.scan_entries(entry_names, cont)
        if packed_entries:
            shown = ", ".join(packed_entries[:4])
            more = f" (+{len(packed_entries) - 4} more)" if len(packed_entries) > 4 else ""
            raise AlreadyPackedError(
                f"this {cont.noun} is already packed by sopack: it contains {shown}{more}. "
                f"Re-packing would seal a second white-box key that the helpers already inside "
                f"cannot unwrap. Pack the ORIGINAL {cont.noun}, or set `allow-repack: true` if "
                f"you are certain.", packed_entries)

    # 2. Are there any native libraries at all? A container with none is NOT an error: sopack
    #    could never have protected anything, and a pipeline that packs every build hands us
    #    pure-Java/Kotlin APKs as a matter of course. Copy the input through and return.
    #
    #    This sits ABOVE the wbaes preflight deliberately. find_wb_keygen raises
    #    ToolMissingError (exit 7), so checking afterwards would leave a lib-free APK failing
    #    on any host without a host wb_keygen - a chacha20-only portable bundle, say - for a
    #    reason that has nothing to do with the input. There is nothing to seal here.
    #
    #    An EXPLICIT `libraries.include` still fails, and does so further down the same way it
    #    always has: the user named libraries that this container does not contain, which is a
    #    mistake worth reporting (SelectionError, exit 5). Only auto-select is forgiving.
    if auto and not any(cont.lib_re.match(n) for n in entry_names):
        # note_warning, not warn: with the exit code now 0, the run record is the only place a
        # batch consumer can still find this.
        diag.note_warning(
            f"WARNING: this {cont.noun} has no {cont.lib_shape} entries at all - there is "
            f"nothing for sopack to encrypt. The input was copied to the output unchanged.")
        # Verbatim, so the original signature survives: nothing was rewritten, so there is
        # nothing for a signature to have stopped matching. (copyfile raises SameFileError if
        # -o names the input, which is the right refusal - it would otherwise truncate it.)
        shutil.copyfile(in_apk, out_apk)
        result.passthrough = True
        result.signed = False           # sopack did not sign it; the INPUT's signature is intact
        return result

    # wbaes preflight: resolve a RUNNABLE host wb_keygen now, so a wrong tool fails before we
    # start injecting (not mid-pack). Also surfaces the Android-vs-host mistake up front.
    if cipher == "wbaes":
        from .provision import find_wb_keygen
        wb_keygen = find_wb_keygen(wb_keygen)   # raises with guidance if unusable
        logger(f"  using host wb_keygen: {wb_keygen}")

    with tempfile.TemporaryDirectory(prefix="sopack-") as tmp:
        unsigned = os.path.join(tmp, "unsigned.apk")
        aligned = os.path.join(tmp, "aligned.apk")

        matched_any = False
        candidates = 0                        # native-library entries seen, any ABI
        seen_names: set[str] = set()          # every entry written (collision guard)
        # wbaes: (entry name, bytes, target's ZIP date_time)
        extra_helpers: list[tuple[str, bytes, tuple[int, int, int, int, int, int]]] = []
        # wbaes: ONE long-term key and ONE shared provider per ABI. Sealed lazily on that
        # ABI's first target, then reused for every later target in it - which is what lets a
        # single ~455 KB blob replace N of them.
        #
        # Keyed on the BARE ABI even for a multi-module bundle, deliberately. A feature module's
        # `lib/arm64-v8a/` is a separate provider SLOT (each module becomes its own split APK, so
        # each needs its own copy of libsopk_wb.so), but every copy for an ABI must carry the SAME
        # sealed blob: bionic resolves a DT_NEEDED soname once per process, so whichever split's
        # copy wins has to unwrap every module's thin helpers. Sealing per (module, abi) would put
        # two different KEKs behind one soname and a helper from module A would unwrap against
        # module B's blob -> sopk_fail -> abort(), on essentially every launch.
        # ONE polymorphic stub set per pack, built before the entry loop and reused for every
        # library. Per-PACK, not per-library: the point is that two APKS differ, and rebuilding
        # per library would multiply an already slow step (a full clang+lld run through O-MVLL)
        # by the library count for no extra protection - every library in one app is reached by
        # the same analyst anyway.
        stub_dir = None
        if obfuscate:
            from .obfuscate import build_obfuscated_stubs
            stub_dir = os.path.join(tmp, "obfstubs")
            os.makedirs(stub_dir, exist_ok=True)
            result.obf_seed = build_obfuscated_stubs(stub_dir)

        pack_keys: dict[str, object] = {}
        # (module, abi) -> ZIP date_time to stamp that slot's provider with (see the helper note
        # below). "module" is "" for an APK, which has exactly one slot per ABI.
        provider_dates: dict[tuple[str, str], tuple[int, int, int, int, int, int]] = {}
        # (module, abi) -> thin helper sonames staged, for the pack-level closure assertion.
        thin_by_slot: dict[tuple[str, str], list[str]] = {}
        with zipfile.ZipFile(in_apk, "r") as zin, \
                zipfile.ZipFile(unsigned, "w") as zout:
            all_input_entries = [i.filename for i in zin.infolist()]
            for item in zin.infolist():
                name = item.filename
                # Drop the previous signature. An APK is re-signed below; a bundle is not, and
                # dropping it there is still right - a JAR signature's MANIFEST.MF holds a
                # SHA-256 digest of every entry, so once we have rewritten one it can never
                # verify again, and a stale signature is harder to diagnose than none.
                # Note this only matches the ROOT META-INF/, so a bundle's
                # <module>/root/META-INF/*.kotlin_module entries pass through untouched.
                if name.startswith("META-INF/") and re.search(r"\.(RSA|DSA|EC|SF|MF)$|MANIFEST\.MF$", name):
                    continue
                data = zin.read(name)
                m = cont.lib_re.match(name)
                select, why = (False, "")
                if m:
                    candidates += 1
                    # The second detection tier, run over EVERY candidate rather than only the
                    # selected ones - sopack's own artifacts are in ALWAYS_EXCLUDE_PATTERNS, so
                    # a selection-scoped check would never look at them. `data` is already in
                    # memory (read unconditionally above), so this costs a byte scan and one
                    # raw ELF parse.
                    #
                    # Raising here is safe: every intermediate lives in `tmp` and `out_apk` is
                    # not written until the very end, so an abort leaves no partial output.
                    if not allow_repack:
                        packed_why = detect_packed.scan_library(data)
                        if packed_why:
                            raise AlreadyPackedError(
                                f"{name} is already packed by sopack: {packed_why}. Re-packing "
                                f"would encrypt ciphertext a second time. Pack the ORIGINAL "
                                f"{cont.noun}, or set `allow-repack: true` if you are certain.",
                                [name])
                        maybe = detect_packed.scan_library_heuristic(data)
                        if maybe:
                            # Advisory ONLY. Other packers emit this same shape, and refusing
                            # a legitimate pack on a guess is worse than encrypting twice.
                            diag.note_warning(
                                f"WARNING: {name} looks like it may already be packed "
                                f"({maybe}). Packing it again is probably not what you want. "
                                f"If it is, this warning is harmless.")
                    select, why = _classify(name, m["abi"], m["so"],
                                            wanted, abis_set, excludes)
                    # Every selection decision, including the ones _print_summary collapses to a
                    # bare count as terminal noise. "why is this library in cleartext?" is the
                    # most common question about a pack, and this answers it per entry.
                    diag.debug(f"select {name}: "
                               + ("YES" if select else f"no ({why})"))
                if select:
                    abi = m["abi"]
                    # Where this library's sibling artifacts belong: "" for an APK, "base/" (or a
                    # feature module's name) for a bundle. Taken from the descriptor rather than
                    # by probing the match, so it lines up with the other four format decisions.
                    prefix = f"{m['mod']}/" if cont.has_module else ""
                    slot = (m["mod"] if cont.has_module else "", abi)
                    logger(f"  injecting {name} [{abi}] …")
                    src = os.path.join(tmp, "in.so")
                    dst = os.path.join(tmp, "out.so")
                    with open(src, "wb") as f:
                        f.write(data)
                    if cipher == "wbaes" and abi not in pack_keys:
                        # Sealed lazily, on this ABI's first target. That means a stale
                        # pre-3.0.0 wb_keygen fails mid-loop rather than up front - which is
                        # safe here only because every intermediate lives in `tmp` and
                        # `out_apk` is not written until signing, so a raise leaves no partial
                        # output. Do not move the output into the loop without hoisting this.
                        from .provision import provision_pack
                        logger(f"  sealing the shared white-box key for {abi} …")
                        pack_keys[abi] = provision_pack(wb_keygen=wb_keygen)
                    try:
                        ir = inject_so(src, dst, abi, cipher=cipher, log=log,
                                       wb_keygen=wb_keygen, target_name=m["so"],
                                       allow_helper_log=allow_helper_log,
                                       pack_key=pack_keys.get(abi),
                                       stub_dir=stub_dir)
                    except InjectError as e:
                        # An explicitly named library still aborts the pack - the user
                        # asked for THAT library and a silent downgrade to cleartext would
                        # be a lie. Under auto-select the list contains libraries the user
                        # never individually considered (prebuilts with no .text, no
                        # .dynamic slack, 4 KB-aligned arm64 …), so one of them must not
                        # kill the run; it is skipped and reported instead.
                        if not auto:
                            # inject_so reports the temp copy's path, not the APK entry -
                            # fine when one library was named, useless once selection is
                            # implicit. Prefix the entry either way.
                            raise InjectError(f"{name}: {e}") from e
                        logger(f"  warning: skipping {name}: {e}")
                        result.failed.append((name, str(e)))
                        # `data` is still the pristine zin.read(name) here - it is only
                        # reassigned below, after a successful inject. A raise also stages
                        # nothing: extra_helpers/thin_by_slot are fed from `ir`, which does
                        # not exist on this path.
                        zout.writestr(item, data)
                        seen_names.add(name)
                        continue
                    with open(dst, "rb") as f:
                        data = f.read()
                    # inject_so worked on a temp copy and cannot know the APK entry name, so
                    # stamp it here: the run report has to name the library it encrypted.
                    ir.entry = name
                    result.injected.append(ir)
                    matched_any = True
                    # wbaes: stage the per-target helper .so to add into lib/<abi>/.
                    # Carry the target's own timestamp: a default ZipInfo date_time is
                    # 1980-01-01, which stands out against the Gradle-built entries around it
                    # and marks the helpers as post-processed artifacts. That mismatch was the
                    # first thing a static-analysis report noticed about a shipped APK,
                    # before any disassembly.
                    if ir.helper_path and ir.helper_soname:
                        hname = f"{prefix}lib/{abi}/{ir.helper_soname}"
                        with open(ir.helper_path, "rb") as hf:
                            extra_helpers.append((hname, hf.read(), item.date_time))
                        thin_by_slot.setdefault(slot, []).append(ir.helper_soname)
                        provider_dates.setdefault(slot, item.date_time)
                    zi = zipfile.ZipInfo(name, date_time=item.date_time)
                    # APK: STORED so the .so stays uncompressed & page-alignable straight out of
                    # the zip. AAB: keep whatever compression it arrived with - bundletool
                    # re-packs the library into the split APKs it generates and chooses their
                    # compression there, so STORED here would only inflate the bundle.
                    zi.compress_type = (zipfile.ZIP_STORED if cont.store_libs
                                        else item.compress_type)
                    zi.external_attr = item.external_attr
                    zout.writestr(zi, data)
                    seen_names.add(name)
                else:
                    if m:
                        result.untouched.append((name, why))
                    # Preserve original entry (compression and all).
                    zout.writestr(item, data)
                    seen_names.add(name)

            # Emit ONE shared white-box provider per SLOT, after the loop - it carries that
            # ABI's single sealed blob, so it cannot be produced per target.
            from .elf_inject import emit_provider
            from .rt_meta import PROVIDER_SONAME
            # Keyed on thin_by_slot, NOT pack_keys: the key is sealed lazily *before*
            # inject_so, so an ABI whose every target was skipped (auto-select fail-soft
            # above) has a pack_keys entry but no thin helper. Emitting its provider would
            # add ~936 KB of white-box to the APK with nothing depending on it.
            #
            # A slot is (module, abi), so a multi-module bundle gets one provider per module that
            # actually staged helpers - each module ships as its own split APK and a thin helper
            # can only DT_NEEDED a library present alongside it. All copies for one ABI carry the
            # same blob, from the single pack_keys[abi]; see the note where pack_keys is declared
            # for why that identity is load-bearing rather than merely tidy.
            for (mod, abi), thin in thin_by_slot.items():
                pk = pack_keys[abi]
                pprefix = f"{mod}/" if mod else ""
                pname = f"{pprefix}lib/{abi}/{PROVIDER_SONAME}"
                ppath = os.path.join(tmp, f"provider-{pprefix.rstrip('/') or 'root'}-{abi}.so")
                # Names the module only when there is one, so an APK pack's output is unchanged
                # and a bundle's does not print the same ABI twice with nothing to tell the two
                # lines apart.
                logger(f"  emitting shared white-box provider for {pprefix}{abi} …")
                emit_provider(abi, pk, ppath, allow_helper_log=allow_helper_log)
                with open(ppath, "rb") as pf:
                    extra_helpers.append(
                        (pname, pf.read(),
                         provider_dates.get((mod, abi), (1980, 1, 1, 0, 0, 0))))

            # Add the wbaes helpers and providers as NEW entries (the packer's only add-file
            # path), under the same compression policy as an injected library: STORED for an APK
            # so they are page-mappable in place, DEFLATED for a bundle to match every other
            # `.so` in it, since bundletool re-packs them into the splits it generates.
            #
            # A collision is handled differently for the two kinds. For a per-target helper it is
            # benign - the soname is derived from the target and prefixed libsopk_rt_, so a clash
            # means the APK already had one and skipping keeps the existing bytes. For the
            # PROVIDER it is fatal: silently skipping it would leave every thin helper resolving
            # against a pre-existing libsopk_wb.so carrying a FOREIGN blob, so no session key
            # would unwrap and every target would abort on device.
            provider_names = {f"{mod + '/' if mod else ''}lib/{abi}/{PROVIDER_SONAME}"
                              for mod, abi in thin_by_slot}
            for hname, hdata, hdate in extra_helpers:
                if hname in seen_names:
                    if hname in provider_names:
                        raise RuntimeError(
                            f"{hname} already exists in this {cont.noun}. It cannot be reused: it "
                            "would carry a different sealed blob than the one the thin helpers "
                            "were wrapped against, so every packed library would fail to decrypt. "
                            f"Pack an {cont.noun} that has not already been packed.")
                    logger(f"  warning: helper {hname} already present; not overwriting")
                    continue
                logger(f"  adding {hname} …")
                zi = zipfile.ZipInfo(hname, date_time=hdate)
                zi.compress_type = (zipfile.ZIP_STORED if cont.store_libs
                                    else zipfile.ZIP_DEFLATED)
                zi.external_attr = (0o644 << 16)
                zout.writestr(zi, hdata)
                seen_names.add(hname)

            # Pack-level closure. `_self_verify_wbaes` runs per target and structurally cannot
            # see this: every thin helper depends on lib/<abi>/libsopk_wb.so, so if that entry is
            # missing the app fails 100% of the time, inside whatever dlopen'd the target.
            for (mod, abi), thin in thin_by_slot.items():
                pname = f"{mod + '/' if mod else ''}lib/{abi}/{PROVIDER_SONAME}"
                if pname not in seen_names:
                    raise RuntimeError(
                        f"{len(thin)} thin helper(s) for {abi} were staged but {pname} was not - "
                        f"every one of them DT_NEEDEDs it, so the app would fail to load. This "
                        f"is a packer bug, not a bad input.")

        # Computed BEFORE the nothing-packed raises below, so it is attached to `result` on
        # both paths - a code-6 report should still say what shipped in cleartext.
        # `all_input_entries` is the INPUT's entry list, so helpers added during the loop can
        # never be mistaken for a cleartext counterpart of themselves.
        result.cross_abi_cleartext = find_cross_abi_cleartext(
            all_input_entries, [ir.entry for ir in result.injected], cont)
        if result.cross_abi_cleartext:
            n = len(result.cross_abi_cleartext)
            diag.warn(
                f"{n} of {len(result.injected)} protected librar"
                f"{'y' if n == 1 else 'ies'} also ship UNENCRYPTED under another ABI in this "
                f"{cont.noun}. A static analyst can read the same code from the cleartext copy "
                f"without touching the encryption. Widen `abis:` to cover them, or drop those "
                f"ABIs from the input.")
            for prot, others in result.cross_abi_cleartext:
                diag.debug(f"cross-abi cleartext {prot}: also at {', '.join(others)}")

        if not matched_any:
            # `result` rides along on every one of these: it holds the accumulated per-library
            # skips, which are the actual diagnosis, and they would otherwise be discarded by the
            # raise and survive only as terminal output.
            if not auto:
                # Still an error, and deliberately so even when the container holds no native
                # libraries at all. The pre-scan's passthrough is scoped to auto-select: the
                # user who wrote `libraries.include` vouched for those names, and packing
                # nothing while reporting success would hide a typo'd or stale library list.
                raise SelectionError(
                    "no .so entries matched the requested list; nothing to encrypt. "
                    f"requested={sorted(wanted)}", result)
            # `candidates == 0` cannot reach here any more: under auto-select the pre-scan at
            # the top of this function copies the input through and returns before the entry
            # loop runs. So everything below means "there WERE libraries and none got packed",
            # which stays a failure - something shipped in cleartext that the operator expected
            # to be protected.
            raise NothingPackedError(
                f"none of the {candidates} {cont.lib_shape} entries in this {cont.noun} were "
                f"packed: "
                f"{len(result.untouched)} excluded or outside `abis:` "
                f"{','.join(sorted(abis_set))}, {len(result.failed)} could not be injected. "
                "See the per-library reasons above.", result)

        # `packed` is the finished zip, whichever of the two temp files that turns out to be.
        # It has to be a variable rather than the literal `aligned`, because the alignment step is
        # skipped for a bundle: reading `aligned` unconditionally below would then look for a file
        # that was never written and fail with FileNotFoundError - reported as an OUTPUT error,
        # blaming `-o`, after a full rezip of a ~150 MB input.
        if cont.zipalign:
            # Align uncompressed entries to 16 KB pages (native `zipalign` if present and
            # runnable, else the built-in Python aligner - needed on hosts without an
            # arch-matching zipalign, e.g. aarch64).
            _align_apk(unsigned, aligned, logger=logger)
            packed = aligned
        else:
            # Nothing to align: a bundle is not installed. bundletool reads it and generates the
            # split APKs, choosing their compression and page alignment from
            # `BundleConfig.pb`'s `optimizations.uncompress_native_libraries` - so entry offsets
            # in THIS zip are discarded before any device sees them. sopack deliberately neither
            # reads nor rewrites that setting: whichever way it is set, it moves together with
            # `extractNativeLibs`, so there is no combination in which skipping this breaks
            # loading (compressed libs are extracted to disk at install and mapped from there).
            logger(f"  not aligning: bundletool aligns native libraries when it generates APKs "
                   f"from this {cont.noun}")
            packed = unsigned

        # self-sign (v2/v3) with apksigner.
        #
        # Resolve apksigner BEFORE touching the keystore. ensure_keystore shells out to keytool
        # and writes ~/.sopack/debug.keystore, so probing in the other order generates a 2048-bit
        # key pair and only then discovers there is nothing to sign with - which is what used to
        # happen, and it left a keystore behind on a machine that cannot sign at all. The same
        # reasoning is why `not cont.sign` skips ensure_keystore entirely instead of signing into
        # a keystore nobody asked for.
        signer: list[str] | None = None
        if not cont.sign:
            # sopack NEVER signs a bundle, and this is a design decision, not a missing feature:
            #   * apksigner physically cannot - it needs a root AndroidManifest.xml, and a bundle's
            #     manifest lives at <module>/manifest/ in protobuf form. It fails with
            #     "ApkFormatException: Missing AndroidManifest.xml".
            #   * a bundle is JAR-signed (jarsigner), and the signature Play actually checks is the
            #     app's UPLOAD key - a key sopack has no business holding, and one that a debug
            #     keystore cannot stand in for.
            # So the artifact is handed over unsigned and the operator signs it. The old signature
            # is still stripped in the entry loop above: MANIFEST.MF carries a SHA-256 digest of
            # every entry, so a signature that can no longer verify is worse than none - it turns
            # "unsigned, go sign it" into a confusing jarsigner -verify failure.
            logger(f"  not signing: a packed {cont.noun} is left unsigned for you to sign with "
                   f"your own upload key")
            if no_sign:
                logger("  (signing.sign: false was set too, so this changes nothing)")
        elif no_sign:
            logger("  skipping signing (signing.sign: false)")
        else:
            try:
                signer = apksigner_cmd()
            except FileNotFoundError as e:
                # Best-effort by design: the packing work is done and the aligned APK is a
                # legitimate artifact for a pipeline that signs with its own production key
                # later. Refusing here would throw that away over a missing tool.
                logger(f"  WARNING: {e}")
                logger("  WARNING: leaving the output UNSIGNED. It cannot be installed as-is - "
                       "sign it before `adb install`, or set `signing.sign: false` to make this "
                       "explicit.")

        if signer is None:
            result.signed = False
            shutil.copyfile(packed, out_apk)
        else:
            ks = keystore or KeystoreInfo(path=DEFAULT_KEYSTORE_PATH)
            ensure_keystore(ks)
            sign_cmd = signer + [
                "sign",
                "--ks", ks.path, "--ks-key-alias", ks.alias,
                "--ks-pass", f"pass:{ks.store_pass}", "--key-pass", f"pass:{ks.key_pass}",
            ]
            if min_sdk is not None:
                sign_cmd += ["--min-sdk-version", str(min_sdk)]
            sign_cmd += ["--out", out_apk, packed]
            diag.log_subprocess(sign_cmd)
            subprocess.run(sign_cmd, check=True)

    return result


# ---- 16 KB alignment --------------------------------------------------------------
def _align_apk(src: str, dst: str, page: int = 16384, logger=print) -> None:
    zipalign = shutil.which("zipalign")
    if not zipalign:
        sdk = _sdk_root()
        if sdk:
            c = sorted(glob.glob(os.path.join(sdk, "build-tools", "*", "zipalign")))
            zipalign = c[-1] if c else None
    if zipalign:
        cmd = [zipalign, "-P", str(page // 1024), "-f", "4", src, dst]
        try:
            out = subprocess.run(cmd, check=True, capture_output=True)
            diag.log_subprocess(cmd, out.returncode, out.stdout, out.stderr)
            return
        except (subprocess.CalledProcessError, OSError) as e:
            diag.log_subprocess(cmd, getattr(e, "returncode", None),
                                getattr(e, "stdout", None), getattr(e, "stderr", None))
            logger(f"  (native zipalign unusable: {e}; using built-in aligner)")
    diag.debug(f"aligning with the built-in Python aligner (page={page})")
    python_zipalign(src, dst, page)


def python_zipalign(src: str, dst: str, page: int = 16384) -> None:
    """Rewrite a zip so every STORED entry's data begins on an aligned offset (16 KB
    for .so, 4 bytes otherwise) by padding the local-header extra field. Compressed
    entries are copied unchanged. Mirrors what `zipalign -P` does before apksigner."""
    with zipfile.ZipFile(src, "r") as zin, zipfile.ZipFile(dst, "w") as zout:
        for item in zin.infolist():
            data = zin.read(item.filename)
            if item.compress_type == zipfile.ZIP_STORED:
                align = page if item.filename.endswith(".so") else 4
                # local header = 30 + name + extra; pad extra so data offset % align == 0
                base = zout.fp.tell() + 30 + len(item.filename.encode("utf-8"))
                pad = (-(base + len(item.extra))) % align
                if pad:
                    item.extra = (item.extra or b"") + b"\x00" * pad
            zout.writestr(item, data)


def verify_signature(apk: str, min_sdk: int | None = None) -> str:
    cmd = apksigner_cmd() + ["verify", "--print-certs"]
    if min_sdk is not None:
        cmd += ["--min-sdk-version", str(min_sdk)]
    cmd.append(apk)
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        # apksigner's own explanation is the whole diagnosis here, and it would otherwise be
        # discarded: cli.main renders CalledProcessError as its bare str(), which names the exit
        # status and nothing else.
        diag.log_subprocess(cmd, e.returncode, e.stdout, e.stderr)
        raise
    diag.log_subprocess(cmd, out.returncode, out.stdout, out.stderr)
    return out.stdout
