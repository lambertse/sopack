"""Per-pack polymorphic stub (`obfuscate: true`).

The property under test is NOT "the stub is bigger" or "O-MVLL ran". It is that the
**whitening key differs between two packs**. That key is a checksum over the stub's own bytes,
so a byte-identical stub means a byte-identical key in every app on earth, and an analyst needs
no reverse engineering to write a universal unpacker (STATIC-ANALYSIS-REVIEW.md S2). Everything
else here is scaffolding around that one assertion.
"""
from __future__ import annotations

import json
import zipfile
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from sopack import config
from sopack.cipher import WHITEN_SPAN, whiten_key
from sopack.config import ConfigError

REPO = Path(__file__).resolve().parent.parent


# ---- config surface (no toolchain needed) -----------------------------------------------

def test_obfuscate_defaults_off():
    assert config.Config.default().obfuscate is False


def test_obfuscate_accepts_a_bool():
    assert config.loads("cipher: chacha20\nobfuscate: true").obfuscate is True


def test_obfuscate_with_wbaes_is_an_error_not_a_no_op():
    """wbaes injects no stub, so honouring this would do nothing. Silently doing nothing is the
    failure the whole config layer exists to prevent."""
    with pytest.raises(ConfigError, match="not compatible with cipher: wbaes"):
        config.loads("obfuscate: true")


def test_obfuscate_rejects_a_non_bool():
    with pytest.raises(ConfigError, match="expected true or false"):
        config.loads("cipher: chacha20\nobfuscate: sure")


def test_repackage_refuses_obfuscate_with_wbaes_directly():
    """repackage() is library API and can bypass config validation."""
    from sopack.apk import repackage
    with pytest.raises(ValueError, match="only meaningful for the stub ciphers"):
        repackage("in.apk", "out.apk", None, cipher="wbaes", obfuscate=True)


def test_missing_toolchain_reports_as_a_toolchain_error():
    """ObfuscationUnavailableError must map to exit 7, not to 'missing input file' (4)."""
    from sopack.errors import ToolMissingError
    from sopack.obfuscate import ObfuscationUnavailableError
    assert issubclass(ObfuscationUnavailableError, ToolMissingError)
    from sopack import exitcodes
    from sopack.cli import code_for
    assert code_for(ObfuscationUnavailableError("x")) == exitcodes.TOOLCHAIN


# ---- the real thing: needs the NDK + an O-MVLL plugin ------------------------------------

def _toolchain():
    """(ndk, plugin, pythonpath) or None. Skips rather than fails: most machines have neither.

    Delegates to the SHIPPING gate, `obfuscate.resolve_toolchain()`, so the test's idea of a
    usable toolchain cannot drift from the packer's - it had drifted: this checked only that
    ANDROID_NDK_HOME was NON-EMPTY, so a stale or misspelled path ran the test instead of
    skipping it, and the failure surfaced as a raw clang error naming no NDK.

    It validates PATHS, not capability. An NDK that exists but cannot load the r29-pinned plugin
    still fails loudly, and should: build_wbaes.sh Phase 4 hands that same clang the same plugin,
    so a skip here would only move the failure later.
    """
    from sopack.obfuscate import (ObfuscationMisconfiguredError, ObfuscationUnavailableError,
                                  resolve_toolchain)
    ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    try:
        plugin, pylib = resolve_toolchain()
    except ObfuscationMisconfiguredError as e:
        # NOT a skip. A variable pointing at nonsense would otherwise silently skip the one test
        # that proves two packs get different whitening keys, and a green suite would mean
        # nothing - the exact way this failure hid before.
        pytest.fail(f"the obfuscation toolchain is CONFIGURED BUT UNUSABLE, so this test can "
                    f"neither run nor honestly skip:\n{e}")
    except ObfuscationUnavailableError:
        return None
    if not (ndk and shutil.which("bash")):
        return None
    if not (Path(plugin).is_file() and Path(pylib).is_dir()):
        return None
    return ndk, plugin, pylib


def _build(tmp_path, seed):
    tc = _toolchain()
    if tc is None:
        pytest.skip("no NDK + O-MVLL toolchain on this host")
    ndk, plugin, pylib = tc
    out = tmp_path / f"s{seed}"
    out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ,
               ANDROID_NDK_HOME=ndk, OMVLL_PLUGIN=plugin, OMVLL_PYTHONPATH=pylib,
               OMVLL_CONFIG=str(REPO / "stub" / "omvll_config.py"),
               SOPK_SEED=str(seed), SOPK_STUB_OUT=str(out))
    r = subprocess.run(["bash", str(REPO / "stub" / "build_stubs.sh")],
                       env=env, cwd=str(out), capture_output=True, text=True)
    if r.returncode != 0:
        # Both streams, and a tail long enough to hold a whole guard message: build_stubs.sh's
        # diagnostics are multi-line, and the 200-char stderr-only version cut them off mid-
        # sentence - on the one path whose only output is this skip reason.
        pytest.skip("O-MVLL build unavailable here (exit "
                    f"{r.returncode}):\n{(r.stdout + r.stderr).strip()[-1500:]}")
    return out


def _span_key(stub_dir):
    meta = json.loads((stub_dir / "stub_arm64-v8a.json").read_text())
    blob = (stub_dir / "stub_arm64-v8a.bin").read_bytes()
    off = meta["decinfo_off"]
    assert off >= WHITEN_SPAN, "obfuscated stub must still leave a full whitening span"
    return whiten_key(blob[off - WHITEN_SPAN:off]), blob, meta


@pytest.mark.slow
def test_two_seeds_produce_different_whitening_keys(tmp_path):
    """THE assertion. Different key per pack == no universal unpacker."""
    k1, b1, _ = _span_key(_build(tmp_path, 111))
    k2, b2, _ = _span_key(_build(tmp_path, 222))
    assert k1 != k2, "same whitening key from two seeds - polymorphism is not working"
    n = min(len(b1), len(b2))
    differing = sum(1 for i in range(n) if b1[i] != b2[i])
    # The branch that introduced this claimed ~85-90%; measured 88.6%. Assert well below that
    # so a pass-set change does not fail the suite spuriously, but high enough that a
    # near-identical build cannot pass.
    assert differing / n > 0.5, f"only {100*differing/n:.1f}% of stub bytes differ"


@pytest.mark.slow
def test_a_seed_is_reproducible(tmp_path):
    """Polymorphic, not random: the seed has to reproduce the same stub, or report.json's
    obf_seed would be a meaningless record."""
    a = (_build(tmp_path / "a", 4242) / "stub_arm64-v8a.bin").read_bytes()
    b = (_build(tmp_path / "b", 4242) / "stub_arm64-v8a.bin").read_bytes()
    assert a == b, "same seed produced different stubs"


# ---- end to end through repackage() ------------------------------------------------------
#
# The build-level tests above prove build_stubs.sh produces divergent stubs. This proves the
# PACK path actually uses them: repackage -> inject_so -> load_stub(abi, stub_dir). That
# threading is where the deliverable property lives, and it is easy to wire up wrongly in a way
# every other test still passes (a pack that silently injects the prebuilt stub looks fine).

@pytest.mark.slow
def test_two_obfuscated_packs_of_one_library_get_different_whitening_keys(tmp_path):
    if _toolchain() is None:
        pytest.skip("no NDK + O-MVLL toolchain on this host")
    from conftest import mkapk
    from sopack.apk import repackage
    from sopack.metadata import MAGIC

    fixture = (REPO / "tests" / "fixtures" / "mini_arm64.so").read_bytes()
    src = tmp_path / "in.apk"
    mkapk(src, ["lib/arm64-v8a/libt.so"], body=fixture)

    keys, seeds = [], []
    for i in (1, 2):
        out = tmp_path / f"out{i}.apk"
        # No explicit seed: this is the branch repackage() actually takes
        # (secrets.randbelow), and nothing else covers it.
        res = repackage(str(src), str(out), None, cipher="chacha20",
                        abis=("arm64-v8a",), obfuscate=True, no_sign=True,
                        logger=lambda *_a, **_k: None)
        assert res.obf_seed is not None, "obf_seed must be recorded for reproducibility"
        seeds.append(res.obf_seed)
        with zipfile.ZipFile(out) as z:
            packed = z.read("lib/arm64-v8a/libt.so")
        keys.append(_recover_whitening_key(packed))

    assert seeds[0] != seeds[1], "two packs reused one seed"
    assert keys[0] is not None and keys[1] is not None, "could not locate the injected stub"
    # THE assertion, at pack level: no constant to precompute across apps.
    assert keys[0] != keys[1], (
        "two obfuscated packs produced the SAME whitening key - the universal-unpacker "
        "attack still works, so the polymorphism is not reaching the injected stub")


def _recover_whitening_key(packed: bytes):
    """Re-run the S2 attack against a packed library and return the whitening key it yields.

    SCANS rather than assuming a fixed offset, and that is not incidental: polymorphism moves
    g_decinfo to a different offset in every build, and the injected segment can carry
    alignment padding past the end of the blob, so "the last 128 bytes of the segment" is wrong
    in general. An earlier version assumed exactly that and passed locally while failing in the
    builder container.

    Scanning is also the honest reproduction of the attack. `magic == b'SOPK'` after de-whitening
    is a self-verifying 32-bit oracle, so an analyst does not need to know the offset either -
    they try candidates until one validates, which is precisely what this does.
    """
    import lief
    from sopack.cipher import WHITEN_SPAN, whiten, whiten_key
    from sopack.metadata import MAGIC, SIZE

    b = lief.parse(list(packed))
    if b is None:
        return None
    want = MAGIC.to_bytes(4, "little")
    for seg in b.segments:
        if seg.type != lief.ELF.Segment.TYPE.LOAD:
            continue
        flags = int(seg.flags)
        if not (flags & 0x1 and flags & 0x4):        # PF_X | PF_R: the injected stub segment
            continue
        blob = bytes(seg.content)
        # g_decinfo is 8-aligned in .sopk_info; step 4 anyway, it is only a few hundred tries.
        for rec_off in range(WHITEN_SPAN, len(blob) - SIZE + 1, 4):
            span = blob[rec_off - WHITEN_SPAN:rec_off]
            rec = whiten(blob[rec_off:rec_off + SIZE], span)
            if rec[:4] == want:
                return whiten_key(span)
    return None


def test_omvll_configs_use_method_names_the_plugin_actually_dispatches():
    """ObfuscationConfig dispatches by EXACT method name and silently ignores an unknown one.

    stub/omvll_config_wb.py once defined `flatten_functions`, which does not exist in O-MVLL
    1.6.0 or 1.9.1 - so control-flow flattening, the single biggest transform, never ran. It
    failed silently and looked exactly like a working build. Measured, same source, same
    plugin, that one name: 1247 .text instructions vs 2223 with `flatten_cfg`.

    The valid set comes from the plugin's own sample-omvll-config.py, identical in both
    versions. Anything outside it is dead code that reads as a shipped control.
    """
    valid = {
        "obfuscate_arithmetic", "flatten_cfg", "obfuscate_string", "indirect_call",
        "break_control_flow", "function_outline", "basic_block_duplicate",
        "__init__",
    }
    import ast as _ast
    for name in ("omvll_config.py", "omvll_config_wb.py"):
        tree = _ast.parse((REPO / "stub" / name).read_text())
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.ClassDef):
                continue
            for fn in [n for n in node.body if isinstance(n, _ast.FunctionDef)]:
                assert fn.name in valid, (
                    f"stub/{name}: {node.name}.{fn.name}() is not an O-MVLL "
                    f"ObfuscationConfig method - it will never be called. "
                    f"Valid: {sorted(valid - {'__init__'})}")


# ---- the build_stubs.sh toolchain guards (no real toolchain needed) ----------------------
#
# These run everywhere, with shims. They exist because the guards they cover are exactly the
# kind that fail OPEN when edited: the -fpass-plugin probe was first written as
# `"$CLANG" … | grep -q "unknown argument"`, which under `set -o pipefail` reports the probe's
# non-zero exit instead of grep's match - so the `if` never fired and the check silently passed
# on the one toolchain it exists to reject. Same lesson as test_exitcodes.py: a guard nothing
# drives is not evidence of a guard.

_BUILD_STUBS = REPO / "stub" / "build_stubs.sh"


def _fake_ndk(root: Path, *, clang_body: str, with_lld: bool, revision="29.0.14206865") -> Path:
    """A directory shaped like an NDK, with shims where build_stubs.sh looks for tools.

    The host tag is `<uname>-x86_64` on every host Google ships an NDK for (macOS NDKs carry
    darwin-x86_64 and run under Rosetta), which is what build_stubs.sh derives, so deriving it
    the same way here keeps the fixture valid on both.
    """
    import platform
    bindir = root / "toolchains" / "llvm" / "prebuilt" / f"{platform.system().lower()}-x86_64" / "bin"
    bindir.mkdir(parents=True)
    (root / "source.properties").write_text(f"Pkg.Revision = {revision}\n")
    for name, body in (("clang", clang_body),
                       ("llvm-objcopy", "exit 0\n"),
                       ("llvm-readelf", "exit 0\n"),
                       ("llvm-objdump", "exit 0\n")):
        p = bindir / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)
    if with_lld:
        lld = bindir / "ld.lld"
        lld.write_text('#!/bin/sh\necho "LLD 20.0.0"\n')
        lld.chmod(0o755)
    return root


# A clang predating -fpass-plugin (clang < 13, i.e. NDK < r26): the exact two lines a stale
# ANDROID_NDK_HOME produced, which reached the user as three retried seeds naming no NDK.
_OLD_CLANG = '''
for a in "$@"; do
  case "$a" in -fpass-plugin=*)
    echo "clang: error: unknown argument: '$a'" >&2
    echo "clang: error: invalid linker name in argument '-fuse-ld=lld'" >&2
    exit 1 ;;
  esac
done
[ "$1" = "--version" ] && echo "Apple clang version 17.0.0"
exit 0
'''

# A clang that knows the flag: it complains about the missing library instead, which is what
# makes "unknown argument" the discriminator rather than the exit status.
_NEW_CLANG = '''
for a in "$@"; do
  case "$a" in -fpass-plugin=*)
    echo "clang: error: unable to load plugin '${a#*=}'" >&2; exit 1 ;;
  esac
done
[ "$1" = "--version" ] && echo "Android (r29) clang version 20.0.0"
exit 0
'''


def _run_build_stubs(tmp_path, ndk: Path, *, plugin: Path | None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK",
                        "OMVLL_PLUGIN", "OMVLL_PYTHONPATH", "OMVLL_CONFIG")}
    env["ANDROID_NDK_HOME"] = str(ndk)
    # Never the tracked sopack/stubs/: build_stubs.sh's default OUT is package data.
    env["SOPK_STUB_OUT"] = str(tmp_path / "out")
    if plugin is not None:
        env["OMVLL_PLUGIN"] = str(plugin)
        env["OMVLL_CONFIG"] = str(REPO / "stub" / "omvll_config.py")
    return subprocess.run(["bash", str(_BUILD_STUBS)], env=env, cwd=str(tmp_path),
                          capture_output=True, text=True)


def test_build_stubs_refuses_a_clang_that_cannot_load_the_plugin(tmp_path):
    """The user-visible failure this replaces: `unknown argument: '-fpass-plugin=…'`, repeated
    per ABI and per retried seed, naming neither the compiler nor the NDK that chose it."""
    plugin = tmp_path / "omvll_ndk_r29.dylib"
    plugin.touch()
    ndk = _fake_ndk(tmp_path / "ndk", clang_body=_OLD_CLANG, with_lld=True)
    r = _run_build_stubs(tmp_path, ndk, plugin=plugin)
    assert r.returncode != 0, "an unusable toolchain must not reach the compile loop"
    assert "does not support -fpass-plugin" in r.stderr, r.stderr
    assert "== building stub" not in r.stdout, "it compiled anyway - the probe failed open"


def test_build_stubs_probe_does_not_reject_a_capable_clang(tmp_path):
    """The other half: the guards must not false-positive, or they cost the mode entirely."""
    plugin = tmp_path / "omvll_ndk_r29.dylib"
    plugin.touch()
    ndk = _fake_ndk(tmp_path / "ndk", clang_body=_NEW_CLANG, with_lld=True)
    r = _run_build_stubs(tmp_path, ndk, plugin=plugin)
    assert "does not support -fpass-plugin" not in r.stderr, r.stderr
    assert "no ld.lld beside" not in r.stderr, r.stderr
    assert "== building stub for arm64-v8a" in r.stdout, r.stdout + r.stderr


def test_build_stubs_names_the_variable_that_supplied_a_bad_ndk(tmp_path):
    """A path with no clang under it used to surface as bash's bare 'No such file or directory',
    which says nothing about the environment variable that chose it."""
    empty = tmp_path / "not-an-ndk"
    empty.mkdir()
    r = _run_build_stubs(tmp_path, empty, plugin=None)
    assert r.returncode != 0
    assert "$ANDROID_NDK_HOME" in r.stderr and str(empty) in r.stderr, r.stderr


def test_build_stubs_requires_lld(tmp_path):
    """LDFLAGS ask for -fuse-ld=lld unconditionally; a driver with no ld.lld beside it fails
    with 'invalid linker name', the second half of the stale-NDK signature."""
    ndk = _fake_ndk(tmp_path / "ndk", clang_body=_NEW_CLANG, with_lld=False)
    r = _run_build_stubs(tmp_path, ndk, plugin=None)
    assert r.returncode != 0
    assert "no ld.lld beside" in r.stderr, r.stderr


def test_build_stubs_warns_when_the_plugin_pin_and_the_ndk_disagree(tmp_path):
    """A capable clang from the WRONG NDK gets as far as 'unable to load plugin', which names
    the plugin but not the version to install. A warning, not a gate: only the major is
    encoded either side, so it cannot prove incompatibility."""
    plugin = tmp_path / "omvll_ndk_r29.dylib"
    plugin.touch()
    ndk = _fake_ndk(tmp_path / "ndk", clang_body=_NEW_CLANG, with_lld=True,
                    revision="27.0.12077973")
    r = _run_build_stubs(tmp_path, ndk, plugin=plugin)
    assert "built for NDK r29" in r.stderr, r.stderr
    assert "== building stub for arm64-v8a" in r.stdout, "a warning must not stop the build"


# ---- what a failed build reports (pure Python) -------------------------------------------

def test_failure_report_includes_stdout_and_names_an_empty_one():
    """The old report printed `e.stderr` alone. A build_stubs.sh guard that writes to stdout was
    invisible, and a build that died under `set -e` printing nothing produced 'last error:'
    followed by nothing - which is what a stale-NDK run actually looked like."""
    from sopack.obfuscate import _describe_failure
    e = subprocess.CalledProcessError(1, ["bash"], output="on stdout", stderr="")
    msg = _describe_failure(e, seed=7, api_level=24)
    assert "seed=7" in msg and "exit 1" in msg
    assert "on stdout" in msg, "a guard that printed to stdout must not be swallowed"
    assert "stderr: (empty)" in msg

    silent = subprocess.CalledProcessError(1, ["bash"], output="", stderr="")
    msg = _describe_failure(silent, seed=7, api_level=24)
    assert "printed NOTHING" in msg and "bash" in msg, "a silent exit must say how to reproduce"


def test_a_toolchain_rejection_does_not_burn_three_seeds():
    """Retries exist for a transient O-MVLL failure on one seed shape. A rejected toolchain
    fails identically every time; retrying buries the message under two more warnings, which is
    how the r29/-fpass-plugin mismatch reached the user as 'failed after 3 seeds'."""
    from sopack.obfuscate import _is_not_seed_dependent
    guard = subprocess.CalledProcessError(
        1, ["bash"], output="", stderr="ERROR: /ndk/bin/clang does not support -fpass-plugin")
    assert _is_not_seed_dependent(guard), "build_stubs.sh's own ERROR: guards are not seed flakes"
    assert _is_not_seed_dependent(subprocess.CalledProcessError(1, ["bash"], output="", stderr=""))
    # A real compiler diagnostic may well be seed-shaped - keep retrying those.
    omvll = subprocess.CalledProcessError(
        1, ["bash"], output="", stderr="fatal error: error in backend: ran out of registers")
    assert not _is_not_seed_dependent(omvll)


def test_a_misconfigured_toolchain_is_still_exit_7():
    """ObfuscationMisconfiguredError exists to be caught SEPARATELY by the gate above, but it is
    the same class of problem for a user: exit 7 (toolchain), not 4 (missing input file)."""
    from sopack.errors import ToolMissingError
    from sopack.obfuscate import ObfuscationMisconfiguredError, ObfuscationUnavailableError
    from sopack import exitcodes
    from sopack.cli import code_for
    assert issubclass(ObfuscationMisconfiguredError, ObfuscationUnavailableError)
    assert issubclass(ObfuscationMisconfiguredError, ToolMissingError)
    assert code_for(ObfuscationMisconfiguredError("x")) == exitcodes.TOOLCHAIN


def test_no_script_expands_a_possibly_empty_array_unguarded():
    """`"${arr[@]}"` on an EMPTY array is an "unbound variable" error under `set -u` in bash
    < 4.4, and macOS ships /bin/bash 3.2 - the host this tool is primarily used on.

    This is the failure the lint exists for: build_stubs.sh built arm64-v8a, printed its size,
    then died with `THIS_OMVLL[@]: unbound variable` on armeabi-v7a, where the O-MVLL array is
    empty by design. Three more sites had the same latent bug (both wbaes link functions under
    --no-omvll, and device_test.sh's APK list).

    A runtime test cannot catch this: every Linux CI host and every container in this repo runs
    bash 5, where the expansion is legal. So the check is static - it looks for arrays declared
    `NAME=()` and expanded bare somewhere in the same file, and demands the portable
    `${NAME[@]+"${NAME[@]}"}` form instead.
    """
    import re
    offenders = []
    # docker/*.sh is included even though that image runs bash 5: the hazard is theoretical
    # there, but a lint with an unexplained hole invites the next script to be written outside it.
    scripts = [p for d in ("scripts", "stub", "docker") for p in sorted((REPO / d).glob("*.sh"))]
    for script in scripts:
        text = script.read_text()
        declared = set(re.findall(r'^[ \t]*([A-Za-z_][A-Za-z0-9_]*)=\(\)[ \t]*$', text, re.M))
        for name in declared:
            for i, line in enumerate(text.splitlines(), 1):
                if f'"${{{name}[@]}}"' in line and f'{name}[@]+' not in line:
                    offenders.append(f"{script.relative_to(REPO)}:{i}: \"${{{name}[@]}}\"")
    assert not offenders, (
        "these expand a possibly-empty array unguarded, which is an 'unbound variable' error "
        "on macOS's bash 3.2 under set -u. Use ${NAME[@]+\"${NAME[@]}\"}:\n  "
        + "\n  ".join(offenders))
