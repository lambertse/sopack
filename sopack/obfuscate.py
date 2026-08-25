"""Per-pack polymorphic stub build (`obfuscate: true`).

WHAT THIS BUYS, precisely
-------------------------
Without it the stub is byte-identical in every packed app. Its whitening key is a checksum over
its own code bytes, so a constant stub means a **constant, precomputable key**: an analyst needs
no reverse engineering at all to write a universal offline unpacker, just a 25-line script. See
docs/technical/STATIC-ANALYSIS-REVIEW.md S2.

With it, sopack recompiles the stub through O-MVLL with a fresh seed for every pack. Measured on
two seeds of the same source: **88.6% of the stub's bytes differ**, and - the part that matters -
the 1024-byte whitening span differs too, so the de-whitening key is different in every app.
There is no cross-app shortcut left. This is the only mechanism in the repo that makes "reverse
once, unpack everything" false.

THE COST, stated honestly (ARCHITECTURE.md S9e)
-----------------------------------------------
It needs the clang/lld toolchain AND the O-MVLL plugin **at pack time**, not just the prebuilt
blob. That breaks the prebuilt-blob model, slows packs, and re-runs the no-reloc / no-undef /
no-adrp guards per pack. It is opt-in for those reasons.

It applies to the stub ciphers only. `cipher: wbaes` does not use the stub at all - it already
has per-app diversity from a fresh KEK per pack - so the combination is rejected in config.py
rather than silently doing nothing.

TOOLCHAIN
---------
The plugin comes from sopack's own vendored copy (scripts/fetch_omvll.sh -> third_party/omvll/),
the same one the wbaes path uses; OMVLL_PLUGIN / OMVLL_PYTHONPATH override it. The NDK comes
from ANDROID_NDK_HOME / ANDROID_NDK_ROOT. If anything is missing this fails fast with an
actionable message rather than quietly packing an un-obfuscated stub - "it built" must never mean
"it built unobfuscated".
"""
from __future__ import annotations

import glob
import os
import secrets
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

from . import diag
from .errors import ToolMissingError

_REPO_ROOT = Path(__file__).resolve().parent.parent
_BUILD_SCRIPT = _REPO_ROOT / "stub" / "build_stubs.sh"
_FETCH_OMVLL = _REPO_ROOT / "scripts" / "fetch_omvll.sh"

# O-MVLL's probability_seed is a signed int32, so seeds must fit in 31 bits - a larger value
# raises "TypeError: incompatible function arguments" from the binding.
_SEED_BITS = 2 ** 31
# A thin safety net for a transient O-MVLL failure on a particular seed. With the 31-bit range
# it should not fire; if it does, a different shape usually compiles.
_AUTO_SEED_RETRIES = 3


class ObfuscationUnavailableError(ToolMissingError):
    """The O-MVLL / NDK toolchain needed for `obfuscate: true` is not present.

    A ToolMissingError subclass so it maps to exit 7 (toolchain) rather than being reported as
    a missing input file - the distinction the exit-code table exists to make.
    """


class ObfuscationMisconfiguredError(ObfuscationUnavailableError):
    """A toolchain variable IS set, and points at something unusable.

    Split from the base because the two deserve OPPOSITE handling by a caller that can degrade:
    "no NDK on this machine" is a fact about the host, while "ANDROID_NDK_HOME names a directory
    with no clang in it" is a mistake someone made and wants told about. tests/test_obfuscate.py
    skips on the former and FAILS on the latter - without the split, pointing the variable at
    nonsense would silently skip the one test that proves two packs get different whitening keys,
    and a green suite would mean nothing.

    Same exit code (7): it is still a toolchain problem, so nothing about `cli.code_for` changes.
    """


def _vendored_plugin() -> tuple[str, str] | None:
    """(plugin, pythonpath) from sopack's own vendored copy, or None if not fetched."""
    if not _FETCH_OMVLL.is_file():
        return None
    try:
        plugin = subprocess.run([str(_FETCH_OMVLL), "--print-plugin"],
                                capture_output=True, text=True).stdout.strip()
        pylib = subprocess.run([str(_FETCH_OMVLL), "--print-pythonpath"],
                               capture_output=True, text=True).stdout.strip()
    except OSError:
        return None
    return (plugin, pylib) if plugin and pylib else None


def resolve_toolchain() -> tuple[str, str]:
    """(OMVLL_PLUGIN, OMVLL_PYTHONPATH), or raise with what to do about it."""
    plugin = os.environ.get("OMVLL_PLUGIN")
    pylib = os.environ.get("OMVLL_PYTHONPATH")
    if not (plugin and pylib):
        found = _vendored_plugin()
        if found:
            plugin, pylib = plugin or found[0], pylib or found[1]

    missing = []
    ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if not ndk:
        missing.append("ANDROID_NDK_HOME (or ANDROID_NDK_ROOT)")
    # Set-but-wrong was previously indistinguishable from set-and-good: the check was for the
    # variable, not the path, so a stale value reached build_stubs.sh and came back as three
    # retried seeds and a raw clang error naming no NDK. Globbed rather than derived from
    # platform.system(), matching tests/test_wbaes.py:_ndk_clang(): on Apple Silicon the only
    # toolchain an NDK ships is darwin-x86_64, run under Rosetta.
    elif not glob.glob(os.path.join(ndk, "toolchains", "llvm", "prebuilt", "*", "bin", "clang")):
        raise ObfuscationMisconfiguredError(
            f"no clang under {ndk}/toolchains/llvm/prebuilt/*/bin - that is not an NDK root "
            "(the SDK root and the ndk/ parent directory are the usual mix-ups).\n"
            "  It came from ANDROID_NDK_HOME/ANDROID_NDK_ROOT. Which NDK matters: the O-MVLL "
            "plugin is pinned to r29 and loads only into the clang it was built against.")
    if not plugin:
        missing.append("an O-MVLL plugin (run ./scripts/fetch_omvll.sh, or set OMVLL_PLUGIN)")
    elif not Path(plugin).is_file():
        raise ObfuscationUnavailableError(f"O-MVLL plugin not found at {plugin}")
    if not pylib:
        missing.append("the O-MVLL CPython stdlib (./scripts/fetch_omvll.sh, or OMVLL_PYTHONPATH)")
    elif not Path(pylib).is_dir():
        raise ObfuscationUnavailableError(f"OMVLL_PYTHONPATH is not a directory: {pylib}")
    if not _BUILD_SCRIPT.is_file():
        raise ObfuscationUnavailableError(f"missing build script {_BUILD_SCRIPT}")
    if missing:
        # Deliberately the BASE class: "nothing is installed here" is a fact about the host, and
        # a caller that can degrade should degrade. Only a variable pointing at nonsense is a
        # mistake worth failing a test over.
        raise ObfuscationUnavailableError(
            "`obfuscate: true` recompiles the stub per pack and needs the O-MVLL/NDK toolchain, "
            "but is missing: " + ", ".join(missing) + ".\n"
            "  Run inside the sopack builder image (docker/), or install the NDK and run "
            "./scripts/fetch_omvll.sh. Unset `obfuscate` to pack with the prebuilt stub - but "
            "note that stub is byte-identical in every app, so its key is a public constant.")
    return plugin, pylib


def _run_build(seed: int, out_dir, api_level: int, plugin: str, pylib: str) -> None:
    env = dict(os.environ)
    env["SOPK_SEED"] = str(seed)
    env["SOPK_STUB_OUT"] = str(out_dir)
    env["OMVLL_PLUGIN"] = plugin
    env["OMVLL_PYTHONPATH"] = pylib
    # sopack's STUB policy, not the wbaes one: stub/omvll_config.py enables only the
    # relocation-free pass set, because build_stubs.sh's guards reject anything that emits a
    # relocation, an undefined symbol, or an arm64 adrp.
    env["OMVLL_CONFIG"] = str(_REPO_ROOT / "stub" / "omvll_config.py")
    diag.emit(f"  building a polymorphic stub (seed={seed}) via O-MVLL …")
    # cwd = out_dir so O-MVLL's "omvll-logs/" - created at plugin init, before its Python config
    # is even read - lands in the temp dir and is cleaned up with it, rather than in the user's
    # working directory. build_stubs.sh uses absolute paths, so cwd is free to use this way.
    subprocess.run(["bash", str(_BUILD_SCRIPT), str(api_level)],
                   env=env, check=True, cwd=str(out_dir),
                   capture_output=True, text=True)


def _describe_failure(e: subprocess.CalledProcessError, seed: int, api_level: int,
                      note: str = "") -> str:
    """Everything known about a failed stub build, in one message.

    This used to print `e.stderr` alone, which was wrong in both directions: a build_stubs.sh
    guard that writes to STDOUT was invisible, and a build that died under `set -e` without
    printing anything produced "last error:" followed by nothing at all - a bug report with no
    content, three seeds deep. Both halves are included, tails only (an O-MVLL failure can emit
    a very long LLVM stack trace, and the actionable line is the last one).
    """
    def tail(s, n=4000):
        s = (s or "").strip()
        return s if len(s) <= n else "…\n" + s[-n:]

    out, err = tail(e.stdout), tail(e.stderr)
    parts = [f"obfuscated stub build failed (seed={seed}, exit {e.returncode})"]
    if note:
        parts.append(f"  {note}")
    parts.append(f"  stderr:\n{err}" if err else "  stderr: (empty)")
    parts.append(f"  stdout:\n{out}" if out else "  stdout: (empty)")
    if not (out or err):
        # A silent non-zero exit is a bug in the script, not a fact about the seed. Say what to
        # run, because nothing above will have named the toolchain it chose.
        parts.append("  It printed NOTHING on either stream, so this is not a compiler "
                     "diagnostic. Reproduce it directly:\n"
                     f'    ANDROID_NDK_HOME="$ANDROID_NDK_HOME" bash {_BUILD_SCRIPT} {api_level}')
    return "\n".join(parts)


def _is_not_seed_dependent(e: subprocess.CalledProcessError) -> str:
    """Why retrying a fresh seed cannot help, or "" if it might.

    The retry loop exists for a transient O-MVLL failure on one seed shape. A broken toolchain
    fails identically every time, so retrying only triples the wall time and buries the cause
    under two more warnings - which is exactly how the r29/-fpass-plugin mismatch reached the
    user as "failed after 3 seeds".
    """
    both = ((e.stdout or "") + (e.stderr or ""))
    if not both.strip():
        return "the build printed nothing, so the seed is not what failed"
    if "ERROR: " in both:
        # build_stubs.sh's own guards (toolchain, plugin, lld, relocations) all use this prefix;
        # O-MVLL and clang diagnostics use "error:" lowercase, without the prefix.
        return "build_stubs.sh rejected the build outright, which no seed changes"
    return ""


def build_obfuscated_stubs(out_dir, api_level: int = 24, seed: int | None = None) -> int:
    """Build a fresh, seeded, O-MVLL-obfuscated stub set into `out_dir`; return the seed used.

    The seed is returned so it can be recorded in report.json: it is the only handle that makes
    a given pack's stub reproducible after the fact.
    """
    plugin, pylib = resolve_toolchain()
    if seed is not None:
        try:
            _run_build(seed, out_dir, api_level, plugin, pylib)
        except subprocess.CalledProcessError as e:
            raise RuntimeError(_describe_failure(e, seed, api_level)) from e
        return seed

    last, last_seed = None, None
    for _ in range(_AUTO_SEED_RETRIES):
        seed = secrets.randbelow(_SEED_BITS)
        try:
            _run_build(seed, out_dir, api_level, plugin, pylib)
            return seed
        except subprocess.CalledProcessError as e:
            last, last_seed = e, seed
            # Fail fast when the seed provably is not the problem: two more identical failures
            # add nothing but noise, and push the one useful message three warnings up.
            why = _is_not_seed_dependent(e)
            if why:
                raise RuntimeError(_describe_failure(e, seed, api_level, why)) from e
            diag.warn(f"  O-MVLL build failed for seed {seed}; retrying with a fresh seed")
    raise RuntimeError(_describe_failure(
        last, last_seed, api_level,
        f"all {_AUTO_SEED_RETRIES} seeds failed, so this is unlikely to be seed-dependent"))


@contextmanager
def obfuscated_stub_dir(api_level: int = 24, seed: int | None = None):
    """Yield (Path(tempdir), seed) holding a freshly obfuscated stub set."""
    with tempfile.TemporaryDirectory(prefix="sopack-obf-") as tmp:
        used = build_obfuscated_stubs(tmp, api_level=api_level, seed=seed)
        yield Path(tmp), used
