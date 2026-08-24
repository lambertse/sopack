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
    if not (os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")):
        missing.append("ANDROID_NDK_HOME (or ANDROID_NDK_ROOT)")
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
            raise RuntimeError(
                f"obfuscated stub build failed (seed={seed}):\n{e.stderr}") from e
        return seed

    last = None
    for _ in range(_AUTO_SEED_RETRIES):
        seed = secrets.randbelow(_SEED_BITS)
        try:
            _run_build(seed, out_dir, api_level, plugin, pylib)
            return seed
        except subprocess.CalledProcessError as e:
            last = e
            diag.warn(f"  O-MVLL build failed for seed {seed}; retrying with a fresh seed")
    raise RuntimeError(
        f"obfuscated stub build failed after {_AUTO_SEED_RETRIES} seeds; last error:\n"
        f"{last.stderr if last else '?'}")


@contextmanager
def obfuscated_stub_dir(api_level: int = 24, seed: int | None = None):
    """Yield (Path(tempdir), seed) holding a freshly obfuscated stub set."""
    with tempfile.TemporaryDirectory(prefix="sopack-obf-") as tmp:
        used = build_obfuscated_stubs(tmp, api_level=api_level, seed=seed)
        yield Path(tmp), used
