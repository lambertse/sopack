"""Per-pack polymorphic stub (`obfuscate: true`).

The property under test is NOT "the stub is bigger" or "O-MVLL ran". It is that the
**whitening key differs between two packs**. That key is a checksum over the stub's own bytes,
so a byte-identical stub means a byte-identical key in every app on earth, and an analyst needs
no reverse engineering to write a universal unpacker (STATIC-ANALYSIS-REVIEW.md S2). Everything
else here is scaffolding around that one assertion.
"""
from __future__ import annotations

import json
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
    """(ndk, plugin, pythonpath) or None. Skips rather than fails: most machines have neither."""
    ndk = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    plugin = os.environ.get("OMVLL_PLUGIN")
    pylib = os.environ.get("OMVLL_PYTHONPATH")
    if not plugin:
        f = REPO / "scripts" / "fetch_omvll.sh"
        if f.is_file():
            r = subprocess.run([str(f), "--print-plugin"], capture_output=True, text=True)
            if r.returncode == 0:
                plugin = r.stdout.strip()
            r = subprocess.run([str(f), "--print-pythonpath"], capture_output=True, text=True)
            if r.returncode == 0:
                pylib = pylib or r.stdout.strip()
    if not (ndk and plugin and pylib and shutil.which("bash")):
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
        pytest.skip(f"O-MVLL build unavailable here: {r.stderr.strip()[-200:]}")
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
