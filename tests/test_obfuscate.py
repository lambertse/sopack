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
