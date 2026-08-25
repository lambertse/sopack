"""Already-packed detection: the two tiers, and what each is allowed to do about a hit.

The behaviour under test is a refusal, so these tests care as much about the FALSE positives as
the true ones. A detector that over-reaches refuses to pack a legitimate app, and the only way
out is a config key the operator has to discover first - which is worse than the double-encrypt
it was preventing. Hence the split the module enforces and this file pins:

* definitive evidence (our own entries, our build markers, our DT_NEEDED, our de-whitened
  decinfo magic) -> `AlreadyPackedError`, exit 11;
* a mere resemblance -> a warning, and the pack proceeds.
"""
from __future__ import annotations

import os
import zipfile

import pytest

from conftest import mkaab, mkapk

from sopack import container, detect, stubs
from sopack.rt_meta import (HELPER_BUILD_MARKER, PROVIDER_BUILD_MARKER, PROVIDER_SONAME,
                            SUPERSEDED_BUILD_MARKERS)

ROOT = os.path.dirname(os.path.dirname(__file__))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "mini_arm64.so")


def _fake_inject(src, dst, abi, **kw):
    """A successful injection that copies the input through. Used where the subject under test
    is the DETECTION decision rather than what injection then does with the bytes."""
    import shutil
    from sopack.elf_inject import InjectResult
    shutil.copyfile(src, dst)
    return InjectResult(abi=abi, text_rva=0x1000, text_size=16, seg_rva=0x2000,
                        entry_rva=0x2040, strategy="DT_INIT-inplace", cipher="chacha20")


# ---- tier 1: the central directory -------------------------------------------------------
def test_a_clean_apk_yields_no_entry_evidence(tmp_path):
    """The assertion that matters most in this file. Everything else here is about catching a
    packed input; this is about not molesting an innocent one."""
    mkapk(tmp_path / "a.apk", ("lib/arm64-v8a/libfoo.so", "lib/x86_64/libbar.so",
                               "assets/lib/arm64-v8a/libnested.so", "classes.dex"))
    with zipfile.ZipFile(tmp_path / "a.apk") as z:
        assert detect.scan_entries(z.namelist(), container.APK) == []


@pytest.mark.parametrize("entry", [
    f"lib/arm64-v8a/{PROVIDER_SONAME}",
    "lib/arm64-v8a/libsopk_rt_libfoo.so",
])
def test_our_own_entries_are_definitive(tmp_path, entry):
    mkapk(tmp_path / "a.apk", ("lib/arm64-v8a/libfoo.so", entry))
    with zipfile.ZipFile(tmp_path / "a.apk") as z:
        assert detect.scan_entries(z.namelist(), container.APK) == [entry]


def test_a_bundle_is_matched_through_its_own_entry_pattern(tmp_path):
    """The module dir is part of the shape, so the APK regex would miss it entirely - and a
    packed AAB is exactly as unfit to re-pack as a packed APK."""
    names = (f"base/lib/arm64-v8a/{PROVIDER_SONAME}", "base/lib/arm64-v8a/libfoo.so")
    mkaab(tmp_path / "a.aab", names)
    with zipfile.ZipFile(tmp_path / "a.aab") as z:
        hits = detect.scan_entries(z.namelist(), container.AAB)
    assert hits == [f"base/lib/arm64-v8a/{PROVIDER_SONAME}"]


def test_the_matcher_is_structural_not_fnmatch(tmp_path):
    """`apk._match_lib_pattern` interprets user globs generously - a bare basename matches every
    ABI, a trailing `.so` is optional. Generosity is the wrong instinct here: this decides
    whether to REFUSE a pack, so a name that merely resembles ours must not count."""
    mkapk(tmp_path / "a.apk", ("assets/libsopk_wb.so", "lib/arm64-v8a/notlibsopk_rt_x.so"))
    with zipfile.ZipFile(tmp_path / "a.apk") as z:
        assert detect.scan_entries(z.namelist(), container.APK) == []


# ---- tier 2: the library bytes -----------------------------------------------------------
def test_a_clean_library_yields_no_evidence():
    data = open(FIXTURE, "rb").read()
    assert detect.scan_library(data) is None
    assert detect.scan_library_heuristic(data) is None


@pytest.mark.parametrize("marker", [HELPER_BUILD_MARKER, PROVIDER_BUILD_MARKER,
                                    *SUPERSEDED_BUILD_MARKERS])
def test_build_markers_are_definitive(marker):
    """Including the SUPERSEDED ones. An APK packed by an older sopack is a large share of what
    gets fed back in, and recognising only the current marker would miss exactly those."""
    data = open(FIXTURE, "rb").read() + marker
    assert marker.hex() in detect.scan_library(data)


def test_a_renamed_helper_is_still_caught():
    """The one thing that defeats tier 1: rename `libsopk_rt_libfoo.so` to anything else and the
    central-directory scan sees nothing. The marker travels inside the file."""
    data = open(FIXTURE, "rb").read() + HELPER_BUILD_MARKER
    assert detect.scan_library(data) is not None


def test_garbage_never_raises():
    """`scan_library` is handed every ZIP member that merely ends in `.so`. A detector that dies
    on a truncated or non-ELF file would turn a cosmetic oddity into a failed pack."""
    for data in (b"", b"\x7fELF", b"\x7fELF" + b"\x00" * 40, b"not an elf at all", b"\xff" * 200):
        assert detect.scan_library(data) is None
        assert detect.scan_library_heuristic(data) is None


# ---- the de-whitening oracle: the only signal a chacha20/xor pack leaves -----------------
def _stub_available(abi="arm64-v8a") -> bool:
    try:
        stubs.load_stub(abi)
        return True
    except (stubs.StubMissingError, ValueError, OSError):
        return False


@pytest.mark.skipif(not _stub_available(), reason="stub blob for arm64-v8a not built")
@pytest.mark.parametrize("cipher", ["chacha20", "xor"])
def test_a_stub_packed_library_is_definitively_detected(tmp_path, cipher):
    """Real injection, then detection off the resulting bytes.

    A stub-mode pack adds NOTHING to the ZIP, so tier 1 cannot see it and this is the whole of
    the coverage for two of the three ciphers. It works because the whitening key is a checksum
    over stub bytes that are identical in every app for a stock (non-polymorphic) stub - so the
    key is a precomputable constant and the record can simply be un-masked.

    Both ciphers are exercised: they ship the identical blob, segment and strings, and the
    de-whitened `cipher_id` is the only thing that tells them apart from outside.
    """
    from sopack.elf_inject import inject_so
    out = str(tmp_path / "packed.so")
    inject_so(FIXTURE, out, "arm64-v8a", cipher=cipher)
    why = detect.scan_library(open(out, "rb").read())
    assert why is not None, "a stub-packed library was not detected"
    assert cipher in why


@pytest.mark.skipif(not _stub_available(), reason="stub blob for arm64-v8a not built")
def test_a_stub_packed_library_is_refused_end_to_end(tmp_path):
    """Through `repackage`, i.e. the tier that runs inside the entry loop rather than the
    central-directory one - the path a chacha20 re-pack actually takes."""
    from sopack import apk as apkmod
    from sopack.elf_inject import inject_so
    from sopack.errors import AlreadyPackedError

    packed = str(tmp_path / "packed.so")
    inject_so(FIXTURE, packed, "arm64-v8a", cipher="chacha20")
    src = tmp_path / "in.apk"
    mkapk(src, ())
    with zipfile.ZipFile(src, "a") as z:
        z.writestr("lib/arm64-v8a/libmini.so", open(packed, "rb").read())

    with pytest.raises(AlreadyPackedError):
        apkmod.repackage(str(src), str(tmp_path / "o.apk"), None,
                         cipher="chacha20", no_sign=True, logger=lambda *a: None)


@pytest.mark.skipif(not _stub_available(), reason="stub blob for arm64-v8a not built")
def test_allow_repack_lets_the_same_input_through(tmp_path, monkeypatch):
    """The escape hatch, on the same input the test above refuses.

    Injection is stubbed out on purpose. What is under test is that DETECTION steps aside -
    whether a genuine double-inject then survives `_self_verify` is a separate question, and
    letting it decide this test would make a detection regression look like an injection bug.
    """
    from sopack import apk as apkmod
    from sopack.elf_inject import inject_so

    packed = str(tmp_path / "packed.so")
    inject_so(FIXTURE, packed, "arm64-v8a", cipher="chacha20")
    src = tmp_path / "in.apk"
    mkapk(src, ())
    with zipfile.ZipFile(src, "a") as z:
        z.writestr("lib/arm64-v8a/libmini.so", open(packed, "rb").read())

    monkeypatch.setattr(apkmod, "inject_so", _fake_inject)
    res = apkmod.repackage(str(src), str(tmp_path / "o.apk"), None,
                           cipher="chacha20", no_sign=True, allow_repack=True,
                           logger=lambda *a: None)
    assert len(res.injected) == 1


# ---- the heuristic tier warns and nothing more -------------------------------------------
@pytest.mark.skipif(not _stub_available(), reason="stub blob for arm64-v8a not built")
def test_the_heuristic_fires_on_the_stub_segment_shape(tmp_path):
    """`DT_INIT` into an R+X segment no section covers. This is what is left once the stub is
    polymorphic (`obfuscate: true`), because then every byte of it differs per pack and the
    oracle above cannot know the key."""
    from sopack.elf_inject import inject_so
    out = str(tmp_path / "packed.so")
    inject_so(FIXTURE, out, "arm64-v8a", cipher="chacha20")
    assert detect.scan_library_heuristic(open(out, "rb").read()) is not None


def test_the_heuristic_is_not_wired_to_the_refusal(tmp_path, monkeypatch):
    """It must WARN, not abort. Other packers emit the same segment shape, and refusing a
    legitimate pack on a resemblance is the worse failure - so a library that trips only the
    heuristic still packs.
    """
    from sopack import apk as apkmod

    monkeypatch.setattr(detect, "scan_library", lambda data: None)
    monkeypatch.setattr(detect, "scan_library_heuristic", lambda data: "looks packed")

    monkeypatch.setattr(apkmod, "inject_so", _fake_inject)
    src = mkapk(tmp_path / "in.apk", ("lib/arm64-v8a/libfoo.so",))
    res = apkmod.repackage(src, str(tmp_path / "o.apk"), None,
                           cipher="chacha20", no_sign=True, logger=lambda *a: None)
    assert len(res.injected) == 1
