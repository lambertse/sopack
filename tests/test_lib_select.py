"""Library selection: auto-select, exclusion patterns, the `abis:` default, fail-soft skips.

These cover the selection layer only - they never build a real ELF. The end-to-end tests
that do live in test_integration.py / test_wbaes.py.
"""
from __future__ import annotations

import os
import shutil
import zipfile

import pytest

from conftest import mkapk as _mkapk
from conftest import mkapk

from sopack import apk, cli, config, container
from sopack.apk import (ALWAYS_EXCLUDE_PATTERNS, _classify, _match_lib_pattern,
                        build_excludes)
from sopack.elf_inject import InjectError, InjectResult
from sopack.stubs import DEFAULT_ABIS, SUPPORTED_ABIS

ARM64 = {"arm64-v8a"}


def _auto(so, excludes=(), abis=ARM64, abi="arm64-v8a"):
    return _classify(f"lib/{abi}/{so}", abi, so, None, abis, excludes)


def _explicit(so, wanted, excludes=(), abis=ARM64, abi="arm64-v8a"):
    return _classify(f"lib/{abi}/{so}", abi, so, set(wanted), abis, excludes)


# ---- 1. pattern matching ----------------------------------------------------------
@pytest.mark.parametrize("pat,so,hit", [
    ("libsopk_*", "libsopk_wb.so", True),
    ("libsopk_*", "libsopk_rt_libapp.so", True),
    ("libsopk_*", "libsopkx.so", False),
    ("libflutter", "libflutter.so", True),      # .so suffix is optional in the pattern
    ("libflutter", "libflutterx.so", False),    # ... but it is not a prefix match
    ("libflutter.so", "libflutter.so", True),
    ("libmy*", "libmyfoo.so", True),
    ("libmy*", "libotherfoo.so", False),
])
def test_match_lib_pattern(pat, so, hit):
    assert _match_lib_pattern(f"lib/arm64-v8a/{so}", so, pat) is hit


def test_match_lib_pattern_full_path():
    entry, so = "lib/arm64-v8a/libfoo.so", "libfoo.so"
    assert _match_lib_pattern(entry, so, "lib/arm64-v8a/*")
    assert not _match_lib_pattern(entry, so, "lib/x86_64/*")


# ---- 2. auto-select ---------------------------------------------------------------
def test_auto_select_takes_everything_in_selected_abis():
    for so in ("libapp.so", "libc++_shared.so", "libweird-name.so"):
        assert _auto(so) == (True, "")


def test_auto_select_respects_abi_filter():
    # armeabi-v7a is merely outside the default --abi ...
    assert _auto("libapp.so", abis=set(DEFAULT_ABIS),
                 abi="armeabi-v7a") == (False, "abi not selected")
    assert _auto("libapp.so", abis=set(SUPPORTED_ABIS), abi="armeabi-v7a") == (True, "")
    # ... but lib/x86/ can never be packed, so the reason must not imply --abi would help.
    for abis in (set(DEFAULT_ABIS), set(SUPPORTED_ABIS)):
        assert _auto("libapp.so", abis=abis, abi="x86") == (
            False, "abi not supported by sopack")


def test_explicit_selection_still_matches_basename_or_full_path():
    assert _explicit("libapp.so", ["libapp.so"]) == (True, "")
    assert _explicit("libapp.so", ["lib/arm64-v8a/libapp.so"]) == (True, "")
    assert _explicit("libapp.so", ["libother.so"]) == (False, "not requested")


@pytest.mark.parametrize("spelling", [
    "libapp", "libapp.so", "lib/arm64-v8a/libapp.so", "libap*",
])
def test_include_matches_exactly_like_exclude(spelling):
    """`include` and `exclude` sit two lines apart in the config, so they MUST accept the
    same spellings. `include: [libapp]` used to match nothing (exact set membership) while
    `exclude: [libflutter]` worked - the pack then aborted with "no .so entries matched",
    which names the list but not the reason."""
    assert _explicit("libapp.so", [spelling])[0] is True


@pytest.mark.parametrize("so", ["libapp2.so", "libappx.so", "libotherapp.so"])
def test_a_bare_include_name_is_not_a_prefix_match(so):
    """The optional-.so rule must not turn `libapp` into `libapp*` - that would silently
    pack neighbours the user never named, which for an explicit list is the whole point."""
    assert _explicit(so, ["libapp"])[0] is False


def test_exclusion_still_beats_an_include_glob():
    """Widening `include` must not become a way around the enforced patterns."""
    ex = build_excludes()
    assert _explicit("libsopk_wb.so", ["libsopk*"], ex)[0] is False
    assert _explicit("libsopk_wb.so", ["*"], ex)[0] is False


# ---- 3-5. exclusion ---------------------------------------------------------------
def test_sopack_artifacts_are_never_selected():
    """The provider and thin helpers must never be fed back through inject_so.

    The `[]` case is the one that matters now that the exclusion list is user-editable
    YAML: `libraries.exclude: []` is a VALID config (unlike `include: []`), and it is
    exactly the shape a user reaches for when they want to pack everything. It must still
    be impossible to select sopack's own decryptor - build_excludes prepends
    ALWAYS_EXCLUDE_PATTERNS whatever the caller passes.
    """
    for so in ("libsopk_wb.so", "libsopk_rt_libapp.so"):
        for ex in (build_excludes(), build_excludes([]), build_excludes(["libfoo"])):
            assert _auto(so, ex)[0] is False
            # ... not even when named explicitly.
            assert _explicit(so, [so], ex)[0] is False


def test_exclusion_beats_explicit_lib():
    ex = build_excludes(["libapp"])
    assert _explicit("libapp.so", ["libapp.so"], ex) == (False, "excluded by 'libapp'")


def test_a_pattern_applies_to_both_modes():
    # Passed literally rather than sourced from the config layer: this module tests the
    # selection layer on its own. That the shipped default still CONTAINS libflutter is a
    # config-layer fact, pinned in test_config.py.
    ex = build_excludes(["libflutter"])
    assert _auto("libflutter.so", ex) == (False, "excluded by 'libflutter'")
    assert _explicit("libflutter.so", ["libflutter.so"], ex)[0] is False


def test_build_excludes_always_prepends_the_enforced_patterns():
    """Enforced in code, not merely written in the shipped config - so a hand-written
    config that omits them is still safe."""
    assert build_excludes() == ALWAYS_EXCLUDE_PATTERNS
    assert build_excludes([]) == ALWAYS_EXCLUDE_PATTERNS
    assert build_excludes(["a", "b"]) == ALWAYS_EXCLUDE_PATTERNS + ("a", "b")


def test_build_excludes_deduplicates():
    """Every generated config lists the enforced patterns, so they arrive twice. Without
    the de-dupe the CLI's `excluding:` line names each of them twice, which reads as a bug."""
    ex = build_excludes(list(ALWAYS_EXCLUDE_PATTERNS) + ["libflutter"])
    assert ex == ALWAYS_EXCLUDE_PATTERNS + ("libflutter",)
    assert len(ex) == len(set(ex))


# ---- 6. CLI plumbing --------------------------------------------------------------
# Everything except the input and output APK moved into the YAML config; the parsing and
# validation assertions that used to live here are in test_config.py now. What is left is
# the CLI surface itself: what argv still accepts, and what it must refuse.
def test_pack_surface_is_input_output_and_config_only():
    """The whole point of the config file. A new flag added here is a regression."""
    args = cli.build_parser().parse_args(
        ["pack", "in.apk", "-o", "out.apk", "--config", "c.yaml"])
    assert (args.input, args.output, args.config) == ("in.apk", "out.apk", "c.yaml")
    assert vars(args).keys() == {"cmd", "input", "output", "config", "func"}


@pytest.mark.parametrize("flag,key", sorted(cli._REMOVED_FLAGS.items()))
def test_removed_flags_fail_loudly_and_name_their_config_key(flag, key, capsys):
    """A stale flag in a script must FAIL, not be silently accepted and ignored.

    The whole surface moved at once, so argparse's bare "unrecognized arguments: --cipher"
    would leave the reader to guess the key. Each message names its replacement.
    """
    with pytest.raises(SystemExit) as e:
        cli.main(["pack", "in.apk", "-o", "out.apk", flag, "x"])
    assert key in str(e.value)
    # Also caught when glued on with `=`, which argparse accepts for long options.
    with pytest.raises(SystemExit):
        cli.main(["pack", "in.apk", "-o", "out.apk", f"{flag}=x"])


def test_wb_keygen_is_neither_a_flag_nor_a_config_key():
    """Removed, not deprecated: provision.find_wb_keygen probes vendor/wbc/bin/ and the
    portable bundle itself, so there is nothing left to point at. It did not come back as a
    config key either - a key would re-open "where does it rank?" against that probe order,
    in which $SOPACK_WBKEYGEN deliberately ranks BELOW a freshly gated local build."""
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(
            ["pack", "in.apk", "-o", "out.apk", "--wb-keygen", "/some/wb_keygen"])
    with pytest.raises(config.ConfigError, match="unknown key"):
        config.loads("wb-keygen: /some/wb_keygen\n")


def test_init_config_writes_a_file_that_parses_to_the_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["init-config"]) == 0
    written = tmp_path / "config.yaml"
    assert written.read_text() == config.SAMPLE_YAML
    assert config.loads(written.read_text()) == config.Config.default()


def test_init_config_refuses_to_clobber(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("cipher: xor\n")
    with pytest.raises(SystemExit, match="already exists"):
        cli.main(["init-config"])
    assert (tmp_path / "config.yaml").read_text() == "cipher: xor\n"


# ---- 7. zero libraries: a pass-through under auto-select, an error when named ------


def test_no_libs_at_all_passes_the_input_through(tmp_path):
    """Not an error, and the output is the input byte-for-byte.

    sopack could never have protected anything here - there is no native code - so there is
    nothing to diagnose, and a pipeline that packs every build must not die on a
    pure-Java/Kotlin APK. Contrast `test_everything_excluded_or_out_of_abi` below, which stays
    a failure precisely because libraries WERE present and shipped in cleartext.

    The copy is verbatim rather than a rezip, so the input's own signature survives - which is
    why `signed` is False here without meaning "you must sign this before installing".
    """
    src = _mkapk(tmp_path / "in.apk", [])
    out = str(tmp_path / "out.apk")
    res = apk.repackage(src, out, None, logger=lambda *_: None)
    assert res.passthrough is True
    assert res.injected == []
    assert res.signed is False
    assert open(out, "rb").read() == open(src, "rb").read()


def test_a_named_library_that_is_absent_is_still_an_error(tmp_path):
    """The asymmetry that scopes the pass-through above to auto-select. The user who wrote
    `libraries.include` vouched for those names; packing nothing and reporting success would
    hide a typo'd or stale library list."""
    src = _mkapk(tmp_path / "in.apk", [])
    out = str(tmp_path / "out.apk")
    with pytest.raises(RuntimeError, match="no .so entries matched the requested list"):
        apk.repackage(src, out, ["libfoo.so"], logger=lambda *_: None)
    assert not os.path.exists(out), "nothing should have been written"


def test_everything_excluded_or_out_of_abi(tmp_path):
    """Libraries WERE present and none got packed - still an error, unlike the empty container
    above. Something shipped in cleartext that the operator may have expected to be encrypted.

    `libvosWrapperEx`, not `libsopk_wb`, stands in for the unconditionally-excluded half: an APK
    containing sopack's own artifacts is now refused earlier and for a different reason (see the
    test below), so using one here would never reach this message.
    """
    src = _mkapk(tmp_path / "in.apk", [
        "lib/arm64-v8a/libflutter.so",         # excluded by the caller's list
        "lib/arm64-v8a/libvosWrapperEx.so",    # excluded unconditionally, list or no list
        "lib/x86_64/libapp.so",                # outside the default abis
    ])
    with pytest.raises(RuntimeError, match="none of the 3 lib/<abi>/"):
        apk.repackage(src, str(tmp_path / "out.apk"), None,
                      exclude_libs=["libflutter"], logger=lambda *_: None)


def test_an_apk_carrying_our_own_artifacts_is_refused_before_selection(tmp_path):
    """The case the test above used to cover with `libsopk_wb.so`, and why it had to move.

    `libsopk_*` being in ALWAYS_EXCLUDE_PATTERNS meant a re-pack surfaced only as "every entry
    was excluded" - exit 6, with the real cause buried in the per-library reasons. It is now its
    own refusal (exit 11) raised from the central-directory pre-scan, before `_classify` runs at
    all. The exclusion stays as defence in depth.
    """
    from sopack.errors import AlreadyPackedError
    src = _mkapk(tmp_path / "in.apk", [
        "lib/arm64-v8a/libapp.so",
        "lib/arm64-v8a/libsopk_wb.so",
    ])
    with pytest.raises(AlreadyPackedError, match="already packed"):
        apk.repackage(src, str(tmp_path / "out.apk"), None, logger=lambda *_: None)


# ---- 8. fail-soft under auto-select, hard fail when named -------------------------
_SIGNING = shutil.which("keytool") and shutil.which("apksigner")
requires_signing = pytest.mark.skipif(
    not _SIGNING, reason="needs keytool + apksigner to produce a signed APK")


def _fake_inject(failing: set[str]):
    """Stand-in for inject_so: writes a marker, or raises for the named targets."""
    def _inject(src, dst, abi, *, target_name=None, cipher="chacha20", **kw):
        if target_name in failing:
            raise InjectError(f"synthetic failure for {target_name}")
        with open(dst, "wb") as f:
            f.write(b"INJECTED")
        return InjectResult(abi=abi, text_rva=0x1000, text_size=8, seg_rva=0x2000,
                            entry_rva=0x2010, strategy="DT_INIT-hijack", cipher=cipher)
    return _inject


@requires_signing
def test_auto_select_skips_failures_and_keeps_original_bytes(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", ["lib/arm64-v8a/libgood.so",
                                       "lib/arm64-v8a/libbad.so"])
    out = str(tmp_path / "out.apk")
    monkeypatch.setattr(apk, "inject_so", _fake_inject({"libbad.so"}))
    ks = apk.KeystoreInfo(path=str(tmp_path / "ks.jks"))

    res = apk.repackage(src, out, None, keystore=ks, min_sdk=24, logger=lambda *_: None)

    assert [ir.abi for ir in res.injected] == ["arm64-v8a"]
    assert [n for n, _ in res.failed] == ["lib/arm64-v8a/libbad.so"]
    assert "synthetic failure" in res.failed[0][1]
    with zipfile.ZipFile(out) as z:
        assert z.read("lib/arm64-v8a/libgood.so") == b"INJECTED"
        # the skipped one must ship byte-identical to the input, not truncated or dropped
        assert z.read("lib/arm64-v8a/libbad.so") == b"\x7fELF-not-really"


def test_explicitly_named_failure_still_aborts(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", ["lib/arm64-v8a/libbad.so"])
    monkeypatch.setattr(apk, "inject_so", _fake_inject({"libbad.so"}))
    out = tmp_path / "out.apk"
    # the abort names the APK entry, not inject_so's temp copy
    with pytest.raises(InjectError, match=r"lib/arm64-v8a/libbad\.so: synthetic failure"):
        apk.repackage(src, str(out), ["libbad.so"], logger=lambda *_: None)
    assert not out.exists(), "an aborted pack must leave no partial output"


@requires_signing
def test_untouched_entries_carry_a_reason(tmp_path, monkeypatch):
    src = _mkapk(tmp_path / "in.apk", [
        "lib/arm64-v8a/libapp.so",
        "lib/arm64-v8a/libflutter.so",
        "lib/armeabi-v7a/libapp.so",
    ])
    monkeypatch.setattr(apk, "inject_so", _fake_inject(set()))
    ks = apk.KeystoreInfo(path=str(tmp_path / "ks.jks"))
    # exclude_libs is explicit: libflutter is a CONFIG-layer default now, so a direct
    # repackage() call knows nothing about it. Only ALWAYS_EXCLUDE_PATTERNS is implicit here.
    res = apk.repackage(src, str(tmp_path / "out.apk"), None, keystore=ks, min_sdk=24,
                        exclude_libs=["libflutter"], logger=lambda *_: None)

    assert len(res.injected) == 1
    assert dict(res.untouched) == {
        "lib/arm64-v8a/libflutter.so": "excluded by 'libflutter'",
        "lib/armeabi-v7a/libapp.so": "abi not selected",
    }


# ---- cross-ABI cleartext detection -----------------------------------------------------
#
# The bypass this reports is not a coverage gap: with `abis: [arm64-v8a]` (the default), a
# library protected on arm64 commonly ships an unencrypted, source-equivalent build one
# directory over in the SAME container. Measured on the repo's own output/vsa-encrypted.apk,
# 20 of 21 protected libraries had such a counterpart. sopack does not close that - it reports
# it, so the exposure is measured rather than invisible.

def test_cross_abi_reports_same_basename_under_other_abi():
    ents = ["lib/arm64-v8a/libpki.so", "lib/armeabi-v7a/libpki.so",
            "lib/x86_64/libpki.so", "res/x.png"]
    got = apk.find_cross_abi_cleartext(ents, ["lib/arm64-v8a/libpki.so"], container.APK)
    assert got == [("lib/arm64-v8a/libpki.so",
                    ["lib/armeabi-v7a/libpki.so", "lib/x86_64/libpki.so"])]


def test_cross_abi_silent_when_the_library_is_arm64_only():
    ents = ["lib/arm64-v8a/libonly.so", "lib/armeabi-v7a/libother.so"]
    assert apk.find_cross_abi_cleartext(ents, ["lib/arm64-v8a/libonly.so"], container.APK) == []


def test_cross_abi_does_not_flag_a_library_protected_on_every_abi():
    """If both copies were injected there is no cleartext copy to read."""
    ents = ["lib/arm64-v8a/libx.so", "lib/x86_64/libx.so"]
    assert apk.find_cross_abi_cleartext(ents, ents, container.APK) == []


def test_cross_abi_is_scoped_per_module_for_a_bundle():
    """Two modules may legitimately ship different libraries under one name, so a feature
    module's copy is NOT a cleartext counterpart of the base module's."""
    ents = ["base/lib/arm64-v8a/libapp.so", "base/lib/x86_64/libapp.so",
            "feat/lib/x86_64/libapp.so"]
    got = apk.find_cross_abi_cleartext(ents, ["base/lib/arm64-v8a/libapp.so"], container.AAB)
    assert got == [("base/lib/arm64-v8a/libapp.so", ["base/lib/x86_64/libapp.so"])]


def test_cross_abi_ignores_non_library_entries():
    """An APK's nested assets/lib/... is not a candidate - the APK pattern never matched it,
    and widening the match here would reintroduce exactly what container.py keeps apart."""
    ents = ["lib/arm64-v8a/libz.so", "assets/lib/armeabi-v7a/libz.so"]
    assert apk.find_cross_abi_cleartext(ents, ["lib/arm64-v8a/libz.so"], container.APK) == []


def test_cross_abi_surfaces_in_repack_result_and_report(tmp_path):
    """End to end: the field is populated by a real pack and reaches report.json."""
    from sopack import report
    src = mkapk(tmp_path / "in.apk",
                ["lib/arm64-v8a/libt.so", "lib/armeabi-v7a/libt.so"])
    res = apk.RepackResult()
    res.injected = [InjectResult(abi="arm64-v8a", text_rva=0, text_size=1, seg_rva=0,
                                 entry_rva=0, strategy="DT_INIT-hijack", cipher="wbaes",
                                 entry="lib/arm64-v8a/libt.so")]
    with zipfile.ZipFile(src) as z:
        ents = [i.filename for i in z.infolist()]
    res.cross_abi_cleartext = apk.find_cross_abi_cleartext(
        ents, [ir.entry for ir in res.injected], container.APK)
    assert res.cross_abi_cleartext == [
        ("lib/arm64-v8a/libt.so", ["lib/armeabi-v7a/libt.so"])]

    rep = report.build(config.Config.default(), res, input_apk=src, output_apk="o.apk",
                       exit_code=0, error=None, config_source="defaults")
    assert rep["cross_abi_cleartext_count"] == 1
    assert rep["cross_abi_cleartext"] == [
        {"entry": "lib/arm64-v8a/libt.so", "cleartext_at": ["lib/armeabi-v7a/libt.so"]}]
    # index.jsonl carries the COUNT only - the line is one os.write on an O_APPEND fd.
    line = report.index_line(rep)
    assert line["cross_abi_cleartext_count"] == 1
    assert "cross_abi_cleartext" not in line
