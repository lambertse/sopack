"""decinfo layout must stay 128 bytes and survive pack/unpack unchanged (it is the
binary contract with stub/decinfo.h)."""
import os
import pytest

from sopack.cipher import WHITEN_NONCE, WHITEN_SPAN, whiten, whiten_key
from sopack.metadata import DecInfo, FLAG_CHAIN_INIT, SIZE


def test_size_is_128():
    assert SIZE == 128


def test_pack_unpack_roundtrip():
    info = DecInfo(
        cipher_id=1, flags=FLAG_CHAIN_INIT,
        delta_text=-0x12345, text_size=0xABCDE,
        delta_init=0x7788, key=bytes(range(32)), nonce=bytes(range(16)),
    )
    blob = info.pack()
    assert len(blob) == 128
    back = DecInfo.unpack(blob)
    assert back.cipher_id == 1
    assert back.flags == FLAG_CHAIN_INIT
    assert back.delta_text == -0x12345
    assert back.text_size == 0xABCDE
    assert back.delta_init == 0x7788
    assert back.key == bytes(range(32))
    assert back.nonce == bytes(range(16))


def test_whiten_is_self_inverse():
    """Whitening is XOR with a keystream, so applying it twice with the same span is the
    identity - this is exactly what the injector (whiten) and the stub (de-whiten) rely on."""
    span = os.urandom(WHITEN_SPAN)
    record = os.urandom(SIZE)
    assert whiten(whiten(record, span), span) == record


def test_whiten_key_kat():
    """Pin the whiten-key derivation so an accidental change to the Python side is caught.
    The C mirror (stub/stub_cipher.h sopk_whiten_key) is locked separately by the aarch64
    dlopen integration test, which only decrypts if both sides agree byte for byte."""
    span = bytes(range(256)) * 4        # 1024 deterministic bytes
    assert whiten_key(span).hex() == (
        "ef3cacbb1efb8cf87396e014800a76a3d08bf1520a1830872e86474941ed143c")
    assert len(WHITEN_NONCE) == 16 and WHITEN_SPAN == 1024


def test_whiten_key_changes_with_span():
    """Different span bytes must yield a different key (tamper -> garbage de-whiten)."""
    base = bytes(WHITEN_SPAN)
    tampered = bytearray(base)
    tampered[0] ^= 0x01
    assert whiten_key(bytes(base)) != whiten_key(bytes(tampered))


if __name__ == "__main__":
    test_size_is_128()
    test_pack_unpack_roundtrip()
    test_whiten_is_self_inverse()
    test_whiten_key_kat()
    test_whiten_key_changes_with_span()
    print("metadata tests passed")


# ---- stub logging is a COMPILE-time decision, not just a runtime flag -------------------
#
# The 14 staged messages and "/dev/socket/logdw" used to ship in every packed library, gated
# only by a bit in decinfo. stub_log.h claimed that when off "the code is compiled in but never
# called, so it is invisible" - true of logcat, false of `strings`. They are compiled out now,
# which means logging.stub-log can no longer be honoured by a default stub.

def test_default_stub_carries_no_log_strings():
    """The shipped blobs must not contain the staged messages or the logd socket path."""
    from sopack import stubs
    for abi in stubs.SUPPORTED_ABIS:
        try:
            blob = stubs.load_stub(abi).blob
        except stubs.StubMissingError:
            pytest.skip(f"stub for {abi} not built")
        for needle in (b"H:native .text decrypted OK", b"A:entry", b"/dev/socket/logdw",
                       b"C:mmap ok=", bytes([0x29, 0x35, 0x2a, 0x3b, 0x39, 0x31])):
            assert needle not in blob, f"{abi} stub leaks {needle!r}"


def test_default_stub_reports_no_log_support():
    from sopack import stubs
    try:
        assert stubs.load_stub("arm64-v8a").log is False
    except stubs.StubMissingError:
        pytest.skip("stub not built")


def test_stub_log_requested_against_a_non_logging_stub_is_refused():
    """Silently not logging is the failure mode this guard exists to prevent."""
    from sopack import stubs
    from sopack.elf_inject import InjectError, inject_so
    try:
        if stubs.load_stub("arm64-v8a").log:
            pytest.skip("this checkout has a --with-log stub")
    except stubs.StubMissingError:
        pytest.skip("stub not built")
    with pytest.raises(InjectError, match="without logging support"):
        inject_so("tests/fixtures/mini_arm64.so", "/tmp/sopk_t.so", "arm64-v8a",
                  cipher="chacha20", log=True)


def test_whitening_span_still_fits_the_smaller_stub():
    """Dropping the log code shrank the blob by two thirds; decinfo_off must still leave a
    full WHITEN_SPAN of real code before it, with enough entropy to key on."""
    from sopack import stubs
    from sopack.cipher import WHITEN_SPAN
    for abi in stubs.SUPPORTED_ABIS:
        try:
            st = stubs.load_stub(abi)
        except stubs.StubMissingError:
            pytest.skip(f"stub for {abi} not built")
        assert st.decinfo_off >= WHITEN_SPAN, f"{abi}: decinfo_off {st.decinfo_off} < span"
        span = st.blob[st.decinfo_off - WHITEN_SPAN:st.decinfo_off]
        assert len(set(span)) >= 16, f"{abi}: whitening span has too few distinct bytes"
