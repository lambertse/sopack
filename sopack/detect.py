"""Recognise a container (or a single library) that sopack has ALREADY packed.

Re-packing sopack's own output is never what the caller meant, and until this module existed
the tool did it. What happened depended on the cipher, and neither outcome named the cause:

* `cipher: wbaes` - the second pack seals a NEW long-term key, so the `libsopk_wb.so` already
  inside cannot be reused (its blob would not unwrap the new helpers' session keys) and cannot
  be replaced (the OLD helpers unwrap against the old one). `apk.py`'s collision guard aborts
  with a bare `RuntimeError`, i.e. exit 1, "internal error" - blaming the packer for a bad input.
* `cipher: chacha20` / `xor` - nothing detected it at all. The already-encrypted `.text` was
  encrypted again and a second stub injected, producing an artifact whose behaviour nobody has
  characterised.

So detection has to work for all three modes, and the modes leave completely different traces.

TWO TIERS, and only one of them aborts
--------------------------------------
**Definitive** signals are ones nothing but sopack produces. They abort the pack
(`errors.AlreadyPackedError` -> exit 11) unless `allow-repack: true`.

**Heuristic** signals are ones sopack produces but so might another packer. They warn and let
the pack proceed. The only member is the stub-mode segment shape below: an appended R+X
`PT_LOAD` that no section covers, with `DT_INIT` pointing into it, is exactly what several
commercial packers also emit, and aborting a legitimate pack on it - with the only escape being
a config key the operator has to discover - is the worse failure.

Deliberately NOT used as a signal at any tier: the strings `expand 32-byte k` and
`/proc/self/auxv`, both of which the stub blob does carry. Any library containing a ChaCha20
implementation has the first, and the second is ordinary. They would be false positives on
innocent input.

Also not a signal: ZIP entry timestamps. `apk.py` deliberately stamps the artifacts it adds
with the TARGET's own `date_time` precisely so they do not stand out as post-processed, and
building a detector on the thing another part of the tool works to erase would make the two
fight.
"""
from __future__ import annotations

import struct

from .cipher import CIPHER_CHACHA20, CIPHER_XOR, WHITEN_SPAN, whiten
from .container import Container
from .metadata import SIZE as DECINFO_SIZE
from .rt_meta import (HELPER_BUILD_MARKER, HELPER_SONAME_PREFIX, PROVIDER_BUILD_MARKER,
                      PROVIDER_SONAME, SUPERSEDED_BUILD_MARKERS)
from .stubs import SUPPORTED_ABIS, StubMissingError, load_stub

# Program-header flag bits, and the combination the injected stub segment carries.
_PF_X, _PF_W, _PF_R = 1, 2, 4
_PF_RX = _PF_R | _PF_X

# ELF32/64 section-header field offsets, by class.
_SH_ADDR = {True: 0x10, False: 0x0C}
_SH_SIZE = {True: 0x20, False: 0x14}


def scan_entries(names, cont: Container) -> list[str]:
    """sopack's own added artifacts, found from the container's CENTRAL DIRECTORY alone.

    This is the primary gate: it needs no decompression, so it catches a `wbaes` re-pack - the
    default cipher, and the overwhelmingly common case - before a single byte of a ~150 MB
    input is inflated.

    Matched STRUCTURALLY against the container's own entry pattern (`lib/<abi>/` for an APK,
    `<module>/lib/<abi>/` for a bundle) rather than with `apk._match_lib_pattern`'s fnmatch:
    that matcher exists to interpret user-written globs generously, and generosity is the wrong
    instinct for a check whose false positive refuses to pack a legitimate app.
    """
    hits = []
    for name in names:
        m = cont.lib_re.match(name)
        if not m:
            continue
        so = m["so"]
        if so == PROVIDER_SONAME or so.startswith(HELPER_SONAME_PREFIX):
            hits.append(name)
    return hits


def scan_library(data: bytes) -> str | None:
    """A DEFINITIVE reason `data` is a sopack artifact or a sopack-packed target, else None.

    Costs one raw ELF parse over bytes the repackage loop has already read, so this runs over
    every candidate library rather than only the selected ones - the artifacts themselves are
    in `ALWAYS_EXCLUDE_PATTERNS` and would otherwise never be looked at.

    Never raises. The input is an arbitrary ZIP member that merely ends in `.so`, and a
    detector that dies on a truncated or non-ELF file would turn a cosmetic oddity into a
    failed pack. Anything unparseable is simply not evidence.
    """
    try:
        return _scan_library(data)
    except Exception:                                   # pragma: no cover - malformed input
        return None


def scan_library_heuristic(data: bytes) -> str | None:
    """A SUGGESTIVE reason, else None. Warns; never aborts. See the module docstring."""
    try:
        return _scan_library_heuristic(data)
    except Exception:                                   # pragma: no cover - malformed input
        return None


# ---- the definitive tier ----------------------------------------------------------

def _scan_library(data: bytes) -> str | None:
    if not data.startswith(b"\x7fELF"):
        return None

    # 1. Build markers. These identify a sopack HELPER or PROVIDER even if it has been renamed
    #    out of `lib/<abi>/libsopk_*.so` - the one thing that defeats `scan_entries`. They live
    #    in .rodata (SHF_ALLOC), so `_emit_helper`'s strip keeps them.
    #
    #    SUPERSEDED_BUILD_MARKERS is included on purpose: an APK packed by an OLDER sopack is a
    #    large share of what gets fed back in, and recognising only the current marker would
    #    miss exactly those.
    for marker, what in ((HELPER_BUILD_MARKER, "a sopack thin helper"),
                         (PROVIDER_BUILD_MARKER, "a sopack white-box provider"),
                         *((m, "a sopack helper from an older version")
                           for m in SUPERSEDED_BUILD_MARKERS)):
        if marker in data:
            return f"contains {what} (build marker {marker.hex()})"

    view = _view(data)

    # 2. A region magic at the exact START of a PT_LOAD. Catches a helper or provider built
    #    from a marker this version does not know about - a future one, or a fork's.
    #    Anchored to the segment start rather than scanned for anywhere in the file, because
    #    four ASCII bytes appear by chance in any large binary.
    for (_va, off, fsz, _msz) in view.loads:
        if fsz >= 4 and data[off:off + 4] in (b"SRTT", b"SRTW"):
            kind = "target" if data[off:off + 4] == b"SRTT" else "white-box"
            return f"carries a sopack {kind} region ({data[off:off + 4].decode()}) at 0x{off:x}"

    # 3. The TARGET side of a wbaes pack: it DT_NEEDEDs its own thin helper. Read through
    #    DT_STRTAB the way bionic does, not from the `.dynstr` section - wbaes supersedes that
    #    section with an appended copy, so the two legitimately disagree in exactly this mode.
    #
    #    This is what still fires when every `libsopk_*` entry has been deleted or renamed:
    #    the dependency is recorded inside the target itself.
    for soname in view.needed():
        if soname.startswith(HELPER_SONAME_PREFIX):
            return f"DT_NEEDED {soname} - already packed with cipher: wbaes"

    # 4. The stub ciphers (chacha20 / xor). They add nothing to the ZIP and no strings worth
    #    keying on, so the signal has to come from the injected blob itself.
    return _dewhiten_oracle(data, view)


def _dewhiten_oracle(data: bytes, view) -> str | None:
    """De-whiten the injected stub's metadata record and look for the decinfo magic.

    The shipped `sopk_decinfo` is XOR-masked with a ChaCha20 keystream whose key is a checksum
    over the WHITEN_SPAN stub bytes immediately before it - real code the injector never
    rewrites (`elf_inject._self_verify` asserts they come through byte-identical). For a STOCK
    stub those bytes are the same in every packed app, so the key is a precomputable constant
    and we can simply reverse the whitening and check for the 8-byte magic+version needle.

    That needle is why this belongs in the definitive tier rather than beside the segment-shape
    heuristic: a false positive needs 128 arbitrary bytes to de-whiten to `SOPK` + version 2.

    Two things it does NOT catch, both of which fall through to the heuristic tier:
      * `obfuscate: true`, which recompiles a freshly seeded stub per pack - the span differs,
        so the key differs and is not knowable from outside;
      * a pack made against a stub blob no longer present in `sopack/stubs/`.
    """
    for stub in _known_stubs():
        want = stub.decinfo_off + DECINFO_SIZE
        for (_va, off, fsz, _msz), flags in zip(view.loads, view.load_flags):
            # The injected segment is the whole flat blob, mapped R+X. Both conditions are
            # true by construction (`elf_inject.inject_so` sets `seg.content = stub.blob` and
            # `_self_verify` asserts R+X-and-not-W), and they are only a cheap pre-filter -
            # the magic needle below is what actually decides. p_memsz is deliberately NOT
            # compared: LIEF owns that field, and a false NEGATIVE here silently turns the
            # oracle off for every stub-mode input.
            if fsz != stub.size or (flags & (_PF_RX | _PF_W)) != _PF_RX:
                continue
            if off + want > len(data) or stub.decinfo_off < WHITEN_SPAN:
                continue
            span = data[off + stub.decinfo_off - WHITEN_SPAN:off + stub.decinfo_off]
            rec = whiten(data[off + stub.decinfo_off:off + want], span)
            if rec.startswith(_magic_needle()):
                return (f"an injected sopack stub segment at 0x{off:x} whose metadata record "
                        f"de-whitens to the decinfo magic ({stub.abi} stub, "
                        f"cipher: {_cipher_name(rec)})")
    return None


# ---- the heuristic tier -----------------------------------------------------------

def _scan_library_heuristic(data: bytes) -> str | None:
    """`DT_INIT` pointing into an R+X `PT_LOAD` that no section header covers.

    That is the shape the stub path leaves behind and the only thing left once the stub is
    polymorphic (`obfuscate: true`), because then every byte of it differs per pack. It is
    also a shape other packers emit, hence advisory: a normal toolchain always places
    `DT_INIT` inside `.init`/`.text`, so a hit is worth saying out loud and not worth aborting
    on.
    """
    if not data.startswith(b"\x7fELF"):
        return None
    view = _view(data)
    init_va = view.tags.get(_DT_INIT)
    if not init_va:
        return None
    for (va, _off, fsz, _msz), flags in zip(view.loads, view.load_flags):
        if not (va <= init_va < va + fsz):
            continue
        if (flags & (_PF_RX | _PF_W)) != _PF_RX:
            return None
        if _covered_by_section(data, view.is64, init_va):
            return None
        return (f"DT_INIT (0x{init_va:x}) points into an R+X segment that no section covers - "
                f"the shape an injected sopack stub leaves behind")
    return None


def _covered_by_section(data: bytes, is64: bool, va: int) -> bool:
    """Is `va` inside any section's address range? Section headers only - the point of the
    check is precisely that the injected segment has no section describing it."""
    W = "<Q" if is64 else "<I"
    e_shoff = _u(data, W, 0x28 if is64 else 0x20)
    e_shentsize = _u(data, "<H", 0x3A if is64 else 0x2E)
    e_shnum = _u(data, "<H", 0x3C if is64 else 0x30)
    if not e_shoff or not e_shnum:
        # No section table at all. Treat as covered, i.e. NOT evidence: bionic 14+ rejects such
        # a library outright, so whatever this file is, it is not a loadable packed target.
        return True
    for i in range(e_shnum):
        s = e_shoff + i * e_shentsize
        if s + e_shentsize > len(data):
            return True
        addr = _u(data, W, s + _SH_ADDR[is64])
        size = _u(data, W, s + _SH_SIZE[is64])
        if addr and addr <= va < addr + size:
            return True
    return False


# ---- plumbing ---------------------------------------------------------------------

def _view(data: bytes):
    # Imported lazily: elf_inject pulls in LIEF, and `detect` is imported by `apk` at module
    # scope purely to reach these functions. Keeping the import inside the call means a caller
    # that only ever uses `scan_entries` (the central-directory tier) pays nothing.
    from .elf_inject import _LoaderView
    return _LoaderView.from_bytes(data)


def _magic_needle() -> bytes:
    from .elf_inject import _MAGIC_NEEDLE
    return _MAGIC_NEEDLE


def _cipher_name(rec: bytes) -> str:
    """Which stub cipher the de-whitened record names.

    `cipher_id` is the third u32 of `sopk_decinfo` (see metadata._FMT / stub/decinfo.h), and
    reading it is the ONLY way to tell an xor pack from a chacha20 one from the outside: the two
    ship the identical blob, segment and strings and differ only at runtime.
    """
    cid = struct.unpack_from("<I", rec, 8)[0]
    return {CIPHER_XOR: "xor", CIPHER_CHACHA20: "chacha20"}.get(cid, f"id {cid}")


def _known_stubs():
    """Every stock stub blob this installation ships. Cached: `scan_library` runs per candidate
    library and these are a few KB read from disk."""
    global _STUB_CACHE
    if _STUB_CACHE is None:
        stubs = []
        for abi in SUPPORTED_ABIS:
            try:
                s = load_stub(abi)
            except (StubMissingError, ValueError, OSError):
                # A wbaes-only bundle need not carry stub blobs. Missing ones simply mean the
                # oracle cannot speak for that ABI; every other signal is unaffected.
                continue
            stubs.append(_StubFacts(abi=abi, size=len(s.blob), decinfo_off=s.decinfo_off))
        _STUB_CACHE = tuple(stubs)
    return _STUB_CACHE


class _StubFacts:
    """Just the two numbers the oracle needs, so the multi-KB blobs are not held resident."""
    __slots__ = ("abi", "size", "decinfo_off")

    def __init__(self, abi: str, size: int, decinfo_off: int) -> None:
        self.abi, self.size, self.decinfo_off = abi, size, decinfo_off


_STUB_CACHE = None
_DT_INIT = 12


def _u(data: bytes, fmt: str, off: int) -> int:
    return struct.unpack_from(fmt, data, off)[0]
