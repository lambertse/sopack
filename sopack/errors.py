"""Exceptions shared across layers, so the CLI can tell three unrelated failures apart.

`FileNotFoundError` was doing triple duty, and because it is also an `OSError` subclass it
shadowed everything more general in `cli._CODE_FOR`. All three of these reported themselves as
"the input APK is missing":

* the input APK really is missing            -> `InputError`      -> exit 4
* a HOST TOOL is missing (apksigner, keytool, zipalign, wb_keygen) -> `ToolMissingError` -> exit 7
* the OUTPUT path cannot be written          -> plain OSError     -> exit 10

That mattered most for `wb_keygen`: "could not find a host wb_keygen" is the first section of
docs/TROUBLESHOOTING.md and the most-hit failure on a fresh checkout, and reporting it as an
input error sends the reader to look at their APK instead of at their toolchain.

`ToolMissingError` and `InputError` both subclass `FileNotFoundError` deliberately, so every
pre-existing `except FileNotFoundError` keeps catching them - notably `apk.repackage`'s
best-effort signing path, which demotes a missing apksigner to a warning rather than failing the
pack.

`AlreadyPackedError` is the fourth resident and is unrelated to that split. It lives here, rather
than in `apk.py` beside its nearest relatives `NothingPackedError` and `SelectionError`, because
`detect.py` raises it and must stay importable without dragging in the packer.

This module imports nothing from sopack, so it can be imported from any layer without a cycle.
"""
from __future__ import annotations


class ToolMissingError(FileNotFoundError):
    """A host tool sopack shells out to is not installed or not findable.

    Distinct from `stubs.StubMissingError` (a build ARTIFACT is absent) even though both map to
    exit 7: one is fixed by installing an SDK or a JDK, the other by running a build script. The
    message says which.
    """


class AlreadyPackedError(RuntimeError):
    """The input container already carries sopack's own artifacts - it is a packed OUTPUT.

    Re-packing is never what the caller meant, and for `cipher: wbaes` it is actively
    destructive: a second pack seals a NEW long-term key, and the pre-existing
    `libsopk_wb.so` cannot be replaced without orphaning every thin helper already inside,
    so `apk.py`'s collision guard aborts. That guard raises a bare `RuntimeError`, i.e.
    exit 1 "internal error", which blames the packer for a bad input; this class exists so
    the condition gets its own code (`exitcodes.ALREADY_PACKED`) and a message naming the
    evidence. The stub ciphers have no such guard at all and would silently double-encrypt.

    NOT a subclass of `apk.NothingPackedError`: nothing was attempted, let alone packed, and
    inheriting would make the two codes' precedence in `cli._CODE_FOR` depend on ordering
    for no reason. `RuntimeError` is deliberate, though - `cli.main`'s except-tuple already
    lists it, so this is caught with no change there.

    `.entries` holds the evidence, so the message can name what was found rather than
    asserting a conclusion the operator cannot check.
    """

    def __init__(self, message: str, entries: "list[str] | None" = None) -> None:
        super().__init__(message)
        self.entries = list(entries or ())


class InputError(FileNotFoundError):
    """The input APK is missing, unreadable, or not a file.

    Raised by an explicit up-front check rather than inferred from wherever the first open()
    happens to fail, because "which path was this about?" is not recoverable from an errno after
    the fact - and getting it wrong is how an unwritable OUTPUT directory came to be reported as a
    missing input.
    """
