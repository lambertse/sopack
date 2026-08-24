"""O-MVLL obfuscation config for sopack's own wbaes skeletons.

Targets `stub/sopk_wb.c` (the shared white-box provider) and `stub/sopk_rt.c` (the thin
per-target helper) as built by scripts/build_wbaes.sh. It is NOT for the freestanding
ChaCha20 stub - that one is `stub/omvll_config.py`, and its constraints are far tighter
(the stub must stay relocation-free, undefined-symbol-free and adrp-free, so only a small
pass set is usable). Two policies, because two very different artifacts.

WHY THIS EXISTS
---------------
`--omvll` used to reach only WBC's `build_android.sh`, i.e. the vendored `libwbcrypto.a`.
sopack's OWN code - the region scan, the passphrase de-whitening, the wbc_* call sequence,
and the entire decrypt-and-place dance - shipped as plain -O2 clang output, while
MANIFEST.txt recorded `provider-obfuscation: omvll` and install.sh presented that as a
property of libsopk_wb.so. Verified by disassembling a shipped provider: straight-line
argument validation, `cmp #0x30` / `cmp #0x20` / `cmp #0x400` all legible, no flattening.

WHY NOT WBC's CONFIG
--------------------
WBC's `third_party/omvll/omvll_config.py` gates on module names - vm.cpp, handlers.cpp,
trusted_storage.cpp. None of those exist here, so reusing it would apply NO passes and
produce a clean, successful, unobfuscated build. That failure is silent, which is exactly
why build_wbaes.sh scopes OMVLL_CONFIG per-invocation instead of exporting it.

THE TARGETING RULE (inherited from WBC's hard-won lesson)
---------------------------------------------------------
Target individual FUNCTIONS, never whole modules. Gating on the module alone obfuscates
every inlined libc++/STL template instantiation in the translation unit, which overwhelms
the register allocator and crashes the backend (exit 139, "Register Coalescer"). So
`_is_library_fn` runs FIRST and rejects runtime/library functions before anything else.

The provider statically links libwbcrypto.a (which brings libsodium and a static libc++),
so that hazard is live here in a way it is not for the thin helper.
"""
import os
from functools import lru_cache

import omvll

# sopack's own entry points, by symbol name. sopk_wb_k is the provider's single export;
# the sopk_rt_* names are the thin helper's ctor and the routines it inlines.
# Verified against the real unstripped artifacts rather than guessed from the source, because
# two of the obvious names do not exist to match:
#
#   sopk_chacha20_apply, sopk_whiten_key   `static inline` in stub_cipher.h. At -O2 they are
#                                          inlined into their callers and emit NO symbol, so
#                                          naming them here would have matched nothing. They
#                                          are still covered - as part of the function they
#                                          were inlined into.
#
# Provider (libsopk_wb.so) has exactly one sopack symbol: sopk_wb_k (544 bytes).
# Helper (sopk_rt_<abi>.so): sopk_rt_ctor (1704 B), self_cb (208), tgt_cb (144),
#                            sopk_wipe (132), sopk_fail (20) - 613 .text instructions total.
_TARGETS = {
    # provider: SRTW scan, passphrase de-whitening, wbc_open/wbc_unwrap_key
    "sopk_wb_k",
    # helper: the decrypt-and-place dance. Inlines the ChaCha20 and the whitening-key
    # derivation, and is 1704 of the helper's ~2452 .text bytes.
    "sopk_rt_ctor",
    # helper: the region magic-scan and the dl_iterate_phdr target lookup. Small, but they are
    # the part that says HOW a helper finds its region and its target - i.e. the protocol.
    "self_cb",
    "tgt_cb",
    # helper: key wipe. Worth obfuscating because its shape identifies where the session key
    # lived a moment earlier.
    "sopk_wipe",
}

# Rejected first, always. Mangling prefixes cover the C++ runtime the provider links in.
_LIB_PREFIXES = ("_ZSt", "_ZNSt", "_ZNKSt", "_ZN9__gnu_cxx")
_LIB_MARKERS = (
    "std::", "__ndk1", "__libcpp", "allocator", "__split_buffer",
    "_ConstructTransaction", "__unwrap", "__rewrap", "__clang_call_terminate",
    "__cxa_", "__gxx_personality",
    # Never obfuscate the vendored crypto from here: WBC's own config already covers
    # libwbcrypto.a at ITS build, and double-obfuscation buys nothing for real cost.
    "wbc_", "sodium_", "crypto_", "argon2",
)


def _name_of(func) -> str:
    for attr in ("demangled_name", "name"):
        try:
            value = getattr(func, attr)
            if value:
                return str(value)
        except Exception:
            pass
    return ""


def _is_library_fn(func) -> bool:
    name = _name_of(func)
    if not name:
        return True          # unknown -> treat as library, i.e. leave it alone
    if name.startswith(_LIB_PREFIXES):
        return True
    return any(m in name for m in _LIB_MARKERS)


def _in_scope(mod, func) -> bool:
    if _is_library_fn(func):
        return False
    return _name_of(func) in _TARGETS


# Optional per-build seed, same mechanism as the stub's config. Not polymorphism here - the
# skeletons are built once and cloned into every app, so this only makes a given BUILD
# reproducible. probability_seed is a signed int32 in O-MVLL's binding; mask to 31 bits so a
# large seed cannot overflow it ("TypeError: incompatible function arguments").
_seed = os.environ.get("SOPK_WB_SEED")
if _seed:
    omvll.config.probability_seed = int(_seed) & 0x7FFFFFFF


class SopackWbConfig(omvll.ObfuscationConfig):
    def flatten_functions(self, mod, func):
        return _in_scope(mod, func)

    def break_control_flow(self, mod, func):
        return _in_scope(mod, func)

    def obfuscate_arithmetic(self, mod, func):
        return _in_scope(mod, func)

    def obfuscate_constants(self, mod, func):
        # The region-layout constants (48, 32, 1024, version 3) are the clearest tell in a
        # disassembly of sopk_wb_k - they name the protocol outright.
        return _in_scope(mod, func)

    def obfuscate_struct_access(self, mod, func, struct):
        return _in_scope(mod, func)

    def obfuscate_string(self, mod, func, string):
        # Release skeletons carry no log strings, but the magic bytes and build markers are
        # rodata this can reach. Harmless when there is nothing to encode.
        return _in_scope(mod, func)

    def anti_hooking(self, mod, func):
        # Permanently off: it conflicts with control-flow flattening ("Cannot inject a
        # hooking prologue ... since there is one") on the cloned functions CFF produces.
        # Observed on NDK r29 / O-MVLL 1.9.1, same as WBC hit.
        return False


@lru_cache(maxsize=1)
def omvll_get_config():
    return SopackWbConfig()
