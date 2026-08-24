#!/usr/bin/env bash
#
# check_obfuscated.sh - decide, FROM THE ARTIFACT, whether O-MVLL ran on sopack's own code.
#
#   ./scripts/check_obfuscated.sh --mode text   [--min N] <sopk_rt_*.so>
#   ./scripts/check_obfuscated.sh --mode symbol [--min N] [--symbol S] <libsopk_wb.so>
#
# Exit 0 = obfuscated (prints the measurement), 1 = demonstrably NOT, 2 = cannot tell.
# EXIT 2 IS NEVER A PASS. A caller that records "obfuscated" on a 2 is lying with extra steps.
#
# WHY THIS EXISTS
#   A shared object records no obfuscation state, so every caller used to answer "is this
#   obfuscated?" from a shell variable. That variable read `provider-obfuscation: omvll` in
#   shipped bundles whose provider was plain -O2 output, because --omvll only ever reached the
#   WBC sub-build. HARDENING.md Method 5 recorded the same lesson after the unstripped-helper
#   incident: "The build flag alone was not enough - a correct --release path already existed
#   when the unstripped helper shipped. Nothing refused one." So: refuse one.
#
# HOW THE SIGNAL WAS CHOSEN (all measured on this repo's toolchain, not assumed)
#   Control-flow flattening + break_control_flow + MBA on one function:
#       plain        32 instructions,  4 conditional branches
#       obfuscated  441 instructions, 11 conditional branches
#   Instructions grew 13.8x; conditional branches only 2.75x, and branch DENSITY actually fell
#   (12.5% -> 2.5%) because flattening dispatches through computed branches. An earlier version
#   of this script thresholded on branch count; it would have been close to useless. Code growth
#   is the signal.
#
#   Two further findings shape the two modes:
#
#   1. A symbol's st_size is NOT a reliable measure. O-MVLL outlines the body into a sibling
#      (`sopk_wb_k` 128 -> 56 bytes, plus a new `sopk_wb_k.1` of 1708). Measured naively, an
#      obfuscated function looks SMALLER than a plain one. Mode `symbol` therefore sums the
#      whole family: SYMBOL plus SYMBOL.* .
#   2. Those outlined siblings are LOCAL symbols, so `llvm-strip --strip-all` deletes them.
#      Mode `symbol` only works BEFORE the strip. Call it there.
#
# WHICH MODE FOR WHICH ARTIFACT
#   thin helper  sopk_rt_<abi>.so  -> --mode text. Its .text is 100% sopack's code (it links no
#                                    white-box at all), so whole-.text instruction count is a
#                                    clean proxy AND survives stripping.
#
#                                    BOTH SIDES MEASURED on real artifacts:
#                                        plain        613 instructions
#                                        obfuscated  1537 instructions   (2.5x)
#
#                                    Only 2.5x, not the 8-14x a single function shows, because
#                                    much of the helper's .text is libc glue (__on_dlclose,
#                                    atexit, pthread_atfork, __clear_cache) that the config
#                                    correctly does not touch. The floor is 1000 - comfortably
#                                    above plain, comfortably below obfuscated. An earlier
#                                    version guessed 1500 from the plain side alone, which the
#                                    real obfuscated build clears by 37 instructions; that would
#                                    have hard-failed builds on any pass-set change.
#   provider     libsopk_wb.so     -> --mode symbol, BEFORE stripping. Its .text is 75,602
#                                    instructions, almost all vendored libwbcrypto, so whole-
#                                    .text would drown sopk_wb_k's 136 entirely.
set -euo pipefail

MODE=""; TARGET=""; SYMBOL="sopk_wb_k"; MIN=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --mode)   MODE="$2"; shift 2 ;;
        --symbol) SYMBOL="$2"; shift 2 ;;
        --min)    MIN="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
        -*) echo "unknown arg: $1" >&2; exit 2 ;;
        *)  TARGET="$1"; shift ;;
    esac
done
[ -n "$TARGET" ] || { echo "usage: $0 --mode text|symbol <artifact.so>" >&2; exit 2; }
[ -f "$TARGET" ] || { echo "no such file: $TARGET" >&2; exit 2; }
case "$MODE" in
    text|symbol) ;;
    *) echo "--mode must be 'text' (thin helper) or 'symbol' (provider, pre-strip)" >&2; exit 2 ;;
esac

find_tool() {   # find_tool NAME -> path, preferring the NDK's copy
    local n="$1" tag
    case "$(uname -s)" in Darwin) tag="darwin-x86_64" ;; *) tag="linux-x86_64" ;; esac
    # llvm-$n FIRST inside the NDK: it ships llvm-objdump and llvm-readelf, never a plain
    # `objdump`. Looking for the plain name only meant falling through to whatever was on PATH -
    # and in the builder container that is an x86_64-only binutils objdump, which disassembles
    # an aarch64 .so to nothing. The check then reported "no .text instructions" (correctly exit
    # 2, "cannot tell") instead of measuring, so the gate went blind on the one host that
    # matters. Prefer the cross-capable tool that is guaranteed to be present.
    for r in "${NDK:-}" "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
        [ -n "$r" ] || continue
        for cand in "llvm-$n" "$n"; do
            [ -x "$r/toolchains/llvm/prebuilt/$tag/bin/$cand" ] \
                && { echo "$r/toolchains/llvm/prebuilt/$tag/bin/$cand"; return 0; }
        done
    done
    command -v "llvm-$n" 2>/dev/null && return 0
    command -v "$n" 2>/dev/null && return 0
    return 1
}
# $NDK is REQUIRED, and this is a hard error rather than a fallback. The tools that can read an
# Android .so are the NDK's; a host binutils is either absent or - on an x86_64 builder reading
# an aarch64 artifact - silently returns an empty disassembly, which this script then has to
# report as "cannot tell". A gate that degrades to "cannot tell" whenever an environment
# variable is unset is not a gate, and the whole point of this script is that the obfuscation
# claim must be checkable. Fail loudly and name the fix.
if [ -z "${NDK:-}${ANDROID_NDK_HOME:-}${ANDROID_NDK_ROOT:-}" ]; then
    echo "ERROR: \$NDK is not set (nor ANDROID_NDK_HOME / ANDROID_NDK_ROOT).
       This check needs the NDK's llvm-readelf and llvm-objdump: they are the tools that can
       read an aarch64 .so. A host objdump is usually x86_64-only and disassembles an Android
       library to nothing, which would make this report 'cannot tell' instead of measuring.
       Set NDK=/path/to/android-ndk-r29 and re-run." >&2
    exit 2
fi

READELF="$(find_tool readelf || true)"
[ -n "$READELF" ] || { echo "cannot verify obfuscation: no readelf found, even with \$NDK set.
       Is \$NDK really an NDK root? Expected
       \$NDK/toolchains/llvm/prebuilt/<host>/bin/llvm-readelf." >&2; exit 2; }

if [ "$MODE" = "text" ]; then
    : "${MIN:=1000}"   # between the measured 613 (plain) and 1537 (obfuscated)
    OBJDUMP="$(find_tool objdump || true)"
    [ -n "$OBJDUMP" ] || { echo "cannot verify obfuscation: no objdump available (unknown)." >&2; exit 2; }
    INSNS="$("$OBJDUMP" -d --section=.text "$TARGET" 2>/dev/null | grep -cE '^[[:space:]]*[0-9a-f]+:' || true)"
    : "${INSNS:=0}"
    if [ "$INSNS" -eq 0 ]; then
        echo "no .text instructions found in $(basename "$TARGET") using $OBJDUMP - it most
       likely cannot disassemble this architecture (a non-multiarch binutils objdump reads an
       aarch64 .so as empty). Set \$NDK so the bundled llvm-objdump is used. Reporting
       'cannot tell' rather than a pass." >&2
        exit 2
    fi
    if [ "$INSNS" -lt "$MIN" ]; then
        echo "$(basename "$TARGET") has $INSNS .text instructions (floor $MIN) - UNOBFUSCATED.
       Its .text is entirely sopack's own code, so this is a direct measurement, not a proxy.
       Measured on real artifacts: 613 instructions plain, 1537 obfuscated.
       Check that scripts/fetch_omvll.sh vendored a plugin, that stub/omvll_config_wb.py
       exists, and that the plugin actually LOADED - clang reports an unloadable pass-plugin
       once per translation unit, so the real error hides in the wall of output." >&2
        exit 1
    fi
    echo "$(basename "$TARGET"): $INSNS .text instructions (floor $MIN)"
    exit 0
fi

# --- mode symbol: outlining siblings in .symtab, PRE-STRIP ---------------------------------
#
# The signal is STRUCTURAL, not a size threshold, and that is deliberate. O-MVLL splits every
# function it transforms into `name` plus `name.1`, `name.2`, ... Measured on the thin helper:
#
#     plain        sopk_rt_ctor self_cb tgt_cb sopk_wipe                     (4 symbols, no .N)
#     obfuscated   ...plus sopk_rt_ctor.1 self_cb.2 tgt_cb.3 sopk_wipe.4     (8 symbols)
#
# Presence of a `.N` sibling is binary and holds across plugin versions, whereas code growth
# emphatically does not: the same source measured 613 / 1247 / 2223 instructions depending on
# O-MVLL version and one method name. A threshold calibrated on one toolchain silently
# mis-gates another, which is how this check first shipped wrong. Bytes are still reported,
# for context; the sibling is what decides. --min is accepted but unused in this mode.
: "${MIN:=0}"
if [ "$("$READELF" -SW "$TARGET" 2>/dev/null | grep -c '\.symtab')" -eq 0 ]; then
    echo "$(basename "$TARGET") has no .symtab - it is already stripped, and O-MVLL's outlined
       siblings ($SYMBOL.1, ...) are LOCAL symbols the strip removed. This check must run
       BEFORE llvm-strip. Cannot tell from this artifact." >&2
    exit 2
fi
SYMS="$("$READELF" -sW "$TARGET" 2>/dev/null \
    | awk -v s="$SYMBOL" '$4=="FUNC" && ($8==s || index($8, s ".")==1) { print $8, $3 }')"
if [ -z "$SYMS" ]; then
    echo "no FUNC symbol '$SYMBOL' (or '$SYMBOL.*') in $(basename "$TARGET") (unknown)." >&2
    exit 2
fi
NSYM="$(printf '%s\n' "$SYMS" | wc -l | tr -d ' ')"
TOTAL="$(printf '%s\n' "$SYMS" | awk '{n+=$2} END{print n+0}')"
OUTLINED="$(printf '%s\n' "$SYMS" | awk -v s="$SYMBOL" '$1 != s' | wc -l | tr -d ' ')"

# Outlining alone decides. A byte floor cannot: a plain sopk_rt_ctor is 1704 bytes and a plain
# sopk_wb_k is 544, so any single threshold either passes the unobfuscated helper or fails the
# obfuscated provider. The sibling count needs no per-symbol calibration at all.
if [ "$OUTLINED" -eq 0 ]; then
    echo "$SYMBOL in $(basename "$TARGET") is a single $TOTAL-byte function with no outlined
       siblings - UNOBFUSCATED. O-MVLL splits what it transforms into $SYMBOL.1, $SYMBOL.2, ...
       and none are present.
       Check that a plugin is vendored (scripts/fetch_omvll.sh), that the config exists, and
       that the plugin actually LOADED - clang reports an unloadable pass-plugin once per
       translation unit, so the real error hides in the wall of output.
       Check the config's METHOD NAMES too: ObfuscationConfig dispatches by exact name and
       silently ignores one it does not know (the real name for flattening is flatten_cfg)." >&2
    exit 1
fi
echo "$SYMBOL family in $(basename "$TARGET"): $NSYM symbol(s), $OUTLINED outlined, $TOTAL bytes"
