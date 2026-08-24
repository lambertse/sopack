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
    for r in "${NDK:-}" "${ANDROID_NDK_HOME:-}" "${ANDROID_NDK_ROOT:-}"; do
        [ -n "$r" ] && [ -x "$r/toolchains/llvm/prebuilt/$tag/bin/$n" ] \
            && { echo "$r/toolchains/llvm/prebuilt/$tag/bin/$n"; return 0; }
    done
    command -v "llvm-$n" 2>/dev/null && return 0
    command -v "$n" 2>/dev/null && return 0
    return 1
}
READELF="$(find_tool readelf || true)"
[ -n "$READELF" ] || { echo "cannot verify obfuscation: no readelf available. That is 'unknown',
       NOT 'obfuscated' - do not record a claim you could not check." >&2; exit 2; }

if [ "$MODE" = "text" ]; then
    : "${MIN:=1000}"   # between the measured 613 (plain) and 1537 (obfuscated)
    OBJDUMP="$(find_tool objdump || true)"
    [ -n "$OBJDUMP" ] || { echo "cannot verify obfuscation: no objdump available (unknown)." >&2; exit 2; }
    INSNS="$("$OBJDUMP" -d --section=.text "$TARGET" 2>/dev/null | grep -cE '^[[:space:]]*[0-9a-f]+:' || true)"
    : "${INSNS:=0}"
    [ "$INSNS" -gt 0 ] || { echo "no .text instructions found in $(basename "$TARGET") (unknown)." >&2; exit 2; }
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

# --- mode symbol: sum SYMBOL and its O-MVLL outlined siblings, from .symtab, PRE-STRIP -------
: "${MIN:=600}"   # plain sopk_wb_k is 544 bytes; obfuscation took a 128-byte function to 1764
if [ "$("$READELF" -SW "$TARGET" 2>/dev/null | grep -c '\.symtab')" -eq 0 ]; then
    echo "$(basename "$TARGET") has no .symtab - it is already stripped, and O-MVLL's outlined
       siblings ($SYMBOL.1, ...) are LOCAL symbols that the strip removed. This check must run
       BEFORE llvm-strip. Cannot tell from this artifact." >&2
    exit 2
fi
TOTAL="$("$READELF" -sW "$TARGET" 2>/dev/null \
    | awk -v s="$SYMBOL" '$4=="FUNC" && ($8==s || index($8, s ".")==1) { n+=$3 } END{print n+0}')"
if [ "$TOTAL" -eq 0 ]; then
    echo "no FUNC symbol '$SYMBOL' (or '$SYMBOL.*') in $(basename "$TARGET") (unknown)." >&2
    exit 2
fi
if [ "$TOTAL" -lt "$MIN" ]; then
    echo "$SYMBOL family in $(basename "$TARGET") totals $TOTAL bytes (floor $MIN) - UNOBFUSCATED.
       O-MVLL did not run on sopack's own code. A plain sopk_wb_k is 544 bytes and obfuscation
       both grows it and splits it into $SYMBOL.1 etc; neither happened here." >&2
    exit 1
fi
echo "$SYMBOL family in $(basename "$TARGET"): $TOTAL bytes across $("$READELF" -sW "$TARGET" 2>/dev/null | awk -v s="$SYMBOL" '$4=="FUNC" && ($8==s || index($8, s ".")==1)' | wc -l | tr -d ' ') symbol(s) (floor $MIN)"
