#!/usr/bin/env bash
#
# check_obfuscated.sh - decide, FROM THE ARTIFACT, whether O-MVLL ran on sopack's own code.
#
#   ./scripts/check_obfuscated.sh <libsopk_wb.so | sopk_rt_*.so> [--symbol NAME] [--min N]
#
# Exit 0 and print a one-line summary if obfuscated; exit 1 with a diagnosis if not; exit 2 if
# the question cannot be answered on this host (no llvm-objdump).
#
# WHY THIS EXISTS
#   A shared object carries no record of whether an obfuscator ran, so every caller answered
#   "is this obfuscated?" from a shell variable. That variable read `provider-obfuscation: omvll`
#   in shipped bundles whose provider was plain -O2 clang output, because --omvll only ever
#   reached the WBC sub-build. A claim that cannot be checked is a claim that eventually lies.
#
#   HARDENING.md Method 5 recorded the same lesson after the unstripped-helper incident: "The
#   build flag alone was not enough - a correct --release path already existed when the
#   unstripped helper shipped. Nothing refused one."
#
# THE SIGNAL
#   Branch density inside sopack's own entry point. Control-flow flattening rewrites a
#   straight-line function into a dispatch loop, multiplying conditional branches several times
#   over; control-flow-breaking and MBA add more. Measured on the shipped UNOBFUSCATED provider,
#   sopk_wb_k has 8 conditional branches in 544 bytes. The default floor of 40 sits far above
#   that and far below a flattened build, so it separates the two without asserting which exact
#   passes ran - deliberately, since the pass set is a config detail that may change.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"

TARGET=""; SYMBOL="sopk_wb_k"; MIN=40
while [ "$#" -gt 0 ]; do
    case "$1" in
        --symbol) SYMBOL="$2"; shift 2 ;;
        --min)    MIN="$2"; shift 2 ;;
        -h|--help) sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
        -*) echo "unknown arg: $1" >&2; exit 2 ;;
        *)  TARGET="$1"; shift ;;
    esac
done
[ -n "$TARGET" ] || { echo "usage: $0 <artifact.so> [--symbol NAME] [--min N]" >&2; exit 2; }
[ -f "$TARGET" ] || { echo "no such file: $TARGET" >&2; exit 2; }

# llvm-objdump from the NDK if we can find it, else anything on PATH.
OBJDUMP=""
if [ -n "${NDK:-}" ]; then
    case "$(uname -s)" in
        Darwin) HOSTTAG="darwin-x86_64" ;;
        *)      HOSTTAG="linux-x86_64" ;;
    esac
    [ -x "$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin/llvm-objdump" ] \
        && OBJDUMP="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin/llvm-objdump"
fi
[ -n "$OBJDUMP" ] || OBJDUMP="$(command -v llvm-objdump || true)"
[ -n "$OBJDUMP" ] || OBJDUMP="$(command -v objdump || true)"
[ -n "$OBJDUMP" ] || {
    echo "cannot verify obfuscation: no llvm-objdump/objdump on PATH and \$NDK has none.
       This is 'unknown', NOT 'obfuscated' - do not record a claim you could not check." >&2
    exit 2; }

# Resolve the symbol from .dynsym, then disassemble an ADDRESS RANGE - do not ask objdump to
# find the symbol by name. The artifact we are checking is always llvm-strip --strip-all'ed
# (HARDENING.md Method 5), so it has no .symtab, and llvm-objdump's --disassemble-symbols only
# consults .symtab: it silently prints an empty disassembly rather than erroring. GNU objdump
# happens to fall back to .dynsym, so the check would pass or fail depending on which objdump
# was first on PATH. --start-address/--stop-address behave identically in both.
READELF="$(command -v llvm-readelf || command -v readelf || true)"
[ -n "$READELF" ] || { echo "cannot verify obfuscation: no readelf on PATH." >&2; exit 2; }

read -r SYM_ADDR SYM_SIZE <<<"$("$READELF" --dyn-syms -W "$TARGET" 2>/dev/null \
    | awk -v s="$SYMBOL" '$8 == s && $4 == "FUNC" { print $2, $3; exit }')"
if [ -z "${SYM_ADDR:-}" ] || [ -z "${SYM_SIZE:-}" ] || [ "$SYM_SIZE" -eq 0 ] 2>/dev/null; then
    echo "cannot find exported FUNC '$SYMBOL' in $(basename "$TARGET")'s .dynsym.
       Expected an exported entry point to measure. Wrong artifact, or the symbol was renamed." >&2
    exit 2
fi
START=$((16#$SYM_ADDR))
STOP=$((START + SYM_SIZE))

DIS="$("$OBJDUMP" -d --start-address="$START" --stop-address="$STOP" "$TARGET" 2>/dev/null || true)"
if ! printf '%s' "$DIS" | grep -qE '^\s*[0-9a-f]+:'; then
    echo "disassembly of $SYMBOL (0x$SYM_ADDR +$SYM_SIZE) in $(basename "$TARGET") produced nothing.
       objdump=$OBJDUMP - is it built for this architecture?" >&2
    exit 2
fi

BR="$(printf '%s\n' "$DIS" | grep -cE '\b(b\.[a-z]+|cbz|cbnz|tbz|tbnz|jn?[a-z]{1,2})\b' || true)"
: "${BR:=0}"
INSNS="$(printf '%s\n' "$DIS" | grep -cE '^\s*[0-9a-f]+:' || true)"
: "${INSNS:=0}"

if [ "$BR" -lt "$MIN" ]; then
    echo "$SYMBOL in $(basename "$TARGET") has only $BR conditional branches in $INSNS instructions
       (floor is $MIN) - this is an UNOBFUSCATED build. O-MVLL did not run on sopack's own code.
       Check that scripts/fetch_omvll.sh vendored a plugin, that stub/omvll_config_wb.py exists,
       and that the plugin actually loaded - clang reports an unloadable pass-plugin once per
       translation unit, so the real error is easy to miss in the wall of output." >&2
    exit 1
fi
echo "$SYMBOL: $BR conditional branches in $INSNS instructions (floor $MIN)"
