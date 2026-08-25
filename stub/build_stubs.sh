#!/usr/bin/env bash
#
# build_stubs.sh - compile the injectable decryption stub into flat, relocation-free
# blobs (one per ABI) plus a JSON sidecar recording the offsets the injector needs
# (sopk_entry and g_decinfo within the blob).
#
# The stub is freestanding (raw syscalls, no Android sysroot), so it can be built with
# EITHER the Android NDK or a plain multi-target LLVM. Toolchain selection:
#   * ANDROID_NDK_HOME / ANDROID_NDK_ROOT / NDK  -> use that NDK's clang/llvm (first one set
#                                                   wins; the wrapper scripts export
#                                                   ANDROID_NDK_HOME from their own --ndk).
#   * otherwise                                  -> use clang / llvm-objcopy / llvm-readelf
#                                                   from PATH (e.g. conda-forge LLVM).
# Output goes to sopack/stubs/ so the Python package can ship the blobs as data.
#
# Usage: ANDROID_NDK_HOME=/path/to/ndk ./build_stubs.sh [API_LEVEL]
#    or: ./build_stubs.sh            # plain LLVM on PATH
#
# Requires an NDK r19+ (must bundle lld - a real version looks like 27.0.12077973, NOT 4.8.0)
# OR a modern LLVM (clang + lld + llvm-objcopy + llvm-readelf) on PATH. With OMVLL_PLUGIN set
# the floor is higher and exact: -fpass-plugin needs clang 13+ (NDK r26+), and the vendored
# plugin loads ONLY into the clang it was built against - r29, per scripts/fetch_omvll.sh. Both
# are checked before the first compile rather than left to a clang error naming no NDK.
# Run with bash (>= 3.2), not sh.
set -euo pipefail

# This script's only caller in the pack path is sopack/obfuscate.py, which reports the failed
# build's stderr and nothing else. `set -e` + `pipefail` can end a run with rc=1 and NO output
# at all - most easily through a command substitution whose pipeline fails - and that arrives as
# "obfuscated stub build failed after 3 seeds; last error:" with nothing after the colon. An ERR
# trap costs one line and makes every such exit name its own line number. It does not fire for
# the deliberate `exit 1`s below (each already printed its reason), nor for a command failing
# inside an `if`/`&&` condition, so it adds no noise to the guards.
trap 'rc=$?; echo "ERROR: build_stubs.sh failed at line $LINENO (exit $rc) without a message of
       its own - a command failed under set -e/pipefail. Reproduce with:
       ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-} OMVLL_PLUGIN=${OMVLL_PLUGIN:-} bash $0" >&2' ERR

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Output dir: default ships into the package; SOPK_STUB_OUT lets the per-pack polymorphic path
# build a fresh, seeded, obfuscated stub set into a temp dir without touching the shipped one.
OUT="${SOPK_STUB_OUT:-$HERE/../sopack/stubs}"

# API level is positional (historically `build_stubs.sh 24`), and --with-log is a flag, so the
# flag has to be filtered out before ${1} is read as the API - otherwise `build_stubs.sh
# --with-log` would silently build for API "--with-log" and fail deep inside clang.
WITH_LOG=0
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --with-log) WITH_LOG=1 ;;
        -h|--help)  sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
        -*)         echo "ERROR: unknown option: $arg" >&2; exit 2 ;;
        *)          POSITIONAL+=("$arg") ;;
    esac
done
API="${POSITIONAL[0]:-24}"
mkdir -p "$OUT"

# ABI:triple pairs. Kept as a plain space-separated list (not a bash-4 associative
# array) so this script also runs on macOS's built-in bash 3.2.
TARGETS="arm64-v8a:aarch64-linux-android${API} \
armeabi-v7a:armv7a-linux-androideabi${API} \
x86_64:x86_64-linux-android${API}"

# $NDK last: ANDROID_NDK_HOME/ROOT are what the callers export (scripts/build_wbaes.sh,
# scripts/build_chacha20.sh both set ANDROID_NDK_HOME from their own --ndk/$NDK resolution), and
# this order matches scripts/fetch_omvll.sh - the other script that resolves an NDK for the SAME
# pinned plugin. Two scripts disagreeing about which variable wins is how the plugin ends up
# loaded into a clang it was not built against.
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-${NDK:-}}}"
if [[ -n "$NDK" ]]; then
    HOSTTAG="$(uname | tr '[:upper:]' '[:lower:]')-x86_64"
    BIN="$NDK/toolchains/llvm/prebuilt/$HOSTTAG/bin"
    CLANG="$BIN/clang"
    OBJCOPY="$BIN/llvm-objcopy"
    READELF="$BIN/llvm-readelf"
    # `|| true` is load-bearing, and this cost a round trip to find: `sed` exits non-zero when
    # source.properties is absent, `set -o pipefail` propagates that to the substitution, and
    # `set -e` then kills the script MID-ASSIGNMENT - before any of the diagnostics below can
    # print. The result was rc=1 with EMPTY stdout and stderr, which sopack/obfuscate.py reports
    # as three retried seeds and "last error: " with nothing after it. Every command
    # substitution in this file that can legitimately fail needs the same treatment; the ERR
    # trap below is the backstop for the ones nobody predicted.
    NDK_REV="$(sed -n 's/^Pkg\.Revision *= *//p' "$NDK/source.properties" 2>/dev/null | head -1 || true)"
    # Name the NDK, the host tag AND which variable supplied the path. Without this the failure
    # is bash's bare "No such file or directory" on a clang nobody asked for, which says nothing
    # about the environment variable that chose it. Resolved here rather than inside the first
    # guard that needs it, because the ld.lld guard below names it too and a second copy of this
    # precedence rule is a second place for it to drift out of step with the $NDK assignment
    # above. An if/elif chain rather than the `[[ ... ]] && WHICH_VAR=...` pair it replaced: that
    # form is safe under `set -e` (a failed test on the left of `&&` is exempt) but it states the
    # order twice, once negated, and this now runs on every build rather than only on the way to
    # an exit.
    if [[ -n "${ANDROID_NDK_HOME:-}" ]]; then
        WHICH_VAR="\$ANDROID_NDK_HOME"
    elif [[ -n "${ANDROID_NDK_ROOT:-}" ]]; then
        WHICH_VAR="\$ANDROID_NDK_ROOT"
    else
        WHICH_VAR="\$NDK"
    fi
    if [[ ! -x "$CLANG" ]]; then
        echo "ERROR: no clang at $CLANG
       That path came from $WHICH_VAR=$NDK (host tag $HOSTTAG, Pkg.Revision ${NDK_REV:-unknown}).
       NDKs are per-host and not interchangeable: a macOS NDK has only prebuilt/darwin-x86_64
       and a Linux one only prebuilt/linux-x86_64. Point $WHICH_VAR at an NDK for THIS host,
       or unset it to build with a plain LLVM on PATH." >&2
        exit 1
    fi
    echo "toolchain: NDK ($NDK, Pkg.Revision ${NDK_REV:-unknown})"
else
    # `|| true` on each: `set -e` kills the script on a failed assignment, so without it the
    # message below - the one that names what to install - was unreachable, and a host with no
    # toolchain at all got a silent exit 1.
    CLANG="$(command -v clang || true)"
    OBJCOPY="$(command -v llvm-objcopy || true)"
    READELF="$(command -v llvm-readelf || true)"
    if [[ -z "$CLANG" || -z "$OBJCOPY" || -z "$READELF" ]]; then
        echo "ERROR: need either ANDROID_NDK_HOME or clang+llvm-objcopy+llvm-readelf on PATH" >&2
        exit 1
    fi
    echo "toolchain: plain LLVM ($CLANG)"
fi

# Logging is OFF by default, and that is a HARDENING decision, not a convenience one.
# A logging build carries all 14 staged messages, "/dev/socket/logdw" and the obfuscated tag in
# every packed library - including the self-describing "H:native .text decrypted OK". They used
# to ship unconditionally, gated only at runtime; `strings` does not care about runtime gates.
# Building without them also shrinks the arm64 blob from 6713 to ~2256 bytes, i.e. two thirds
# less injected code to reverse. See docs/technical/STATIC-ANALYSIS-REVIEW.md S7.
#
# `logging.stub-log: true` needs a stub built WITH this flag; the JSON sidecar records which
# kind each blob is so the packer can refuse the mismatch instead of silently ignoring it.
CFLAGS=(
    -Os -fPIC -fno-plt -ffreestanding -nostdlib
    -fvisibility=hidden -fno-stack-protector -fno-jump-tables
    -fno-asynchronous-unwind-tables -fno-unwind-tables
    -fno-builtin -fomit-frame-pointer -std=c11 -Wall -Wextra
)
[[ "$WITH_LOG" -eq 1 ]] && CFLAGS+=(-DSOPK_STUB_LOG)
LDFLAGS=(
    -nostdlib -static -fuse-ld=lld -Wl,--build-id=none -Wl,-e,sopk_entry
    -Wl,--no-dynamic-linker -Wl,--gc-sections
    -Wl,-T,"$HERE/stub.ld"
)

# ---- optional O-MVLL obfuscation (opt-in, per-pack polymorphism) --------------------------
# Set OMVLL_PLUGIN to compile the stub through the O-MVLL pass-plugin. Only the guard-safe pass
# set is enabled by stub/omvll_config.py; the no-reloc / no-undef / no-adrp guards below still
# gate every build, and they are what makes this safe to enable at all.
#
# SOPK_SEED makes the obfuscation shape per-build. That is the point: without it the stub is
# byte-identical in every packed app, so its whitening key is a precomputable constant and an
# analyst needs no reverse engineering at all to write a universal unpacker
# (docs/technical/STATIC-ANALYSIS-REVIEW.md S2). With it, two packs of the same library differ
# in most of their stub bytes and there is no cross-app shortcut.
OMVLL_FLAGS=()
if [[ -n "${OMVLL_PLUGIN:-}" ]]; then
    [[ -f "$OMVLL_PLUGIN" ]] || { echo "ERROR: OMVLL_PLUGIN=$OMVLL_PLUGIN not found" >&2; exit 1; }
    export OMVLL_CONFIG="${OMVLL_CONFIG:-$HERE/omvll_config.py}"
    [[ -f "$OMVLL_CONFIG" ]] || { echo "ERROR: OMVLL_CONFIG=$OMVLL_CONFIG not found - without a
       config the plugin loads but applies NO passes, i.e. an unobfuscated build that looks
       obfuscated." >&2; exit 1; }
    # Does THIS clang even know the flag? A pass-plugin only loads into the clang it was built
    # against, and the vendored plugin is pinned to NDK r29 (scripts/fetch_omvll.sh names it
    # omvll_ndk_r29.*), so a stale ANDROID_NDK_HOME - or Apple clang from PATH - fails with
    # "unknown argument: '-fpass-plugin=…'" plus "invalid linker name in argument '-fuse-ld=lld'"
    # for every ABI and every retried seed. Probed here, once, because the caller that hits this
    # is sopack/obfuscate.py: it retries three seeds and reports only the LAST clang error, which
    # names neither the compiler nor the NDK that produced it.
    # A clang that knows the flag complains about the missing library instead, so "unknown
    # argument" is the discriminator; -fsyntax-only keeps the probe from needing a target or a
    # sysroot, and does not load the plugin.
    # Captured into a variable rather than piped into grep on purpose: under `set -o pipefail`
    # the pipeline reports the PROBE's non-zero exit, not grep's match, so the `if` never fires
    # and the check silently passes on exactly the toolchain it exists to reject.
    PROBE_OUT="$("$CLANG" -fsyntax-only -fpass-plugin=/nonexistent -x c /dev/null 2>&1 || true)"
    if [[ "$PROBE_OUT" == *"unknown argument"* ]]; then
        echo "ERROR: $CLANG does not support -fpass-plugin, so it cannot load the O-MVLL plugin.
       clang: $("$CLANG" --version 2>&1 | head -1)
       plugin: $OMVLL_PLUGIN (pinned to NDK r29 - a plugin loads only into the clang it was
       built against, so the NDK pin and the O-MVLL pin move together).
       -fpass-plugin needs clang 13+, i.e. NDK r26+. This is the toolchain selected above:
       point ANDROID_NDK_HOME at the r29 NDK (scripts/build_wbaes.sh --ndk PATH exports it for
       the whole run), or unset OMVLL_PLUGIN to build an UNOBFUSCATED stub - which is
       byte-identical in every app, so its whitening key is a public constant." >&2
        exit 1
    fi
    # A capable clang from the WRONG NDK gets as far as "unable to load plugin", which names the
    # plugin but not the version to install. The plugin filename encodes the NDK it was built
    # against (fetch_omvll.sh: omvll_ndk_r29.*), so compare the two and say it up front.
    # A WARNING, not a gate: only Google's own major is encoded either side, so this cannot tell
    # a genuinely compatible pair from a mismatched one - and refusing a setup that works is
    # worse than a line of output on one that does not.
    PLUGIN_NDK="$(basename "$OMVLL_PLUGIN" | sed -n 's/.*_r\([0-9]\{1,\}\).*/\1/p')"
    if [[ -n "$PLUGIN_NDK" && -n "${NDK_REV:-}" && "${NDK_REV%%.*}" != "$PLUGIN_NDK" ]]; then
        echo "WARNING: the O-MVLL plugin is built for NDK r$PLUGIN_NDK, but this NDK is
       Pkg.Revision $NDK_REV. An LLVM pass-plugin loads only into the clang it was built
       against, so expect 'unable to load plugin' below. Install NDK r$PLUGIN_NDK." >&2
    fi
    OMVLL_FLAGS=(-fpass-plugin="$OMVLL_PLUGIN")
    echo "obfuscation: O-MVLL ($OMVLL_PLUGIN)  config=$OMVLL_CONFIG  seed=${SOPK_SEED:-<none>}"
fi

# LDFLAGS ask for lld unconditionally, and a driver with no ld.lld beside it fails with
# "invalid linker name in argument '-fuse-ld=lld'" - the second half of the stale-NDK signature
# above, and a pre-r18 NDK / Apple clang tell on its own. Say so before the first compile.
#
# THE CHECK IS BRANCH-SPECIFIC, and that is the whole point of it. It used to be a single test
# that accepted an ld.lld from $PATH whichever branch chose the compiler, which made it a no-op
# on any host with the distro `lld` package installed - including docker/'s own builder image
# (Dockerfile installs `clang lld`, so /usr/bin/ld.lld is always there). A stale or broken NDK
# then sailed past the guard and died much later as "missing symbols in arm64-v8a", naming
# neither the linker nor the NDK. For an NDK the linker must be the NDK's own: a host lld is
# outside the pinned toolchain. `-x` rather than `--version` because the question is presence,
# not whether this host can execute that particular binary.
if [[ -n "$NDK" ]]; then
    if [[ ! -x "$BIN/ld.lld" ]]; then
        echo "ERROR: no ld.lld beside $CLANG, but the stub links with -fuse-ld=lld.
       The stub is freestanding and linked with a custom script ($HERE/stub.ld); lld is not
       optional here. An NDK r18+ bundles ld.lld in the same bin/ as clang - if this is an NDK,
       it is too old (or $WHICH_VAR=$NDK points at something else). An ld.lld on PATH is
       deliberately NOT accepted here: it is outside the NDK this build is pinned to. Unset
       $WHICH_VAR to build with a plain LLVM on PATH instead." >&2
        exit 1
    fi
elif ! "$(dirname "$CLANG")/ld.lld" --version >/dev/null 2>&1 && ! command -v ld.lld >/dev/null; then
    echo "ERROR: no ld.lld beside $CLANG (nor on PATH), but the stub links with -fuse-ld=lld.
       The stub is freestanding and linked with a custom script ($HERE/stub.ld); lld is not
       optional here. Install the LLVM linker (the 'lld' package) beside the clang above." >&2
    exit 1
fi

sym_off() {  # sym_off <elf> <name> -> hex offset (== vaddr, image based at 0)
    "$READELF" -sW "$1" | awk -v n="$2" '$8==n {print "0x"$2; exit}'
}

for PAIR in $TARGETS; do
    ABI="${PAIR%%:*}"
    TRIPLE="${PAIR#*:}"
    echo "== building stub for $ABI ($TRIPLE) =="
    ELF="$OUT/stub_${ABI}.elf"
    BLOB="$OUT/stub_${ABI}.bin"
    META="$OUT/stub_${ABI}.json"

    # arm64: force -mcmodel=tiny so the compiler emits `adr` (byte PC-relative) instead
    # of `adrp+add` (page PC-relative). `adrp` is only correct when the blob loads at a
    # page-aligned virtual address; some LIEF versions place the injected segment at a
    # non-page-aligned vaddr, which breaks `adrp` addressing to g_decinfo. `adr` works at
    # any alignment. (x86_64 RIP-relative and armv7 literal pools are already byte-relative.)
    EXTRA=""
    if [ "$ABI" = "arm64-v8a" ]; then EXTRA="-mcmodel=tiny"; fi

    # O-MVLL is applied to arm64-v8a ONLY. It supports AArch64/AArch32 but not x86_64, and the
    # full pass set exhausts AArch32's smaller register file in the freestanding stub ("ran out
    # of registers"); armv7 would need a lighter, 32-bit-specific set. arm64 is also the only
    # ABI protected in practice, so this is where it matters.
    # `${arr[@]+"${arr[@]}"}` and not `"${arr[@]}"`: expanding an EMPTY array under `set -u` is
    # an "unbound variable" error in bash < 4.4, and macOS ships /bin/bash 3.2 - which this file
    # supports by design (see the header). THIS_OMVLL is empty for armeabi-v7a and x86_64, so a
    # Mac died with `THIS_OMVLL[@]: unbound variable` on the SECOND ABI, after arm64 had already
    # built and printed its size. Linux/bash 5 cannot reproduce it, so the lint in
    # tests/test_obfuscate.py is what keeps this from coming back.
    # The `-n "$OMVLL_PLUGIN"` test replaced `${#OMVLL_FLAGS[@]} -gt 0` for the same reason: no
    # expansion of a possibly-empty array, not even for its length.
    THIS_OMVLL=()
    if [[ -n "${OMVLL_PLUGIN:-}" && "$ABI" == "arm64-v8a" ]]; then
        THIS_OMVLL=(${OMVLL_FLAGS[@]+"${OMVLL_FLAGS[@]}"})
    fi

    "$CLANG" --target="$TRIPLE" $EXTRA ${THIS_OMVLL[@]+"${THIS_OMVLL[@]}"} \
        "${CFLAGS[@]}" "${LDFLAGS[@]}" -I"$HERE" "$HERE/stub.c" -o "$ELF"

    # Hard requirement: no dynamic relocations and no undefined symbols, or the blob
    # is not self-contained and will crash when injected.
    if "$READELF" -rW "$ELF" | grep -qiE 'R_(AARCH64|ARM|X86_64)_'; then
        echo "ERROR: $ABI stub has relocations (not position-independent enough):" >&2
        "$READELF" -rW "$ELF" >&2
        exit 1
    fi
    if "$READELF" -sW "$ELF" | awk '$7=="UND" && $8!="" {found=1} END{exit !found}'; then
        echo "ERROR: $ABI stub references undefined (external) symbols:" >&2
        "$READELF" -sW "$ELF" | awk '$7=="UND" && $8!=""' >&2
        exit 1
    fi
    # arm64: the blob MUST use adr (byte PC-relative), never adrp (page PC-relative),
    # or it breaks when a LIEF version places the injected segment at a non-page-aligned
    # virtual address. -mcmodel=tiny guarantees adr; assert it here.
    if [ "$ABI" = "arm64-v8a" ]; then
        OBJDUMP="$(dirname "$READELF")/llvm-objdump"
        if "$OBJDUMP" -d "$ELF" | grep -qw adrp; then
            echo "ERROR: $ABI stub uses adrp (page-relative) - must build with -mcmodel=tiny" >&2
            exit 1
        fi
    fi

    # `|| true`: sym_off pipes readelf into awk, so a readelf failure would kill the script here
    # through pipefail instead of reaching the "missing symbols" message one line down.
    ENTRY_OFF="$(sym_off "$ELF" sopk_entry || true)"
    INFO_OFF="$(sym_off "$ELF" g_decinfo || true)"
    [[ -n "$ENTRY_OFF" && -n "$INFO_OFF" ]] || { echo "ERROR: missing symbols in $ABI" >&2; exit 1; }

    "$OBJCOPY" -O binary "$ELF" "$BLOB"
    SIZE="$(wc -c < "$BLOB")"

    cat > "$META" <<EOF
{
  "abi": "$ABI",
  "triple": "$TRIPLE",
  "api": $API,
  "size": $SIZE,
  "entry_off": $((ENTRY_OFF)),
  "decinfo_off": $((INFO_OFF)),
  "log": $([[ "$WITH_LOG" -eq 1 ]] && echo true || echo false)
}
EOF
    echo "   -> $BLOB ($SIZE bytes)  entry=+$((ENTRY_OFF))  decinfo=+$((INFO_OFF))"
    rm -f "$ELF"
done

echo "All stubs built into $OUT"
