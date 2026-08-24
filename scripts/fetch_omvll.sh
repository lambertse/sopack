#!/usr/bin/env bash
#
# fetch_omvll.sh - vendor the O-MVLL pass-plugin (and its CPython stdlib) into
#   third_party/omvll/. sopack owns this pin; see "Why here" below.
#
# USAGE
#   ./scripts/fetch_omvll.sh [--force] [--dir D]
#
#   --force   re-download even if the per-host stamp says it is vendored
#   --dir D   vendor somewhere other than <repo>/third_party/omvll
#   --print-plugin / --print-pythonpath
#             print the path and exit 0 if present, exit 1 if not. For callers
#             that want the paths without triggering a download.
#
# WHY HERE, AND NOT IN THE WBC SUBMODULE
#   An LLVM pass-plugin only loads into the clang it was built against, so the
#   O-MVLL pin and the NDK pin move together - and sopack owns the NDK pin
#   (docker/Dockerfile). One repo owning half of a coupled pair is how the two
#   drift apart. WBC keeps a fetch of its own as a standalone-dev fallback, and
#   its version MAY LAG this one; build_wbaes.sh warns when they disagree.
#
#   WBC also keeps its own omvll_config.py, which is POLICY, not tooling: it
#   names WBC's translation units and would match nothing of ours. sopack's own
#   policies live in stub/, beside the sources they name - stub/omvll_config_wb.py
#   for the wbaes skeletons, stub/omvll_config.py for the freestanding stub. This
#   directory holds only FETCHED artifacts and is entirely gitignored.
#
# ONE TARBALL, TWO OUTPUTS
#   The upstream release carries the plugin AND a matching CPython 3.10.7 stdlib.
#   The plugin embeds a CPython VM and aborts with "failed to get the Python
#   codec of the filesystem encoding" without a 3.10 stdlib at OMVLL_PYTHONPATH.
#   They are version-locked by construction, so they are fetched as ONE unit and
#   must never be pinned separately.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOPACK="$(cd "$HERE/.." && pwd)"
# shellcheck source=scripts/_common.sh
. "$HERE/_common.sh"

DEST="$SOPACK/third_party/omvll"
FORCE=0
PRINT=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)             FORCE=1; shift ;;
        --dir)               DEST="$2"; shift 2 ;;
        --print-plugin)      PRINT="plugin"; shift ;;
        --print-pythonpath)  PRINT="pythonpath"; shift ;;
        # Self-maintaining: everything from line 2 up to (not including) `set -euo pipefail`.
        # A hardcoded range silently truncates the help, or starts printing shell code, the
        # first time the header grows - which is exactly what the other scripts here do.
        -h|--help)           sed -n '2,/^set -euo pipefail/p' "$0" | sed '$d'; exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
done

# ---- the pin ------------------------------------------------------------------------------
# Copied from the WBC submodule's third_party/fetch_deps.sh rather than shared, because that
# copy is now the standalone fallback and this one is authoritative. THE PIN IS THEREFORE
# DUPLICATED ACROSS TWO REPOS - a real cost of keeping WBC buildable alone. build_wbaes.sh
# greps the submodule's constants and warns on divergence, which is the only thing that turns
# a silent skew into a visible one.
#
# The NDK pin moves with this. docker/Dockerfile pins NDK r29 for exactly this reason.
OMVLL_VERSION="1.9.1"
OMVLL_MACOS_SHA256="0471e049b21e7ada4b52bb15bb4bc7d0be67ae385417d9cd78c27e48718470de"
OMVLL_MACOS_URL="https://github.com/open-obfuscator/o-mvll/releases/download/1.9.1/omvll_v1-9-1_macos_2026-07-08T15_08_58.tar.gz"
OMVLL_LINUX_SHA256="f1f8f88812e173ea44d74372502c4a09600810de3254dbae1f82599bfc339aa0"
OMVLL_LINUX_URL="https://github.com/open-obfuscator/o-mvll/releases/download/1.9.1/omvll_v1-9-1_linux_2026-07-06T09_44_15.tar.gz"

# omvll_plugin_path - the ONE place the per-host filename is decided, within this repo.
# macOS clang dlopens a Mach-O dylib, Linux an ELF .so; they are not interchangeable.
omvll_plugin_path() {
    case "$(uname -s)" in
        Darwin) echo "$DEST/omvll_ndk_r29.dylib" ;;
        Linux)  echo "$DEST/omvll_ndk_r29.so" ;;
        *)      echo "$DEST/omvll_ndk_r29.unsupported" ;;
    esac
}
omvll_pythonpath() { echo "$DEST/python/Lib"; }

PLUGIN="$(omvll_plugin_path)"
PYLIB="$(omvll_pythonpath)"

if [ -n "$PRINT" ]; then
    case "$PRINT" in
        plugin)     [ -f "$PLUGIN" ] && { echo "$PLUGIN"; exit 0; }; exit 1 ;;
        pythonpath) [ -d "$PYLIB" ]  && { echo "$PYLIB";  exit 0; }; exit 1 ;;
    esac
fi

# Per-host stamp. A checkout shared between a macOS working copy and a Linux container (the
# submodule bind-mount case) otherwise has one host's plugin plus a valid stamp, and reports
# "already vendored" while the file THIS host needs is absent. Keying the stamp to the host
# makes that self-correcting. ANDed with the binary, so deleting the file re-fetches.
STAMP="$DEST/.vendored-ok-$(uname -s)"

case "$(uname -s)" in
    Darwin) URL="$OMVLL_MACOS_URL"; SHA="$OMVLL_MACOS_SHA256"; MEMBER="omvll-ndk.dylib" ;;
    Linux)  URL="$OMVLL_LINUX_URL"; SHA="$OMVLL_LINUX_SHA256"; MEMBER="omvll-ndk.so" ;;
    *) die "upstream publishes no O-MVLL $OMVLL_VERSION release for $(uname -s).
       Build with cipher chacha20, or with --no-omvll / --allow-unobfuscated-provider." ;;
esac

if [ "$(uname -s)" = "Linux" ] && [ "$(uname -m)" != "x86_64" ]; then
    die "the O-MVLL Linux plugin is x86_64-only and this host is $(uname -m).
       Google also publishes no linux-aarch64 NDK, so this host cannot cross-build the
       skeletons at all. Use docker/ (linux/amd64), or an x86_64 host."
fi

if [ "$FORCE" -eq 0 ] && [ -f "$STAMP" ] && [ -f "$PLUGIN" ] && [ -f "$PYLIB/abc.py" ]; then
    ok "O-MVLL $OMVLL_VERSION already vendored at $PLUGIN"
    exit 0
fi

need curl "downloading the O-MVLL plugin"
need tar  "unpacking the O-MVLL release tarball"

mkdir -p "$DEST"
TARBALL="$DEST/omvll-v${OMVLL_VERSION}.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" "$TARBALL"' EXIT

say "downloading O-MVLL $OMVLL_VERSION ($(uname -s)) - ~65-95 MB, once"
curl -sSL -o "$TARBALL" "$URL" || die "download failed: $URL"
info "verifying SHA256 ..."
verify_sha256 "$TARBALL" "$SHA" "the O-MVLL $OMVLL_VERSION tarball"

info "extracting ..."
tar -xzf "$TARBALL" -C "$TMP"

# Name the tarball's ACTUAL contents on a miss. Upstream renaming a member is the realistic
# breakage here, and a bare "not found" sends you to read this script instead of the listing
# that answers the question.
FOUND="$(find "$TMP" -name "$MEMBER" -print -quit)"
[ -n "$FOUND" ] || {
    printf 'ERROR: %s not found in the O-MVLL tarball. It contains:\n' "$MEMBER" >&2
    ( cd "$TMP" && find . -maxdepth 2 -name 'omvll*' -o -maxdepth 1 -type f ) >&2
    exit 1
}
cp "$FOUND" "$PLUGIN"
chmod +x "$PLUGIN"

# The stdlib out of the SAME tarball - version-locked to the plugin above. Never a second
# download from python.org: that would be a separately-drifting pin for one dependency.
PYSRC="$(find "$TMP" -maxdepth 2 -type d -name 'Python-*' -print -quit)"
[ -n "$PYSRC" ] && [ -f "$PYSRC/Lib/abc.py" ] || {
    printf 'ERROR: no CPython stdlib (Python-*/Lib/abc.py) in the O-MVLL tarball. It contains:\n' >&2
    ( cd "$TMP" && find . -maxdepth 2 -type d ) >&2
    exit 1
}
info "installing the bundled $(basename "$PYSRC") stdlib"
rm -rf "$DEST/python"; mkdir -p "$DEST/python"
cp -a "$PYSRC/Lib" "$DEST/python/Lib"

# Stamp LAST, and only after asserting the tree is real rather than merely present. A stamped
# but incomplete tree sails through the short-circuit above and fails much later, inside the
# plugin, as "failed to get the Python codec of the filesystem encoding".
[ -f "$PYLIB/abc.py" ] || die "installed the stdlib but $PYLIB/abc.py is missing"
touch "$STAMP"

ok "O-MVLL $OMVLL_VERSION vendored"
info "plugin:     $PLUGIN"
info "pythonpath: $PYLIB"
