#!/usr/bin/env bash
#
# docker-entrypoint.sh - generate the Linux/x86_64 portable pack bundle inside the builder image.
#
# Thin on purpose. Every gate that matters lives in scripts/artifact_generation.sh and
# scripts/build_wbaes.sh, and duplicating any of them here would give two places to keep in
# step. This does three things the image needs and the scripts should not know about:
#   1. seed the bind-mounted submodule from the deps baked into the image, so a run is offline;
#   2. install sopack into the container's python (the bundler imports it);
#   3. run the bundler into /out, then print the receipts worth reading in CI output.
#
# Arguments are passed straight through to artifact_generation.sh, so:
#   docker run ... sopack-bundler --abi arm64-v8a --api 24 --tar
set -euo pipefail

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

SOPACK=/workspace
# The bundle goes in a SUBDIRECTORY of the mount, not the mount itself, because
# artifact_generation.sh writes its --tar archive BESIDE --out (an archive created inside the
# directory it is archiving would self-include). With --out /out that "beside" is /, i.e. inside
# the container, and the tarball would be lost when it exits.
OUTROOT=/out
OUT="$OUTROOT/bundle"
WBC="$SOPACK/third_party/whitebox-cryptography"

[ -f "$SOPACK/pyproject.toml" ] || die "no sopack checkout bind-mounted at $SOPACK.
       Run with: -v \"\$PWD:/workspace\" -v \"\$PWD/out:/out\""
[ -d "$OUTROOT" ] || die "no output directory bind-mounted at $OUTROOT.
       Run with: -v \"\$PWD/out:/out\"   (so the bundle survives the container)"

# HOME. Docker hands a `--user $(id -u):$(id -g)` uid with no /etc/passwd entry HOME=/, and that
# degenerate value is not cosmetic - it breaks two things, one loudly and one in silence:
#   * the submodule's archive gate greps libwbcrypto.a for "${ROOT}|${HOME}|/Users/|/home/", so
#     HOME=/ collapses the ${HOME} alternative to a bare "/" and EVERY line holding a slash reads
#     as a leaked host path - ar member headers (/0, /1022), the long-name table (//), binary
#     noise. A clean, DWARF-free archive then die()s as "embeds host paths - -g0/-ffile-prefix-map
#     did not take effect", naming the one thing that is not wrong, and the run stops before the
#     DWARF check, the wbc_blob_kdf_tier symbol check and the copy into vendor/wbc/.
#   * sopack's host log defaults to ~/.sopack/logs, i.e. /.sopack/logs, which a non-root uid
#     cannot create - and log failures are deliberately swallowed (warn once, keep packing), so
#     the run records just never appear.
# Point it somewhere writable, for the same reason the venv lives under /tmp. A caller who
# exports a usable HOME keeps it. Export SOPACK_LOG_DIR (it outranks the config) if the run log
# should survive the container.
if [ -z "${HOME:-}" ] || [ "$HOME" = "/" ] || [ ! -w "$HOME" ]; then
    export HOME=/tmp/sopack-home
fi
mkdir -p "$HOME" 2>/dev/null || true
[ -n "$HOME" ] && [ "$HOME" != "/" ] && [ -d "$HOME" ] && [ -w "$HOME" ] \
    || die "HOME=$HOME is empty, / or not writable. Leave HOME unset (this script then uses
       /tmp/sopack-home) or point it at a writable directory: the submodule's host-path gate
       greps libwbcrypto.a for \$HOME, and a degenerate value matches every path-like string
       in it, failing a perfectly clean archive."

# The bundle lands in /out, but the BUILD writes into the mounted checkout: vendor/wbc/,
# sopack/stubs/*.so and the submodule's build-host/ + build-android/. All are gitignored and
# regenerable, so this is safe - except that they are per-host, and replacing a Mac's copies
# with Linux ones means the Mac must re-run build_wbaes.sh before it can pack again. Say so
# when that is about to happen rather than after.
if [ -f "$SOPACK/vendor/wbc/bin/wb_keygen" ] \
   && [ "$(head -c4 "$SOPACK/vendor/wbc/bin/wb_keygen" | od -An -tx1 | tr -d ' \n')" != "7f454c46" ]; then
    printf 'WARN: %s\n' "the mounted checkout carries a NON-ELF vendor/wbc/bin/wb_keygen - it was
      built on macOS. This run replaces it, plus sopack/stubs/*.so and the submodule's
      build-host/, with Linux builds. Nothing is lost that ./scripts/build_wbaes.sh cannot
      rebuild, but that Mac will have to re-run it. Use a separate clone to avoid the churn." >&2
fi

# 1. The submodule. A bind-mounted checkout may have it uninitialised, and the image cannot
#    pre-populate a path that the mount masks - hence the staging copy at /opt/wbc-deps.
say "preparing the whitebox-cryptography submodule"
if [ ! -f "$WBC/include/wbcrypto.h" ]; then
    git -C "$SOPACK" submodule update --init third_party/whitebox-cryptography \
        || die "could not initialise the submodule (needs network unless it is already checked
       out on the host side of the mount)"
fi
# Seed the vendored deps from the image rather than re-downloading them. An existing tree always
# wins: a host that already fetched them, or a dev who deliberately swapped one in, must not be
# overwritten. /opt/wbc-deps is empty when the image could not pre-warm (see the Dockerfile) - in
# that case fall through to fetching, which is the same thing the pre-warm would have done.
mkdir -p "$WBC/third_party"
# Only libsodium now. O-MVLL and its CPython stdlib are sopack's (see below) and no longer get
# copied into the submodule at all - that copying was the old inside-out arrangement, where
# sopack downloaded the plugin and then wrote it into WBC's tree so WBC could "find" it.
for d in libsodium; do
    if [ ! -e "$WBC/third_party/$d" ] && [ -e "/opt/wbc-deps/$d" ]; then
        cp -a "/opt/wbc-deps/$d" "$WBC/third_party/$d"
        printf '    seeded third_party/%s from the image\n' "$d"
    fi
done
# The plugin is only needed for an obfuscated build, so honour the escape hatch: with
# --allow-unobfuscated-provider there is nothing to fetch and nothing to insist on. libsodium is
# needed either way, hence the separate fetch.
WANT_OMVLL=1
for a in "$@"; do
    [ "$a" = "--allow-unobfuscated-provider" ] && WANT_OMVLL=0
done

# libsodium is needed either way; O-MVLL only for an obfuscated build, hence the split.
if [ ! -e "$WBC/third_party/libsodium" ]; then
    printf '    no libsodium yet - fetching (needs network, once)\n'
    ( cd "$WBC" && ./third_party/fetch_deps.sh libsodium ) || die "fetch_deps.sh libsodium failed"
fi

# O-MVLL is sopack's now, and the image baked it at $SOPACK_OMVLL_DIR. Seed the checkout's own
# third_party/omvll from that rather than downloading again - the bind-mounted checkout starts
# empty there because the directory is gitignored.
if [ "$WANT_OMVLL" -eq 1 ]; then
    OMVLL_SRC="${SOPACK_OMVLL_DIR:-/opt/omvll}"
    OMVLL_DST="$SOPACK/third_party/omvll"
    if [ ! -f "$OMVLL_DST/omvll_ndk_r29.so" ]; then
        if [ -f "$OMVLL_SRC/omvll_ndk_r29.so" ]; then
            mkdir -p "$OMVLL_DST"
            cp -a "$OMVLL_SRC/." "$OMVLL_DST/"
            printf '    seeded third_party/omvll from the image (no network needed)\n'
        else
            printf '    no O-MVLL plugin baked in - fetching (needs network, once)\n'
            "$SOPACK/scripts/fetch_omvll.sh" \
                || die "scripts/fetch_omvll.sh failed. If this container has no network, rebuild
       the image so the plugin is baked in, or pass --allow-unobfuscated-provider."
        fi
    fi
else
    printf '    --allow-unobfuscated-provider: skipping the O-MVLL plugin entirely\n'
fi

# 2. sopack itself, into a venv under /tmp rather than the system python.
#    /tmp because this container is meant to run as `--user $(id -u):$(id -g)` so the bundle it
#    writes to /out is not root-owned - and a non-root uid cannot write to
#    /usr/lib/python3/dist-packages. The failure would be a bare permission error naming neither
#    Docker nor sopack.
#    --system-site-packages so lief, pyyaml and pytest come from the image (all three are baked
#    into the Dockerfile's pip layer) instead of being re-fetched; only sopack is installed here.
#    This is why every sopack dependency has to be in that layer: the `pip install -e` below
#    resolves them, so one that is missing sends it to PyPI and an offline run dies right there.
#    Editable, so the bundler reads the mounted checkout - which is the whole point of mounting it.
#    Putting the venv first on PATH is what makes this reach the scripts: build_wbaes.sh and
#    artifact_generation.sh both invoke plain `python3`/`python3 -m pip`.
say "installing sopack (editable) into a venv"
VENV=/tmp/sopack-venv
python3 -m venv --system-site-packages "$VENV" || die "python3 -m venv failed"
export PATH="$VENV/bin:$PATH"
#    --no-build-isolation because PEP 517 build isolation is a NETWORK CALL that the pre-staged
#    dependency layer does not cover. pip builds sopack's wheel in a fresh throwaway env and
#    resolves pyproject.toml's `[build-system] requires = ["setuptools>=68"]` from PyPI *there*,
#    ignoring the setuptools already installed system-wide - so the layer that exists to make
#    this offline is bypassed by the one install it was built for. On a slow or absent link that
#    is a multi-minute ReadTimeoutError against files.pythonhosted.org, ~2.5 GB of NDK layers
#    into the run, surfacing as "pip install -e /workspace failed" with pip insisting it is "not
#    a problem with pip". The image's pip layer carries setuptools>=68 and wheel precisely so the
#    local backend can do this build, and --system-site-packages is what makes them visible here.
#    artifact_generation.sh tries an isolated wheel build first and falls back, because it cannot
#    assume a baked-in layer; this script can, so it goes straight to the local backend.
python3 -c 'import setuptools' 2>/dev/null \
    || die "setuptools is not importable in $VENV, so the --no-build-isolation install below has
       no build backend. It comes from the image's system pip layer (docker/Dockerfile) via
       --system-site-packages - rebuild the image. Do not drop the flag to work around this: that
       turns every run into a PyPI download and re-breaks the offline path."
"$VENV/bin/pip" install --quiet --no-cache-dir --no-build-isolation -e "$SOPACK" \
    || die "pip install -e $SOPACK failed"
python3 -c 'import sopack, lief, yaml' \
    || die "sopack/lief/pyyaml not importable from $VENV after install"

# 3. Generate. --out is under the mount and never $SOPACK/artifacts: artifact_generation.sh does
#    `rm -rf` on its --out, and a checkout mounted from a Mac usually has a working bundle there.
say "generating the bundle"
cd "$SOPACK"
./scripts/artifact_generation.sh --out "$OUT" "$@"

# ---- receipts ----------------------------------------------------------------------------
# The bundler's own gates already passed by here; these are the two facts a reader of the build
# log most wants to confirm at a glance, and both are invisible in a green exit code.
say "receipts"
if [ -f "$OUT/bin/wb_keygen" ]; then
    printf '    wb_keygen: %s\n' "$(file -b "$OUT/bin/wb_keygen")"
    if readelf -d "$OUT/bin/wb_keygen" 2>/dev/null | grep -q NEEDED; then
        die "bin/wb_keygen is dynamically linked - it would carry a glibc floor to the target.
       gate 4 should have caught this; do not ship this bundle."
    fi
    printf '    wb_keygen linkage: static (no DT_NEEDED)\n'
fi
grep -E '^(host-os|host-arch|abi|provider-obfuscation|wb-keygen-linkage|wbc-rev)' \
    "$OUT/MANIFEST.txt" | sed 's/^/    /'

cat <<EOF

==> Done. On the host: the bundle is ./out/bundle/, and --tar puts the archive beside it in
    ./out/. To use it on the target machine:

      mkdir -p ~/sopack-bundle
      tar xzf out/sopack-bundle-*.tar.gz -C ~/sopack-bundle   # if you passed --tar
      ~/sopack-bundle/install.sh
      ~/sopack-bundle/venv/bin/sopack pack <your.apk> -o packed.apk

    That machine needs python3 (>= 3.9) WITH venv, a JDK, apksigner, and network once for pip
    to fetch lief. See the bundle's README.md.
EOF
