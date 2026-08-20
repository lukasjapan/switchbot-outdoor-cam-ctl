#!/usr/bin/env bash
# Container entrypoint: wire up the mounted content, then run the aarch64 binary
# under qemu-user. Replaces camctl's run.sh (which did the build on the host and
# assembled a copied sysroot before every run).
set -euo pipefail

BIN=switchbot-outdoor-cam-ctl
SYS=/sysroot
RUNDIR=/run/outdoor-cam-ctl

# ---------------------------------------------------------------- mount checks
# The sysroot is all symlinks into these mounts, so a missing mount shows up as a
# confusing "library not found" from the guest linker. Fail with the real reason.
if [ ! -d /ext/xapk/lib/arm64-v8a ]; then
    echo "error: /ext/xapk/lib/arm64-v8a not found." >&2
    echo "       Is ./switchbot-9.11.15.13-xapk populated and mounted? It needs the" >&2
    echo "       native libs from the bundle's config.arm64_v8a split — a base APK" >&2
    echo "       alone carries no lib/ directory at all." >&2
    exit 1
fi
for a in t_s.bmp t_cdc.tcfg; do
    [ -f "/ext/xapk/assets/$a" ] || {
        echo "error: /ext/xapk/assets/$a missing — libthing_security cannot derive its keys without it." >&2
        exit 1
    }
done

# ------------------------------------------------------------- NDK indirection
# The host tag (linux-x86_64) can't be globbed at image-build time, so the
# skeleton points the NDK-sourced libs at /run/ndk/lib and we resolve it here.
NDKLIB=$(echo /ext/ndk/toolchains/llvm/prebuilt/*/sysroot/usr/lib/aarch64-linux-android/24)
if [ ! -d "$NDKLIB" ]; then
    echo "error: no NDK sysroot under /ext/ndk — is ./android-ndk-r27d-linux mounted?" >&2
    echo "       expected .../toolchains/llvm/prebuilt/<host>/sysroot/usr/lib/aarch64-linux-android/24" >&2
    exit 1
fi
mkdir -p /run/ndk
ln -sfn "$NDKLIB" /run/ndk/lib

# ----------------------------------------------------------------- signer.der
# libthing_security hashes the app's signing certificate into its derived keys,
# so it has to be the real one. It is simply the cert inside the APK's PKCS#7
# signature block, so derive it from the mount instead of vendoring a copy.
mkdir -p "$RUNDIR"
if [ ! -s "$RUNDIR/signer.der" ]; then
    RSA=/ext/xapk/META-INF/BNDLTOOL.RSA
    TMPRSA=
    if [ ! -f "$RSA" ]; then
        # Not unpacked alongside the libs? Take it out of the base APK instead.
        for apk in /ext/xapk/com.theswitchbot.switchbot.apk /ext/xapk/*.apk; do
            [ -f "$apk" ] || continue
            TMPRSA=/tmp/BNDLTOOL.RSA
            unzip -p "$apk" 'META-INF/*.RSA' > "$TMPRSA" 2>/dev/null && [ -s "$TMPRSA" ] && { RSA="$TMPRSA"; break; }
            TMPRSA=
        done
    fi
    if [ -f "$RSA" ]; then
        openssl pkcs7 -inform DER -in "$RSA" -print_certs 2>/dev/null \
            | openssl x509 -outform DER -out "$RUNDIR/signer.der" 2>/dev/null || true
    fi
    [ -n "$TMPRSA" ] && rm -f "$TMPRSA"
    if [ -s "$RUNDIR/signer.der" ]; then
        # Routine startup step — only worth mentioning when tracing. Written as a
        # plain `if`: under `set -e`, a trailing `[ ... ] && echo` would make the
        # branch exit non-zero whenever VERBOSE is unset.
        if [ -n "${VERBOSE:-}" ]; then
            echo "signer.der: derived from the APK signature block ($(wc -c < "$RUNDIR/signer.der") bytes)" >&2
        fi
    else
        echo "warning: could not derive signer.der — derived keys will be wrong and cloud calls will fail." >&2
    fi
fi

# ------------------------------------------------------------------ run it
# qemu resolves the guest ELF's PT_INTERP (/system/bin/linker64) under -L, and
# the guest linker then dlopen()s the SDK from LD_LIBRARY_PATH.
QARGS=(-L "$SYS"
       -E LD_LIBRARY_PATH=/system/lib64
       -E HOME=/root
       -E ASSETS_DIR="$SYS/work/assets"
       -E OUTDOOR_CAM_SIGNER_DER="$SYS/work/signer.der"
       -E OUTDOOR_CAM_OUT_DIR=/hostcwd)

# Forward the knobs that are actually set: TZ/VERBOSE plus every OUTDOOR_CAM_*
# and TUYA_* override, so new ones need no change here.
#
# Skip the three we already set above, and OUTDOOR_CAM_HOME in particular: on the
# compose side that names a *host* directory to mount, and leaking it into the
# guest would send creds_dir() to a path that does not exist in the container.
# The credential cache is always /root/.switchbot-outdoor-cam-ctl in here.
for var in TZ VERBOSE ${!OUTDOOR_CAM_@} ${!TUYA_@}; do
    case "$var" in
        OUTDOOR_CAM_HOME|OUTDOOR_CAM_SIGNER_DER|OUTDOOR_CAM_OUT_DIR) continue ;;
    esac
    val="${!var:-}"
    if [ -n "$val" ]; then QARGS+=(-E "$var=$val"); fi
done

cd "$SYS/work"

if [ -n "${VERBOSE:-}" ]; then
    exec qemu-aarch64 "${QARGS[@]}" "./$BIN" "$@"
fi

# Quiet mode. Two kinds of chatter cannot be gated at the source:
#   - libThingP2PSDK logs through plain printf/fprintf, not the android log API,
#     so the liblog shim never sees it ("[uv_thread_create]…").
#   - bionic grumbles when the SDK joins a thread it never started, on teardown.
# Both are harmless and constant, so filter them out of stderr unless tracing.
# Only stderr goes through the filter; stdout is passed straight through, so
# `--out -` stays byte-exact. --line-buffered keeps progress output prompt.
NOISE='^\[uv_thread_create\]|^libc: invalid pthread_t \([0-9]+\) passed to pthread_join'
exec 3>&1
qemu-aarch64 "${QARGS[@]}" "./$BIN" "$@" 2>&1 1>&3 3>&- \
    | grep --line-buffered -Ev "$NOISE" >&2
rc=${PIPESTATUS[0]}
exec 3>&-
exit "$rc"
