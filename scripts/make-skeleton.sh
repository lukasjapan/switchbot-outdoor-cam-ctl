#!/usr/bin/env bash
# Lay down /sysroot as a tree of symlinks at image-build time.
#
# This replaces camctl's make-sysroot.sh, which copied ~40 binaries into a
# staging dir on every build. Here nothing is copied: each library is a symlink
# to wherever it actually lives — the read-only mounts (/ext/xapk, /ext/ndk) or
# the baked-in dirs (/opt/bionic, /opt/outdoor-cam-ctl).
#
# The mounts do not exist yet while the image is being built, so most of these
# symlinks are DANGLING here. That is intended: they resolve when the container
# runs with its mounts. qemu's `-L /sysroot` and the guest linker64 open absolute
# container paths, and the host kernel follows the symlinks out of /sysroot.
set -euo pipefail

SYS=/sysroot
BIN=switchbot-outdoor-cam-ctl

mkdir -p "$SYS/system/bin" "$SYS/system/lib64" "$SYS/system/etc" "$SYS/work/assets"

# --- bionic core, extracted from the Android runtime APEX (see extract-bionic.sh)
ln -sfn /opt/bionic/linker64 "$SYS/system/bin/linker64"
for so in libc.so libm.so libdl.so libdl_android.so; do
    ln -sfn "/opt/bionic/$so" "$SYS/system/lib64/$so"
done

# --- our own compiled shims
#  liblog.so    : bionic's real liblog wants logd on /dev/log, absent under qemu
#  libandroid.so: fakes AAssetManager_* so libthing_security can read its key
#                 material (t_s.bmp / t_cdc.tcfg) off the filesystem
for so in liblog.so libandroid.so; do
    ln -sfn "/opt/outdoor-cam-ctl/$so" "$SYS/system/lib64/$so"
done

# --- the camera chain, straight out of the app's own lib dir
# The app's build of each of these is what the SDK was linked against, so prefer
# it over any other copy (this is why libmbedtls/libmbedx509 come from here too).
XAPK_LIBS="
  libThingCameraSDK.so libThingP2PSDK.so libThingAvLogSDK.so libThingAudioEngineSDK.so
  libThingVideoCodecSDK.so libThingFFmpegWrapper.so libThingSmartLink.so
  libavcodec.so libavformat.so libavutil.so libavfilter.so libswscale.so libswresample.so
  libyuv.so libopenh264.so libssl.1.1.so libcrypto.1.1.so
  libc++_shared.so libmbedcrypto.so libmbedtls.so libmbedx509.so
  libthing_security.so libthing_security_algorithm.so
"
for so in $XAPK_LIBS; do
    ln -sfn "/ext/xapk/lib/arm64-v8a/$so" "$SYS/system/lib64/$so"
done

# --- Android system libs from the NDK
# These are NDK link stubs, which is enough only because the camera chain lists
# them as NEEDED (so the symbols must resolve at load) but never calls into them.
# Hand-written empty stubs are NOT enough: libz's inflate/zlibVersion and
# libstdc++'s __cxa_pure_virtual / operator new+delete must exist as symbols.
# /run/ndk/lib is a level of indirection the entrypoint fills in, because the NDK
# host tag (linux-x86_64) cannot be globbed while the image is being built.
for so in libz.so libstdc++.so libOpenSLES.so libGLESv1_CM.so libGLESv2.so; do
    ln -sfn "/run/ndk/lib/$so" "$SYS/system/lib64/$so"
done

# --- the binary, its assets and the signing cert
ln -sfn "/opt/outdoor-cam-ctl/$BIN"        "$SYS/work/$BIN"
ln -sfn /ext/xapk/assets/t_s.bmp           "$SYS/work/assets/t_s.bmp"
ln -sfn /ext/xapk/assets/t_cdc.tcfg        "$SYS/work/assets/t_cdc.tcfg"
ln -sfn /run/outdoor-cam-ctl/signer.der    "$SYS/work/signer.der"

# --- the one real file: bionic's linker config
cat > "$SYS/system/etc/ld.config.txt" <<'EOF'
dir.system = /system/bin
[system]
namespace.default.isolated = false
namespace.default.search.paths = /system/lib64
EOF

# The linker looks for a *generated* config at /linkerconfig/ld.config.txt first
# — on a real device linkerconfig(8) writes it during boot. Nothing generates it
# here, and its absence makes the linker print a warning to stderr on every
# single run before falling back to /system/etc. The same config there satisfies
# the first lookup and keeps the output clean.
mkdir -p "$SYS/linkerconfig"
cp "$SYS/system/etc/ld.config.txt" "$SYS/linkerconfig/ld.config.txt"

n=$(find "$SYS/system/lib64" -maxdepth 1 -name '*.so' | wc -l | tr -d ' ')
echo "== skeleton ready: $n libs under system/lib64 =="
[ "$n" = "34" ] || { echo "expected 34 libs, got $n" >&2; exit 1; }
