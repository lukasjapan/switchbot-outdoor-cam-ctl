#!/usr/bin/env bash
# Extract the five real Android bionic files from the com.android.runtime APEX.
#
# Why this exists: the runtime bionic (linker64 + libc/libm/libdl/libdl_android)
# ships with the Android OS, not with the NDK. The NDK's same-named files are
# *link stubs* — its libc.so is 204K against the real 1.2M — and it contains no
# linker64 at all. So the only source is an Android system image; we take it from
# a digest-pinned redroid image, which carries the APEX verbatim.
#
# The APEX is a zip whose apex_payload.img is an ext4 filesystem. debugfs reads
# it without mounting, so this needs no privileges and works in a plain
# `docker build` (a loopback mount would need --privileged).
set -euo pipefail

APEX="${1:?usage: extract-bionic.sh <com.android.runtime.apex> <outdir>}"
OUT="${2:?usage: extract-bionic.sh <com.android.runtime.apex> <outdir>}"
IMG=/tmp/apex_payload.img

mkdir -p "$OUT"
echo "== unpacking $APEX =="
unzip -p "$APEX" apex_payload.img > "$IMG"

echo "== dumping bionic out of the ext4 payload (no mount) =="
# guest path inside the payload -> local filename
extract() {
    debugfs -R "dump -p $1 $OUT/$2" "$IMG" 2>/dev/null
    [ -s "$OUT/$2" ] || { echo "FAILED to extract $1 from the APEX payload" >&2; exit 1; }
}
extract /bin/linker64                 linker64
extract /lib64/bionic/libc.so         libc.so
extract /lib64/bionic/libm.so         libm.so
extract /lib64/bionic/libdl.so        libdl.so
extract /lib64/bionic/libdl_android.so libdl_android.so
chmod 0755 "$OUT/linker64"
rm -f "$IMG"

# Tripwire. These are the exact bytes the working camctl sysroot ran against, so
# a bumped redroid pin can never silently swap the bionic ABI underneath us.
echo "== verifying sha256 =="
sha256sum -c --strict - <<EOF
5fb80c2306d63523bc4c4c5fcfd4e58eb1ea9df90efbdf4a5399be3793f5e20a  $OUT/linker64
a95c71cd6a4acc53aeca2d67a110ceb066f4251178f4861c485371008ceb2115  $OUT/libc.so
44433149f62eeb8f09f38ecd3566683fac01a0f89de6ea6d15f6e4deca1ba4bc  $OUT/libm.so
5cba916ac95c941b99e82ca3091b1c604b910fafae8baa92586314964445552f  $OUT/libdl.so
739c5716653bcff6700501d98f576957fc299e4f2483c3ad2bd1c0f641e96422  $OUT/libdl_android.so
EOF
echo "== bionic ready in $OUT =="
