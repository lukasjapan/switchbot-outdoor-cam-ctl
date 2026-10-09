# syntax=docker/dockerfile:1.7
# Build and run switchbot-outdoor-cam-ctl entirely inside Docker.
#
# Nothing proprietary is baked in: the SwitchBot libraries stay in the mounted
# ./switchbot-9.11.15.13-xapk, and the NDK in ./android-ndk-r27d-linux. What the
# image does contain is
# the compiled binary, the Android bionic runtime, and a /sysroot made of
# symlinks pointing at those mounts.

# ---------------------------------------------------------------------------
# 1. The Android runtime APEX, from a digest-pinned redroid image.
#    Pinned by digest on purpose: this image is the source of the exact bionic
#    bytes the working camctl sysroot ran against, and :latest moves.
#    Forced to arm64 because we need aarch64 Android binaries no matter what
#    architecture the build host is.
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 redroid/redroid@sha256:d89f520484bd16aac244e9832a150f72a8b9296f0b4439f3667c8181d1f3b77f AS apex

# ---------------------------------------------------------------------------
# 2. Pull the five bionic files out of the APEX payload.
# ---------------------------------------------------------------------------
FROM --platform=linux/arm64 debian:bookworm-slim AS bionic
RUN apt-get update && apt-get install -y --no-install-recommends \
        unzip e2fsprogs \
    && rm -rf /var/lib/apt/lists/*
COPY --from=apex /system/apex/com.android.runtime.apex /tmp/runtime.apex
COPY scripts/extract-bionic.sh /usr/local/bin/extract-bionic.sh
RUN chmod +x /usr/local/bin/extract-bionic.sh \
    && /usr/local/bin/extract-bionic.sh /tmp/runtime.apex /opt/bionic \
    && rm -f /tmp/runtime.apex

# ---------------------------------------------------------------------------
# 3. Cross-compile with the mounted NDK.
#    linux/amd64 because Google ships no official linux-aarch64 NDK, so the
#    toolchain binaries are x86_64 and run here under Docker Desktop emulation.
#    The NDK arrives as a named build context (see docker-compose.yml), bind
#    mounted read-only — BuildKit only transfers the files clang actually reads.
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 debian:bookworm-slim AS builder
ARG API=24
RUN apt-get update && apt-get install -y --no-install-recommends \
        libncurses6 zlib1g \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src   ./src
COPY mocks ./mocks
# Compiled with src/*.c as a glob (camctl carried a hand-maintained file list
# that named a mux.c which does not exist). No -lpthread: bionic folds pthread
# into libc, so the flag does not exist there.
# ThingP2PRecvData is exported so the camera SDK's import of it binds to ours
# (src/rawmedia.c): that is how `live --native` takes over the media channel.
# ThingP2PSendData likewise, so the SDK's own commands (playback) pass by it.
RUN --mount=type=bind,from=ndk,target=/ndk \
    set -eu; \
    CCDIR=/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin; \
    if [ ! -d "$CCDIR" ]; then \
        echo "error: the NDK build context must be a LINUX NDK (developed against r27d)." >&2; \
        echo "       Found host tags: $(ls /ndk/toolchains/llvm/prebuilt 2>/dev/null || echo none)" >&2; \
        echo "       A darwin-x86_64 NDK holds macOS binaries and cannot run in this container." >&2; \
        echo "       Unpack android-ndk-r27d-linux.zip into ./android-ndk-r27d-linux" >&2; \
        exit 1; \
    fi; \
    CC="$CCDIR/aarch64-linux-android${API}-clang"; \
    mkdir -p /out; \
    echo "== switchbot-outdoor-cam-ctl =="; \
    "$CC" -O2 -Wall -Wextra -fPIE -pie -Isrc src/*.c -ldl \
          -Wl,--export-dynamic-symbol=ThingP2PRecvData \
          -Wl,--export-dynamic-symbol=ThingP2PSendData \
          -o /out/switchbot-outdoor-cam-ctl; \
    echo "== liblog shim =="; \
    "$CC" -O2 -Wall -shared -fPIC -Wl,-soname,liblog.so \
          mocks/mock_liblog.c -o /out/liblog.so; \
    echo "== mock libandroid =="; \
    "$CC" -O2 -Wall -shared -fPIC -Wl,-soname,libandroid.so \
          mocks/mock_android.c -o /out/libandroid.so

# ---------------------------------------------------------------------------
# 4. Runtime: arm64 Linux with qemu-user.
#    On Apple Silicon this is a native arm64 container (no CPU emulation);
#    qemu-user supplies a clean guest loader and syscall layer isolated from the
#    container's glibc, and needs no binder.
# ---------------------------------------------------------------------------
FROM arm64v8/debian:bookworm-slim
# tzdata matters: with no zoneinfo database bionic's localtime_r() silently falls
# back to UTC, so recording timestamps would render in the wrong zone.
# openssl derives signer.der from the APK signature block at container start.
RUN apt-get update && apt-get install -y --no-install-recommends \
        qemu-user \
        ca-certificates \
        tzdata \
        openssl \
        unzip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=bionic  /opt/bionic /opt/bionic
COPY --from=builder /out        /opt/outdoor-cam-ctl
COPY scripts/make-skeleton.sh scripts/entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/make-skeleton.sh /usr/local/bin/entrypoint.sh \
    && /usr/local/bin/make-skeleton.sh

# Android-format timezone database. bionic does NOT read /usr/share/zoneinfo —
# __bionic_open_tzdata looks for a single concatenated blob under $ANDROID_ROOT
# (default /system), so the Debian tzdata package alone leaves it falling back to
# UTC whatever TZ says. Taking the real blob from the same image as bionic makes
# TZ actually work; without this, recording timestamps render in UTC.
COPY --from=apex /system/usr/share/zoneinfo/tzdata /sysroot/system/usr/share/zoneinfo/tzdata

WORKDIR /hostcwd
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
