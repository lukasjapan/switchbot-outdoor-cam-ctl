# switchbot-outdoor-cam-ctl

A CLI for the **SwitchBot Outdoor Spotlight Cam** (1st gen): list, download and
live-view its video without the phone app. Everything runs in Docker.

This began with wanting my own footage on my own disk. With most cameras that's
routine — RTSP or ONVIF, point a recorder at it, done. This one offers neither: the
video exists inside the app and nowhere else. So the question became what was
actually stopping me, and answering it meant reading the app's native libraries.

Security research isn't my field, and a few years ago that would have ended it.
With AI it took days instead of weeks — which is arguably the more interesting
result than the tool.

---

## Security model

The camera has no local API. It speaks to the vendor's cloud, the cloud speaks to
the app, and video arrives over a peer-to-peer channel the cloud brokers between
the two.

So your password on its own gets you nowhere. The app also has to prove it is the
app. A few things stand in the way.

**The signature is awkward on purpose.** Requests are signed over a fixed subset
of their parameters, not the whole thing. Then the hex digest gets shuffled: four
8-character blocks, reordered to B, A, D, C. Assume it's a plain HMAC and the
server turns you down. One more signed parameter comes out of native code and is
constant for the life of an install.

**Bodies are encrypted, not just signed.** The same native code encrypts what goes
out and decrypts what comes back, so watching the wire doesn't hand you the
protocol.

**The keys live in a picture.** `t_s.bmp` is a real bitmap — 100×75, 24-bit, valid
header, opens in any viewer. The key material is in the pixels. Beside it,
`t_cdc.tcfg` is 4.9 KB of noise that decrypts at start-up
into region and endpoint settings.

**The keys are welded to the app's signature.** On start-up the library asks
Android which certificate signed the installed app, hashes it, and mixes that hash
into every key it derives. Repackage the app and you don't get an error — you get
keys that are quietly wrong, and a failure somewhere far away from the cause.

**Nothing long-lived for the video path.** Per-device keys, plus a P2P config that
expires — ten hours, going by what comes back. The media session brings its own
auth and encryption.

### Why this tool exists

None of that protects the video. It protects the client. Whether you're allowed to
see the footage is one server-side check, and it asks one question: does this
account own this camera?

So the effect of all that hardening isn't privacy. It's that footage from a camera
you bought, mounted and powered is reachable through exactly one program, on one
kind of device, in one shape somebody else picked. No local API, no export, no
scripting.

That's the gap this closes — and it closes it by satisfying the ownership check,
not by getting around it:

**It runs the vendor's code.** Not a reimplementation of the protocol — the real
libraries, handed the Android they're looking for.

**It signs in as you.** Your credentials stay on your machine. Nothing goes anywhere the app wouldn't send it.

**It carries none of the proprietary parts.** The libraries and the keys come out
of the app package, which you supply.

**It gets what the app gets, and no more.** Your cameras, your recordings, nothing
belonging to anyone else. The same check still decides, exactly as it does on the
phone.

Your hardware, your data. Keep it that way.

---

## What you need to obtain

Two things, neither included in this repo. Both go in version-named folders that
already exist (with a `.keep` file); just fill them.

### 1. The SwitchBot app payload → `switchbot-9.11.15.13-xapk/`

The camera libraries come from the Android app. Obtain the **XAPK bundle for
SwitchBot 9.11.15.13** and unpack it so the folder ends up like this:

```
switchbot-9.11.15.13-xapk/
  lib/arm64-v8a/*.so
  assets/t_s.bmp
  assets/t_cdc.tcfg
  assets/switchbot_config.json
  META-INF/BNDLTOOL.RSA
```

**Only 9.11.15.13 is verified. Other versions are at your own risk.**

### 2. The Android NDK → `android-ndk-r27d-linux/`

Download **Android NDK r27d, the Linux x86_64 build**, and unpack it into that
folder.

**It must be the Linux build even if you are on macOS** — the compile runs inside
a Linux container, and a macOS NDK cannot execute there. The build checks and
tells you.

**Only r27d is verified. Other versions are at your own risk.**

Still needed at run time, so keep at least these; the rest of the NDK (1.9 GB) is
build-only and deletable:

```
android-ndk-r27d-linux/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/24/
  libz.so libstdc++.so libOpenSLES.so libGLESv1_CM.so libGLESv2.so
```

---

## Run it

### Build, and set up a shortcut

From this directory:

```bash
docker compose build                                      # builds the image
docker compose run --rm switchbot-outdoor-cam-ctl <args>   # runs one command
```

Build again after changing sources.

Everything below is written as `osc <args>`, a small wrapper around that second
line — so `osc snapshot --out shot.jpg` and `docker compose run --rm
switchbot-outdoor-cam-ctl snapshot --out shot.jpg` do the same thing. It adds
only working from any directory and cleaning up a container Compose can leave
behind, so it is worth putting on your PATH:

```bash
ln -s "$PWD/osc" /usr/local/bin/osc     # or anywhere on your PATH
```

### Check it works

This loads the whole native stack without touching a camera or needing an
account — the fastest way to know your two folders are correct:

```bash
osc selftest
```

### Log in first

**A login is required before any other command** — every one of them needs your
SwitchBot account to reach the camera. The camera stack isn't SwitchBot's own: it's
Tuya's, and behind your SwitchBot account sits a second, automatically created Tuya
account that the video path actually authenticates against. Logging in exchanges your SwitchBot credentials for those Tuya ones and caches
them, so later commands need no auth.

```bash
osc login --email you@example.com --password ...
```

If your account has MFA enabled, pass the app's session token (a JWT starting
`eyJ`) instead: `osc login --session-token <jwt>`.

### Find your camera's id

Ask SwitchBot's own public API. Get an **Open Token** and **Secret Key** from the
SwitchBot app (Profile → Preferences → tap _App Version_ repeatedly until
developer options appear), then:

```bash
export SWITCHBOT_TOKEN=... SWITCHBOT_SECRET=...

python3 - <<'EOF'
import base64, hashlib, hmac, json, os, time, urllib.request, uuid
tok, sec = os.environ["SWITCHBOT_TOKEN"], os.environ["SWITCHBOT_SECRET"]
t, nonce = str(int(time.time() * 1000)), str(uuid.uuid4())
sign = base64.b64encode(
    hmac.new(sec.encode(), (tok + t + nonce).encode(), hashlib.sha256).digest()
).decode().upper()
req = urllib.request.Request(
    "https://api.switch-bot.com/v1.1/devices",
    headers={"Authorization": tok, "sign": sign, "t": t, "nonce": nonce})
for d in json.load(urllib.request.urlopen(req))["body"]["deviceList"]:
    print(d["deviceId"], d["deviceType"], d.get("deviceName", ""))
EOF
```

Your camera appears in the Outdoor Spotlight Cam family; its `deviceId` is what
`--dev-id` wants. Every camera command needs that id. Since it never changes, export it once and
drop the flag entirely:

```bash
export OUTDOOR_CAM_DEV_ID=<id>
```

An explicit `--dev-id <id>` still overrides it, for when you have more than one
camera.

### Commands

#### `list` — what's on the SD card

Defaults to the current month; the camera has no bulk index, so listing walks days.

```bash
osc list
osc list --year 2026 --month 7
osc list --from 2026-06 --to 2026-08
osc list --json
```

#### `download` — fetch a recording

Addressed by time range, since the firmware reports no ids. Paste the `START_TS`
straight from `list`, or use local wall-clock.

```bash
osc download --start 1785568473 --duration 60 --out clip.mp4
osc download --start "2026-08-01 16:14:33" --duration 60 --out clip.mp4
osc download --start 1785568473 --stop 1785568533 --out clip.mp4
osc download --start 1785568473 --duration 60 --out - > /tmp/clip.mp4
```

**`--native`.** The camera's own stream instead of the SDK's mp4, so nothing is
decoded. Video is H.265 Annex-B on `--out`, sound is raw PCM (8 kHz mono s16le) on
`--audio-out`. No container, so ffmpeg joins them:

```bash
osc download --native --start 1791028125 --stop 1791028152 --out clip.h265 --audio-out clip.pcm
ffmpeg -f hevc -framerate 15 -i clip.h265 -f s16le -ar 8000 -ac 1 -i clip.pcm \
       -c:v copy -tag:v hvc1 -c:a aac clip.mp4
```

#### `record` — capture live video to mp4

Fixed duration. Only a finished file is readable — the index lands at the end.

```bash
osc record --format hd --duration 10 --out clip.mp4
osc record --duration 10 --out - | ssh nas 'cat > /vol/clip.mp4'
```

#### `live` — stream until Ctrl-C or the player closes

Writes to stdout. Two output formats:

| | default | `--native` |
| --- | --- | --- |
| container | Y4M (uncompressed `yuv420p`) | none — Annex-B elementary stream |
| `--format hd` | 1920x1080 | H.265, 1920x1080 |
| `--format sd` | 640x360 | H.264, 640x360 |

**Default (Y4M).** The stream describes itself, so players and ffmpeg need no flags:

```bash
osc live | ffplay -
osc live --format sd | ffplay -
osc live | tee cam.y4m | ffplay -                        # watch and keep
ffmpeg -i cam.y4m -c:v libx264 cam.mp4                   # compress afterwards
```

**`--native`.** The camera's video exactly as it sends it. There is no container
and no timestamps, so tell the reader the codec (`-f hevc` for `hd`, `-f h264` for
`sd`) and the frame rate (`-framerate 15`; without it ffmpeg assumes 25):

```bash
osc live --native | ffplay -f hevc -framerate 15 -
osc live --native --format sd | ffplay -f h264 -framerate 15 -
osc live --native --format sd > cam.h264                 # keep it
ffmpeg -f h264 -framerate 15 -i cam.h264 -c copy cam.mp4 # into mp4, no re-encode
```

It stops on Ctrl-C, after `--duration <sec>`, or when whatever reads it exits —
close the ffplay window and the camera session is released shortly after. It also
gives up if no video arrives within 60 s.

A `--native` capture cut short usually ends in the middle of a group of pictures,
so ffmpeg warns about the last access unit ("missing picture in access unit").
Everything before it is intact.

#### `snapshot` — single JPEG

```bash
osc snapshot --out shot.jpg
osc snapshot --out - | ffmpeg -i - -vf scale=320:-1 -y thumb.jpg
osc snapshot --out - > /tmp/cam.jpg && open /tmp/cam.jpg
```

#### `info` — camera capabilities

```bash
osc info
```

Run `osc` with no arguments for the full option list.

- **Output** lands in `./recordings`. `--out -` writes to stdout instead — media
  only, since progress and errors go to stderr, so pipes and redirects get clean
  bytes. `live` already defaults to stdout.
- **`--duration <sec>`** caps `record` and `live`.
- **`record` has no audio track.** `download` does, since the SD card keeps it,
  but camera audio is muted by default on the live path and the SDK's unmute call
  segfaults under emulation. Unresolved — see `camera_set_mute()` in `camera.c`.
- With `OUTDOOR_CAM_DEV_ID` set, `osc selftest` also brings up the signaling
  transport against that camera. To get the plain no-account check back, blank it
  for one command: `OUTDOOR_CAM_DEV_ID= osc selftest`.

---

## How it works

The camera's protocol lives in the app's own native libraries — aarch64 Android
`.so` files that expect Android's bionic libc and dynamic linker. Rather than
reimplement the protocol, this project calls them directly: a small C program
`dlopen`s `libThingCameraSDK.so` and drives it, running as an aarch64 Android ELF
under **qemu-user** inside an arm64 Linux container, against a real Android bionic
runtime. `src/jni_mock.c` fakes just enough JNI for the SDK to believe it's on
Android. Nothing in the security model has to be reimplemented — the code that
signs, encrypts and derives the keys is the code being run.

Hence Docker: the SDK needs an Android userland (bionic, the linker, the JNI
mock, aarch64) that no Mac or desktop Linux provides.
