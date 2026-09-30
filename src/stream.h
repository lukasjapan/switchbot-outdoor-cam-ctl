// Y4M writer for `live`.
//
// The camera SDK never exposes the encoded bitstream to us — its listener only
// offers frames it has already decoded, as three I420 planes (see camera.c's
// onVideoFrameRecved). Raw planes carry no geometry, and the same byte count fits
// a dozen plausible resolutions, so the bytes alone are ambiguous.
//
// Wrapping them in YUV4MPEG2 fixes that for essentially nothing: a ~58-byte text
// header plus 6 bytes per frame (0.002% on a 40 MB capture). It is streamable by
// design and every ffmpeg tool auto-detects it, so `live --raw | ffplay -i pipe:0`
// works with no format flags at all.
#ifndef OUTDOOR_CAM_STREAM_H
#define OUTDOOR_CAM_STREAM_H

#include <stddef.h>
#include <stdint.h>

// out == "-" (or NULL) means stdout. The geometry goes into the Y4M header, so it
// has to be right; stream_write_frame cross-checks it against the plane sizes and
// complains if they disagree. fps is nominal — it sets playback pacing only.
int  stream_open(const char *out, int w, int h, int fps);
void stream_close(void);

// Called from the SDK's frame thread. Emits one Y4M frame (FRAME magic + the
// three planes) and flushes, so a consumer sees each frame as it is produced
// rather than in 4 KB clumps.
void stream_write_frame(const uint8_t *y, size_t ylen,
                        const uint8_t *u, size_t ulen,
                        const uint8_t *v, size_t vlen);

// The encoded `live` path: same destination handling and bounded writes, but no
// header and no framing — the caller hands over finished bytes (one Annex-B access
// unit or NAL at a time). Each call counts as one "frame" for stream_frame_count.
int  stream_open_bytes(const char *out);
void stream_write_bytes(const uint8_t *buf, size_t len);

long stream_frame_count(void);
int  stream_broken(void);   // destination went away (EPIPE / short write)

#endif
