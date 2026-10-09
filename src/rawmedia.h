// Encoded live video, straight off the P2P session.
//
// camera_start_preview() makes the camera SDK start its own software decoder, and
// all it hands back is decoded I420 — which under emulation costs well over a core
// and has to be re-encoded by whoever watches. But the camera already sends
// H.264 (sd) / H.265 (hd). So this path leaves the SDK's preview alone and does
// what ThingCameraSimple::StartPreview does on the wire, through the P2P SDK's C
// API: the clarity and start-video commands via ThingP2PSendData on channel 0.
// The video then arrives on channel 1, which we take over from the SDK's own
// reader (see rawmedia.c) and de-frame to an Annex-B elementary stream.
//
// The command layout and the channel numbers are the ones thing_p2p/qemu/
// p2p_harness.c proved against this camera; the command ids and payloads are from
// ThingCameraSimple::StartPreview/StopPreview (ghidra-output/camera_start.c).
#ifndef OUTDOOR_CAM_RAWMEDIA_H
#define OUTDOOR_CAM_RAWMEDIA_H

// Take over the media channel of `session` (camera_p2p_session) and ask the
// camera for video at `clarity`. Annex-B goes out through stream_write_bytes, so
// stream_open_bytes must already be done. 0 on success.
int  rawmedia_start(int session, int clarity);

// Send stop-video and hand the media channel back. Safe after a failed start.
void rawmedia_stop(void);

// The tap alone, for streams something else starts (playback): media-channel bytes
// are de-framed to Annex-B and the SDK sees none, so it decodes nothing.
// rawmedia_untap hands the channel back without sending anything.
int  rawmedia_tap(int session);
void rawmedia_untap(void);

// The newest video frame's recording time, unix ms; 0 before the first. Only
// playback frames carry it meaningfully.
unsigned long long rawmedia_last_ms(void);

// Also take the audio channel's PCM (8 kHz, mono, s16le) into `path`. Call after
// rawmedia_tap; the file is closed by rawmedia_untap. 0 on success.
int  rawmedia_audio_out(const char *path);

// What the media channel carried: packets per RTP payload type, and the video
// frame rate by the frame headers' recording times.
void rawmedia_summary(void);

// "h264", "h265", or NULL until the first video packet has arrived.
const char *rawmedia_codec(void);

#endif
