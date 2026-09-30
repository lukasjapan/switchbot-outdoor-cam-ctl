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

// "h264", "h265", or NULL until the first video packet has arrived.
const char *rawmedia_codec(void);

#endif
