// Native camera session (libThingCameraSDK).
//
// The SDK owns the P2P/WebRTC handshake; switchbot-outdoor-cam-ctl only supplies the credentials and
// carries the signaling. Concretely:
//   createSimpleCamera(devId, p2pType, pid, listener) -> handle
//   connect(handle, "admin", authPwd, token=p2pConfig, skill, traceId, isLan, 0)
// While connect() runs, the SDK raises sendMessageThroughMqtt(...) from its own
// threads; we publish those and feed replies back through ThingP2PSDK.setSignaling
// until the session reports connected.
#ifndef OUTDOOR_CAM_CAMERA_H
#define OUTDOOR_CAM_CAMERA_H

#include "creds.h"
#include "signaling.h"

typedef struct Camera Camera;

// Clarity values (ICameraP2P / ThingCameraConstants.VideoClarityMode). The SDK
// also defines SHD (8), but this camera's skill advertises only two video
// streams — 1920x1080 HEVC and 640x360 H.264 — so only these two are offered.
#define CAM_CLARITY_SD   2
#define CAM_CLARITY_HD   4

// Create the native camera object. `sg` carries signaling for this session, and
// `local_id` is the Tuya user uid (the P2P SDK's init takes it).
Camera *camera_open(const CredDevice *dev, Signaling *sg, const char *local_id);

// Open the P2P session. Pumps signaling on a background thread and waits up to
// `timeout_ms` for the session to come up. 0 on success.
int camera_connect(Camera *cam, const char *auth_pwd, int is_lan, int timeout_ms);

// Live preview. Frames arrive on the SDK's listener callbacks.
int camera_start_preview(Camera *cam, int clarity);
int camera_stop_preview(Camera *cam);

// Camera audio is muted by default on the live path, so a recording taken
// without unmuting has no audio track at all. 0 = unmute, 1 = mute.
int camera_set_mute(Camera *cam, int mute);

// Decoded-frame sink. While a preview runs, the SDK calls
// ThingCameraListener.onVideoFrameRecved(int, ByteBuffer y, ByteBuffer u,
// ByteBuffer v, ThingCameraVideoFrame) for every frame it has decoded. Install a
// sink to receive those three planes; without one the frames are dropped, which
// is what happened for the entire life of this tool until now.
//
// NB: called on the SDK's own frame thread, and the plane pointers are only
// valid for the duration of the call.
typedef void (*camera_frame_fn)(const unsigned char *y, size_t ylen,
                                const unsigned char *u, size_t ulen,
                                const unsigned char *v, size_t vlen);
void camera_set_frame_sink(camera_frame_fn fn);

// Record the running stream straight to MP4. The SDK does the muxing (its JNI
// listener only exposes decoded YUV planes, so handling frames ourselves would
// mean re-encoding). `folder` is created if needed; ".mp4" is appended to
// `file_name` when missing, and a matching .jpg thumbnail is written alongside.
int camera_start_record(Camera *cam, const char *folder, const char *file_name);
int camera_stop_record(Camera *cam);

// Single JPEG from the current stream.
int camera_snapshot(Camera *cam, const char *abs_path);

// Full path of the file the active/last recording wrote to (NULL if none).
const char *camera_record_path(Camera *cam);

// Start/stop SD-card playback of a span. The app opens playback before it
// downloads (CamPlayBackActivity: queryRecordTimeSliceByDay -> startPlayBack ->
// startPlayBackDownload), and the native download appears to need that context.
// `play_time` is the seek offset in seconds within the span.
int camera_start_playback(Camera *cam, long long start, long long stop, int play_time);
int camera_stop_playback(Camera *cam);

// Download one recorded span to MP4. The SDK fetches, decrypts and muxes it —
// same native muxer the live recorder uses. Blocks until the SDK reports the
// download finished (or `timeout_ms` elapses). `progress_out` receives the last
// reported percentage if non-NULL.
int camera_download(Camera *cam, long long start, long long stop,
                    const char *folder, const char *file_name,
                    int timeout_ms, int *progress_out);

// ---- SD-card recording index ----------------------------------------------
// Both queries are async natives that answer through ThingBaseCallback
// .onResponse(String json, int code); these wrap them synchronously.
// Results are malloc'd JSON text the caller frees.
//
// Days in a month -> {"DataDays":["01","05",…]}   (key is "yyyyMM")
int camera_query_days(Camera *cam, int year, int month, char **json_out, int timeout_ms);
// Fragments in a day -> {"count":N,"items":[{startTime,endTime,type,…}]}
// (key is "yyyyMMdd"; unix-second times). `events` selects the motion-event
// variant, which returned nothing on the tested camera — its SD index reports
// only {type,startTime,endTime}, with no event classification.
int camera_query_fragments(Camera *cam, int year, int month, int day, int page,
                           int events, char **json_out, int timeout_ms);

void camera_close(Camera *cam);

// Map a --format value to a clarity constant (HD default).
int camera_clarity_from_format(const char *fmt);
void camera_format_geometry(const char *fmt, int *w, int *h, int *fps);

#endif
