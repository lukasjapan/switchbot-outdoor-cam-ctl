#include "camera.h"
#include "jni_mock.h"
#include "json.h"
#include "native.h"
#include "status.h"

#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CAM_PREFIX "Java_com_thingclips_smart_camera_nativeapi_ThingCameraNative_"
#define P2P_SETSIGNALING "Java_com_thingclips_smart_p2p_p2psdk_ThingP2PSDK_setSignaling"

// Native signatures, per ThingCameraNative's declarations.
typedef jlong (*fn_createSimple_t)(JNIEnv*, jclass, jstring, jint, jstring, jobject);
typedef jint  (*fn_connect_t)(JNIEnv*, jclass, jlong, jstring, jstring, jstring, jstring, jstring, jboolean, jint);
typedef jint  (*fn_startPreview_t)(JNIEnv*, jclass, jlong, jint, jobject);
typedef jint  (*fn_stopPreview_t)(JNIEnv*, jclass, jlong, jobject);
typedef jint  (*fn_setMute_t)(JNIEnv*, jclass, jlong, jint);
typedef jint  (*fn_disconnect_t)(JNIEnv*, jclass, jlong, jboolean);
typedef jint  (*fn_destroy_t)(JNIEnv*, jclass, jlong);
typedef jint  (*fn_setEncryptionInfo_t)(JNIEnv*, jclass, jlong, jstring);
typedef void  (*fn_setSignaling_t)(JNIEnv*, jobject, jstring, jint);

struct Camera {
    jlong handle;
    const CredDevice *dev;
    Signaling *sg;
    char *p2pConfig;      // the connect "token"
    char *skill;
    char *traceId;

    // Session state, written from SDK threads.
    volatile int connected;      // 1 once the session reports up
    volatile int failed;
    volatile int last_state;
    volatile int last_error;

    // The P2P SDK's session handle, for `live --native`, which drives
    // ThingP2PSendData directly. -1 until the session is up.
    volatile int p2pSession;

    // Signaling pump.
    pthread_t pump;
    volatile int pump_stop;
    int pump_running;

    // Active recording (the SDK writes the mp4 itself).
    char recPath[512];
    int recording;

    // In-flight query: the record-index natives answer asynchronously through
    // ThingBaseCallback.onResponse(json, code), so one slot is enough for the
    // synchronous wrappers below (only one query runs at a time).
    volatile int   queryPending;
    volatile int   queryDone;
    volatile int   queryCode;
    char          *queryJson;

    // In-flight playback download (async: onProgress/onFinished).
    volatile int   dlActive;
    volatile int   dlDone;
    volatile int   dlCode;
    volatile int   dlProgress;
};

// mkdir -p for the recording directory.
static int mkdir_p(const char *path){
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for(char *p = tmp + 1; *p; p++){
        if(*p != '/') continue;
        *p = 0;
        if(mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    if(mkdir(tmp, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

// The JNI mock's handlers are plain function pointers with no user data, so the
// active session is reachable through this. switchbot-outdoor-cam-ctl drives one camera at a time.
static Camera *g_active;

static void *cam_sym(const char *suffix){
    void *so = native_camera_so();
    if(!so) return NULL;
    char buf[256];
    snprintf(buf, sizeof buf, CAM_PREFIX "%s", suffix);
    void *p = dlsym(so, buf);
    if(!p) st_debug("camera SDK: missing export %s", buf);
    return p;
}
static jclass cam_class(void){
    return (jclass)jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraNative");
}

// Hand an inbound 302 payload to the P2P SDK.
static void feed_signaling(const char *json, void *user){
    (void)user;
    void *p2p = native_p2p_so();
    fn_setSignaling_t fn = p2p ? (fn_setSignaling_t)dlsym(p2p, P2P_SETSIGNALING) : NULL;
    if(!fn){ st_debug("no setSignaling export — dropping inbound frame"); return; }
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/p2p/p2psdk/ThingP2PSDK");
    fn(&g_env, (jobject)klass, (jstring)jni_mk_string(json), (jint)strlen(json));
    st_debug("signaling fed to SDK (%zu bytes)", strlen(json));
}

// Where decoded frames go while a preview runs, if anyone asked for them.
static camera_frame_fn g_frame_sink;
void camera_set_frame_sink(camera_frame_fn fn){ g_frame_sink = fn; }

// ---- SDK -> us -------------------------------------------------------------
// Outbound signaling plus session-state notifications. Argument layouts mirror
// the Java callbacks the SDKs invoke.
static void on_void_callback(const char *method, MockObj *self, va_list *ap){
    (void)self;
    if(!method) return;
    Camera *cam = g_active;

    if(!strcmp(method, "sendMessageThroughMqtt")){
        if(!ap) return;
        int byLan       = va_arg(*ap, int);
        MockObj *topic  = va_arg(*ap, MockObj*);
        MockObj *json   = va_arg(*ap, MockObj*);
        const char *t = (topic && topic->str) ? topic->str : NULL;
        const char *j = (json  && json->str)  ? json->str  : NULL;
        // The SDK offers each message twice: byLan=1 for a direct local publish
        // (the app's lan302Publish) and byLan=0 for the cloud broker. We only
        // carry the cloud path, so dropping the LAN copy avoids sending each
        // frame twice.
        if(byLan){
            st_debug("SDK -> signaling (LAN copy, skipped)");
            return;
        }
        st_debug("SDK -> signaling (dev=%s)", t ? t : "(default)");
        if(cam && cam->sg && j) signaling_publish(cam->sg, t, j);
        return;
    }
    // libThingP2PSDK's own session notification: i2 is the state (3 = connected,
    // 4 = closed), i4 the error code.
    if(!strcmp(method, "onSessionStateChanged")){
        if(!ap) return;
        MockObj *sid = va_arg(*ap, MockObj*); // session id string
        int i0 = va_arg(*ap, int);
        int i1 = va_arg(*ap, int);
        int state = va_arg(*ap, int);
        int i3 = va_arg(*ap, int);
        int err = va_arg(*ap, int);
        if(cam){
            cam->last_state = state;
            cam->last_error = err;
            // i0 is the handle ThingP2PSendData takes: checked on the camera,
            // where it was 65537 and the commands sent on it were answered.
            if(state == 3){ cam->connected = 1; cam->p2pSession = i0; }
            if(state == 4) cam->failed = 1;
        }
        st_debug("P2P session state=%d err=%d (id=%s i0=%d i1=%d i3=%d)", state, err,
                 sid && sid->str ? sid->str : "", i0, i1, i3);
        return;
    }
    // ThingCameraListener.onSessionStatusChanged(sessionId, status): 5 = connected,
    // 4 = failure, 6 = not connected (ICameraP2P constants).
    if(!strcmp(method, "onSessionStatusChanged")){
        if(!ap) return;
        int session = va_arg(*ap, int);
        int status  = va_arg(*ap, int);
        if(cam){
            cam->last_state = status;
            if(status == 5) cam->connected = 1;
            if(status == 4 || status == 6) cam->failed = 1;
        }
        st_debug("camera session=%d status=%d", session, status);
        return;
    }
    // ThingBaseCallback.onResponse(String json, int code) — how the record-index
    // natives return their results.
    if(!strcmp(method, "onResponse")){
        if(!ap) return;
        MockObj *js = va_arg(*ap, MockObj*);
        int code = va_arg(*ap, int);
        if(cam && cam->queryPending && !cam->queryDone){
            free(cam->queryJson);
            cam->queryJson = (js && js->str) ? strdup(js->str) : NULL;
            cam->queryCode = code;
            cam->queryDone = 1;
            st_debug("query response code=%d (%zu bytes)", code,
                     cam->queryJson ? strlen(cam->queryJson) : (size_t)0);
        } else {
            st_debug("onResponse code=%d (no query waiting)", code);
        }
        return;
    }
    // ThingProgressiveCallback.onProgress(int, int) / onFinished(String, int) —
    // how startPlayBackDownload reports progress and completion.
    if(!strcmp(method, "onProgress")){
        if(!ap) return;
        int a = va_arg(*ap, int);
        int b = va_arg(*ap, int);
        if(cam && cam->dlActive){
            // The first value carries the percentage; the second stayed 0 in
            // every observed run.
            int pct = a > 0 ? a : b;
            if(pct != cam->dlProgress){ cam->dlProgress = pct; st_info("download %d%%", pct); }
        } else st_debug("onProgress %d/%d", a, b);
        return;
    }
    if(!strcmp(method, "onFinished")){
        if(!ap) return;
        MockObj *msg = va_arg(*ap, MockObj*);
        int code = va_arg(*ap, int);
        if(cam && cam->dlActive){
            cam->dlCode = code;
            cam->dlDone = 1;
            st_debug("download finished code=%d msg=%s", code, msg && msg->str ? msg->str : "");
        } else st_debug("onFinished code=%d", code);
        return;
    }
    if(!strcmp(method, "onSessionStatusChangedWithMsg")){ st_debug("session status (with msg)"); return; }
    if(!strcmp(method, "onEventInfoReceived")){ st_debug("SDK event info"); return; }
    if(!strcmp(method, "sendNativeLog") || !strcmp(method, "sendApmLog") ||
       !strcmp(method, "sendFullLinkLog")){
        if(g_status_verbose && ap){
            MockObj *s = va_arg(*ap, MockObj*);
            if(s && s->str) st_debug("sdk: %s", s->str);
        }
        return;
    }
    // ThingCameraListener.onVideoFrameRecved(int, ByteBuffer y, ByteBuffer u,
    //   ByteBuffer v, ThingCameraVideoFrame) — one decoded frame, as three
    // planes. The trailing frame-info object carries width/height/keyframe, but
    // the SDK passes those to its constructor and our J_NewObject discards
    // constructor arguments, so the geometry has to come from the caller (which
    // knows the clarity it asked for) and is cross-checked against the plane
    // sizes in stream.c.
    if(!strcmp(method, "onVideoFrameRecved")){
        if(!ap || !g_frame_sink) return;
        (void)va_arg(*ap, int);                 // which port/handle
        MockObj *y = va_arg(*ap, MockObj*);
        MockObj *u = va_arg(*ap, MockObj*);
        MockObj *v = va_arg(*ap, MockObj*);
        if(y && u && v && y->bytes && u->bytes && v->bytes)
            g_frame_sink(y->bytes, (size_t)y->len,
                         u->bytes, (size_t)u->len,
                         v->bytes, (size_t)v->len);
        return;
    }
    st_debug("unhandled SDK callback: %s", method);
}

// ---- signaling pump --------------------------------------------------------
static void *pump_thread(void *arg){
    Camera *cam = (Camera*)arg;
    while(!cam->pump_stop){
        // Keep the poll's read window SHORT. Reads and writes share one TLS
        // socket, so they must be serialised — and if the pump held that lock
        // across a long blocking read, the SDK's outbound candidates would queue
        // behind it and the handshake would time out (-3) before they were ever
        // published. Sleep outside the lock so writers get in promptly.
        if(signaling_poll(cam->sg, 10, feed_signaling, cam) != 0){
            st_warn("signaling link lost");
            break;
        }
        usleep(2000);
    }
    return NULL;
}

// ---- public ---------------------------------------------------------------
int camera_clarity_from_format(const char *fmt){
    if(!fmt) return CAM_CLARITY_HD;
    if(!strcasecmp(fmt, "sd") || !strcasecmp(fmt, "standard")) return CAM_CLARITY_SD;
    if(!strcasecmp(fmt, "hd")) return CAM_CLARITY_HD;
    st_warn("unknown --format '%s'; using hd (valid: hd, sd)", fmt);
    return CAM_CLARITY_HD;
}

// Expected decoded geometry and nominal frame rate per clarity. These go into the
// Y4M header `live` writes, so they have to be right — the frame-info object the
// SDK passes alongside each frame does carry the real width/height, but it arrives
// as constructor arguments that the JNI mock does not retain.
//
// The rates are measured, not from a spec: SD sustains roughly 15 fps, while HD
// runs slower because 1080p HEVC is being decoded in software under emulation.
void camera_format_geometry(const char *fmt, int *w, int *h, int *fps){
    int sd = camera_clarity_from_format(fmt) == CAM_CLARITY_SD;
    if(w)   *w   = sd ? 640 : 1920;
    if(h)   *h   = sd ? 360 : 1080;
    if(fps) *fps = sd ? 15  : 10;
}

Camera *camera_open(const CredDevice *dev, Signaling *sg, const char *local_id){
    if(!dev || !dev->p2pConfig){
        st_err("camera: device has no p2pConfig (run info first)");
        return NULL;
    }
    fn_createSimple_t create = (fn_createSimple_t)cam_sym("createSimpleCamera");
    if(!create){ st_err("camera SDK: no createSimpleCamera export"); return NULL; }

    // Both engines must be initialised before a camera can connect, mirroring
    // IPCThingP2PCamera.initNativeOnce: the AV engine, then the P2P SDK keyed by
    // the user uid. Without the latter, ThingP2PConnect_v3 fails instantly with
    // session -1. (initP2PModule() is only for the legacy p2pType 2 path.)
    if(native_engine_initialize() < 0){ st_err("camera engine init failed"); return NULL; }
    // Software decode only: there is no Android MediaCodec behind the JNI mock,
    // and letting the SDK probe hardware decode for HEVC crashes it.
    native_engine_set_soft_decode(1);
    if(native_p2p_init(local_id) < 0)  st_warn("P2P SDK init reported a problem — connect may fail");

    Camera *cam = calloc(1, sizeof *cam);
    if(!cam) return NULL;
    cam->dev = dev;
    cam->sg  = sg;
    cam->p2pSession = -1;
    cam->p2pConfig = strdup(dev->p2pConfig);
    cam->skill     = dev->skill ? strdup(dev->skill) : strdup("");
    // The app uses "<sessionTid>_<millis>"; any stable-per-connect value works.
    char trace[64];
    snprintf(trace, sizeof trace, "outdoorcam%08x", (unsigned)(uintptr_t)cam);
    cam->traceId = strdup(trace);

    // Route the SDK's callbacks here before anything can fire.
    g_active = cam;
    jni_set_void_handler(on_void_callback);

    // The listener object is opaque to us; the mock only needs it to exist so the
    // SDK can invoke methods on it (which land in on_void_callback).
    MockObj *listener = jni_mk_object("com/thingclips/smart/camera/api/ThingCameraListener", cam);
    int p2p_type = dev->p2pType > 0 ? dev->p2pType : 4;
    st_info("creating camera (devId=%s p2pType=%d)…", dev->devId, p2p_type);
    cam->handle = create(&g_env, cam_class(),
                         (jstring)jni_mk_string(dev->devId), (jint)p2p_type,
                         (jstring)jni_mk_string(dev->pv[0] ? dev->pv : ""),
                         (jobject)listener);
    if(cam->handle == 0){
        st_err("createSimpleCamera returned a null handle");
        camera_close(cam);
        return NULL;
    }
    st_debug("camera handle=%lld", (long long)cam->handle);
    return cam;
}

int camera_connect(Camera *cam, const char *auth_pwd, int is_lan, int timeout_ms){
    if(!cam || !auth_pwd) return -1;
    fn_connect_t connect_fn = (fn_connect_t)cam_sym("connect");
    if(!connect_fn){ st_err("camera SDK: no connect export"); return -1; }

    // Start carrying signaling before connect(), since the SDK begins publishing
    // as soon as it is called.
    if(cam->sg && !cam->pump_running){
        cam->pump_stop = 0;
        if(pthread_create(&cam->pump, NULL, pump_thread, cam) == 0) cam->pump_running = 1;
        else st_warn("could not start the signaling pump thread");
    }

    st_info("opening P2P session (%s)…", is_lan ? "LAN" : "relay/cloud");
    jint rc = connect_fn(&g_env, cam_class(), cam->handle,
                         (jstring)jni_mk_string("admin"),
                         (jstring)jni_mk_string(auth_pwd),
                         (jstring)jni_mk_string(cam->p2pConfig),
                         (jstring)jni_mk_string(cam->skill),
                         (jstring)jni_mk_string(cam->traceId),
                         is_lan ? JNI_TRUE : JNI_FALSE,
                         0);
    st_debug("connect() -> %d", (int)rc);

    // connect() may return a session id (>=0) immediately and finish asynchronously,
    // so wait for the state callback either way.
    int waited = 0;
    const int step = 100;
    while(!cam->connected && !cam->failed && waited < timeout_ms){
        usleep((useconds_t)step * 1000);
        waited += step;
    }
    if(cam->connected){
        st_info("P2P session connected");
        return 0;
    }
    if(cam->failed)
        st_err("P2P session failed (state=%d error=%d)", cam->last_state, cam->last_error);
    else if(rc < 0)
        st_err("connect() rejected the request (%d)", (int)rc);
    else
        st_err("P2P session did not come up within %dms (last state=%d)", timeout_ms, cam->last_state);
    return -1;
}

int camera_p2p_session(Camera *cam){ return cam ? cam->p2pSession : -1; }

int camera_start_preview(Camera *cam, int clarity){
    if(!cam) return -1;
    fn_startPreview_t fn = (fn_startPreview_t)cam_sym("startPreview");
    if(!fn){ st_err("camera SDK: no startPreview export"); return -1; }
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingBaseCallback", cam);
    jint rc = fn(&g_env, cam_class(), cam->handle, (jint)clarity, (jobject)cb);
    st_debug("startPreview(clarity=%d) -> %d", clarity, (int)rc);
    return rc >= 0 ? 0 : -1;
}

// ThingCameraNative.setMute(long, int) — ICameraP2P.MUTE = 1, UNMUTE = 0.
// Camera audio starts muted, so a recording made without this has a video track
// and nothing else. Playback (download) is unaffected: it carries whatever the
// SD card holds.
//
// WARNING: calling this under qemu segfaults inside the SDK (null deref) — it is
// not wired into any command yet. The signature is right (the app calls the same
// native directly, ThingCameraImpl.setMute), and there is no missing prerequisite
// at the Java layer: IPCThingP2PCamera.audioOpen() is an empty method. Something
// in the native audio path is uninitialised in this environment. Kept because the
// wrapper is correct and the next attempt should start here.
int camera_set_mute(Camera *cam, int mute){
    if(!cam) return -1;
    fn_setMute_t fn = (fn_setMute_t)cam_sym("setMute");
    if(!fn){ st_debug("camera SDK: no setMute export"); return -1; }
    jint rc = fn(&g_env, cam_class(), cam->handle, (jint)mute);
    st_debug("setMute(%d) -> %d", mute, (int)rc);
    return rc >= 0 ? 0 : -1;
}

int camera_stop_preview(Camera *cam){
    if(!cam) return -1;
    fn_stopPreview_t fn = (fn_stopPreview_t)cam_sym("stopPreview");
    if(!fn) return -1;
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingBaseCallback", cam);
    return fn(&g_env, cam_class(), cam->handle, (jobject)cb) >= 0 ? 0 : -1;
}

void camera_close(Camera *cam){
    if(!cam) return;
    if(cam->pump_running){
        cam->pump_stop = 1;
        pthread_join(cam->pump, NULL);
        cam->pump_running = 0;
    }
    if(cam->handle){
        fn_disconnect_t dis = (fn_disconnect_t)cam_sym("disconnect");
        if(dis) dis(&g_env, cam_class(), cam->handle, JNI_FALSE);
        fn_destroy_t des = (fn_destroy_t)cam_sym("destroy");
        if(des) des(&g_env, cam_class(), cam->handle);
        cam->handle = 0;
    }
    if(g_active == cam){ g_active = NULL; jni_set_void_handler(NULL); }
    free(cam->p2pConfig); free(cam->skill); free(cam->traceId);
    free(cam);
}

// ThingCameraNative.startRecordLocalMp4(handle, folder, file, thumb, rotation, i, i)
typedef jint (*fn_startRecord_t)(JNIEnv*, jclass, jlong, jstring, jstring, jstring, jint, jint, jint);
typedef jint (*fn_stopRecord_t)(JNIEnv*, jclass, jlong, jint, jint);
typedef jint (*fn_snapshot_t)(JNIEnv*, jclass, jlong, jstring, jint, jint, jint);

int camera_start_record(Camera *cam, const char *folder, const char *file_name){
    if(!cam || !folder || !*folder || !file_name || !*file_name){
        st_err("record: folder and file name are required");
        return -1;
    }
    fn_startRecord_t fn = (fn_startRecord_t)cam_sym("startRecordLocalMp4");
    if(!fn){ st_err("camera SDK: no startRecordLocalMp4 export"); return -1; }

    // Same preparation the app does: create the directory, ensure a trailing
    // slash, force a .mp4 suffix, and derive the thumbnail name from it.
    if(mkdir_p(folder) != 0){ st_err("record: cannot create %s", folder); return -1; }
    char dir[512];
    snprintf(dir, sizeof dir, "%s%s", folder, folder[strlen(folder)-1] == '/' ? "" : "/");

    char mp4[256];
    size_t fn_len = strlen(file_name);
    if(fn_len > 4 && !strcasecmp(file_name + fn_len - 4, ".mp4"))
        snprintf(mp4, sizeof mp4, "%s", file_name);
    else
        snprintf(mp4, sizeof mp4, "%s.mp4", file_name);

    char jpg[256];
    snprintf(jpg, sizeof jpg, "%s", mp4);
    size_t jl = strlen(jpg);
    if(jl > 4) memcpy(jpg + jl - 4, ".jpg", 4);

    jint rc = fn(&g_env, cam_class(), cam->handle,
                 (jstring)jni_mk_string(dir), (jstring)jni_mk_string(mp4),
                 (jstring)jni_mk_string(jpg), 0, 0, 0);
    st_debug("startRecordLocalMp4(%s%s) -> %d", dir, mp4, (int)rc);
    if(rc < 0){ st_err("the SDK refused to start recording (%d)", (int)rc); return -1; }
    snprintf(cam->recPath, sizeof cam->recPath, "%s%s", dir, mp4);
    cam->recording = 1;
    return 0;
}

int camera_stop_record(Camera *cam){
    if(!cam || !cam->recording) return -1;
    fn_stopRecord_t fn = (fn_stopRecord_t)cam_sym("stopRecordLocalMp4");
    if(!fn) return -1;
    jint rc = fn(&g_env, cam_class(), cam->handle, 0, 0);
    cam->recording = 0;
    st_debug("stopRecordLocalMp4 -> %d", (int)rc);
    return rc >= 0 ? 0 : -1;
}

int camera_snapshot(Camera *cam, const char *abs_path){
    if(!cam || !abs_path) return -1;
    fn_snapshot_t fn = (fn_snapshot_t)cam_sym("snapshot");
    if(!fn){ st_err("camera SDK: no snapshot export"); return -1; }
    // The SDK will not create the directory (unlike the recorder), so make sure
    // the parent exists or it silently writes nothing.
    {
        char dir[512];
        snprintf(dir, sizeof dir, "%s", abs_path);
        char *slash = strrchr(dir, '/');
        if(slash && slash != dir){
            *slash = 0;
            if(mkdir_p(dir) != 0){ st_err("snapshot: cannot create %s", dir); return -1; }
        }
    }
    jint rc = fn(&g_env, cam_class(), cam->handle, (jstring)jni_mk_string(abs_path), 0, 0, 0);
    st_debug("snapshot(%s) -> %d", abs_path, (int)rc);
    return rc >= 0 ? 0 : -1;
}

const char *camera_record_path(Camera *cam){ return cam && cam->recPath[0] ? cam->recPath : NULL; }

// ThingCameraNative record-index natives.
typedef jint (*fn_days_t)(JNIEnv*, jclass, jlong, jstring, jobject);
typedef jint (*fn_frags_t)(JNIEnv*, jclass, jlong, jstring, jint, jobject);

// Issue an async record-index query and block until onResponse arrives.
static int query_wait(Camera *cam, char **json_out, int timeout_ms, const char *what){
    int waited = 0;
    const int step = 50;
    while(!cam->queryDone && waited < timeout_ms){
        usleep((useconds_t)step * 1000);
        waited += step;
    }
    cam->queryPending = 0;
    if(!cam->queryDone){
        st_err("%s timed out after %dms", what, timeout_ms);
        return -1;
    }
    if(cam->queryCode < 0){
        st_err("%s failed (code %d)", what, cam->queryCode);
        free(cam->queryJson); cam->queryJson = NULL;
        return -1;
    }
    *json_out = cam->queryJson;      // hand ownership to the caller
    cam->queryJson = NULL;
    return 0;
}

static void query_begin(Camera *cam){
    cam->queryDone = 0;
    cam->queryCode = 0;
    free(cam->queryJson);
    cam->queryJson = NULL;
    cam->queryPending = 1;
}

int camera_query_days(Camera *cam, int year, int month, char **json_out, int timeout_ms){
    if(!cam || !json_out) return -1;
    *json_out = NULL;
    fn_days_t fn = (fn_days_t)cam_sym("getRecordDaysByMonth");
    if(!fn){ st_err("camera SDK: no getRecordDaysByMonth export"); return -1; }

    char key[16];
    snprintf(key, sizeof key, "%04d%02d", year, month);      // "yyyyMM"
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingBaseCallback", cam);
    query_begin(cam);
    jint rc = fn(&g_env, cam_class(), cam->handle, (jstring)jni_mk_string(key), (jobject)cb);
    st_debug("getRecordDaysByMonth(%s) -> %d", key, (int)rc);
    if(rc < 0){ cam->queryPending = 0; st_err("getRecordDaysByMonth rejected (%d)", (int)rc); return -1; }
    return query_wait(cam, json_out, timeout_ms, "record-days query");
}

int camera_query_fragments(Camera *cam, int year, int month, int day, int page,
                           int events, char **json_out, int timeout_ms){
    if(!cam || !json_out) return -1;
    *json_out = NULL;
    // Motion-only listings come from the event variant, which is page-based.
    const char *sym = events ? "getRecordEventFragmentsByDayAndPageId" : "getRecordFragmentsByDay";
    fn_frags_t fn = (fn_frags_t)cam_sym(sym);
    if(!fn){ st_err("camera SDK: no %s export", sym); return -1; }

    char key[16];
    snprintf(key, sizeof key, "%04d%02d%02d", year, month, day);   // "yyyyMMdd"
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingBaseCallback", cam);
    query_begin(cam);
    jint rc = fn(&g_env, cam_class(), cam->handle, (jstring)jni_mk_string(key), (jint)page, (jobject)cb);
    st_debug("%s(%s, page=%d) -> %d", sym, key, page, (int)rc);
    if(rc < 0){ cam->queryPending = 0; st_err("%s rejected (%d)", sym, (int)rc); return -1; }
    return query_wait(cam, json_out, timeout_ms, "record-fragments query");
}

// ThingCameraNative.startPlayBackDownload(handle, start, stop, folder, file,
//                                        thumb, rotation, ?, ThingProgressiveCallback)
typedef jint (*fn_dl_t)(JNIEnv*, jclass, jlong, jint, jint, jstring, jstring, jstring, jint, jint, jobject);

int camera_download(Camera *cam, long long start, long long stop,
                    const char *folder, const char *file_name,
                    int timeout_ms, int *progress_out){
    if(progress_out) *progress_out = 0;
    if(!cam || !folder || !file_name) return -1;
    fn_dl_t fn = (fn_dl_t)cam_sym("startPlayBackDownload");
    if(!fn){ st_err("camera SDK: no startPlayBackDownload export"); return -1; }
    if(mkdir_p(folder) != 0){ st_err("download: cannot create %s", folder); return -1; }

    char dir[512];
    snprintf(dir, sizeof dir, "%s%s", folder, folder[strlen(folder)-1] == '/' ? "" : "/");
    char mp4[256];
    size_t fl = strlen(file_name);
    if(fl > 4 && !strcasecmp(file_name + fl - 4, ".mp4")) snprintf(mp4, sizeof mp4, "%s", file_name);
    else                                                  snprintf(mp4, sizeof mp4, "%s.mp4", file_name);
    char jpg[256];
    snprintf(jpg, sizeof jpg, "%s", mp4);
    size_t jl = strlen(jpg);
    if(jl > 4) memcpy(jpg + jl - 4, ".jpg", 4);

    // The app's playback screen passes these end-first; the native declares
    // (start, stop). OUTDOOR_CAM_SWAP_TIMES flips them so the real order can be
    // settled by experiment rather than assumption.
    jint a = (jint)start, b = (jint)stop;
    if(getenv("OUTDOOR_CAM_SWAP_TIMES")){ jint t = a; a = b; b = t; }

    cam->dlActive = 1; cam->dlDone = 0; cam->dlCode = 0; cam->dlProgress = 0;
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingProgressiveCallback", cam);
    jint rc = fn(&g_env, cam_class(), cam->handle, a, b,
                 (jstring)jni_mk_string(dir), (jstring)jni_mk_string(mp4),
                 (jstring)jni_mk_string(jpg), 0, 0, (jobject)cb);
    st_debug("startPlayBackDownload(%d..%d -> %s%s) -> %d", (int)a, (int)b, dir, mp4, (int)rc);
    if(rc < 0){
        cam->dlActive = 0;
        st_err("the SDK refused the download (%d)", (int)rc);
        return -1;
    }
    snprintf(cam->recPath, sizeof cam->recPath, "%s%s", dir, mp4);

    int waited = 0;
    const int step = 200;
    while(!cam->dlDone && waited < timeout_ms){
        usleep((useconds_t)step * 1000);
        waited += step;
    }
    cam->dlActive = 0;
    if(progress_out) *progress_out = cam->dlProgress;
    if(!cam->dlDone){ st_err("download timed out after %dms (last %d%%)", timeout_ms, cam->dlProgress); return -1; }
    if(cam->dlCode < 0){ st_err("download failed (code %d)", cam->dlCode); return -1; }
    return 0;
}

// startPlayBack(handle, start, stop, playTime, 0, ThingFinishableCallback)
typedef jint (*fn_playback_t)(JNIEnv*, jclass, jlong, jint, jint, jint, jint, jobject);
typedef jint (*fn_stopplayback_t)(JNIEnv*, jclass, jlong, jobject);

int camera_start_playback(Camera *cam, long long start, long long stop, int play_time){
    if(!cam) return -1;
    fn_playback_t fn = (fn_playback_t)cam_sym("startPlayBack");
    if(!fn){ st_err("camera SDK: no startPlayBack export"); return -1; }
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingFinishableCallback", cam);
    // Trailing 0 selects the unencrypted path (1 is the V2/encrypted variant).
    jint rc = fn(&g_env, cam_class(), cam->handle,
                 (jint)start, (jint)stop, (jint)play_time, 0, (jobject)cb);
    st_debug("startPlayBack(%lld..%lld, seek=%d) -> %d", start, stop, play_time, (int)rc);
    return rc >= 0 ? 0 : -1;
}

int camera_stop_playback(Camera *cam){
    if(!cam) return -1;
    fn_stopplayback_t fn = (fn_stopplayback_t)cam_sym("stopPlayBack");
    if(!fn) return -1;
    MockObj *cb = jni_mk_object("com/thingclips/smart/camera/callback/ThingBaseCallback", cam);
    return fn(&g_env, cam_class(), cam->handle, (jobject)cb) >= 0 ? 0 : -1;
}
