#include "native.h"
#include "jni_mock.h"
#include "status.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *g_camera_so, *g_p2p_so, *g_security_so;
static int   g_loaded;

void *native_camera_so(void)  { return g_camera_so; }
void *native_p2p_so(void)     { return g_p2p_so; }
void *native_security_so(void){ return g_security_so; }

// RTLD_GLOBAL so later libs resolve symbols exported by earlier ones.
static void *load_lib(const char *name, int required){
    void *h = dlopen(name, RTLD_NOW | RTLD_GLOBAL);
    if(!h){
        if(required) st_err("dlopen(%s): %s", name, dlerror());
        else         st_debug("dlopen(%s) skipped: %s", name, dlerror());
    } else {
        st_debug("dlopen(%s) ok", name);
    }
    return h;
}

// Read the app signing certificate (DER) and hand it, plus its SHA-256, to the
// JNI mock. Path override: OUTDOOR_CAM_SIGNER_DER.
static void load_app_cert(void){
    const char *path = getenv("OUTDOOR_CAM_SIGNER_DER");
    if(!path || !*path) path = "signer.der";     // staged next to the binary
    FILE *f = fopen(path, "rb");
    if(!f){ st_debug("no signing cert at %s — derived keys will be wrong", path); return; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if(n <= 0 || n > (1 << 20)){ fclose(f); return; }
    unsigned char *der = malloc((size_t)n);
    if(!der){ fclose(f); return; }
    size_t rd = fread(der, 1, (size_t)n, f);
    fclose(f);
    if(rd != (size_t)n){ free(der); return; }

    // SHA-256 over the DER, via the app's own libcrypto (no OpenSSL headers here).
    unsigned char sha[32];
    size_t sha_len = 0;
    void *lc = dlopen("libcrypto.1.1.so", RTLD_NOW | RTLD_GLOBAL);
    unsigned char *(*sha256_fn)(const unsigned char*, size_t, unsigned char*) =
        lc ? (unsigned char *(*)(const unsigned char*, size_t, unsigned char*))dlsym(lc, "SHA256") : NULL;
    if(sha256_fn && sha256_fn(der, (size_t)n, sha)) sha_len = sizeof sha;
    else st_debug("SHA256 unavailable — cert fingerprint not supplied");

    jni_set_app_cert(der, (size_t)n, sha_len ? sha : NULL, sha_len);
    st_debug("signing cert loaded (%ld bytes DER, fingerprint %s)", n, sha_len ? "ok" : "missing");
    free(der);
}

int native_load(void){
    if(g_loaded) return 0;

    // Dependency order: C++ runtime, then codecs/FFmpeg, then crypto, then the
    // Thing SDKs (camera last — it depends on all of them).
    static const char *chain[] = {
        "libc++_shared.so",
        "libavutil.so", "libswresample.so", "libswscale.so",
        "libavcodec.so", "libavformat.so", "libavfilter.so",
        "libyuv.so", "libopenh264.so",
        "libcrypto.1.1.so", "libssl.1.1.so",
        "libmbedcrypto.so",
        "libThingFFmpegWrapper.so", "libThingVideoCodecSDK.so",
        "libThingAvLogSDK.so", "libThingAudioEngineSDK.so",
        NULL
    };
    for(int i = 0; chain[i]; i++) load_lib(chain[i], 0);

    // thing_security powers the Tuya request signing / response decryption.
    g_security_so = load_lib("libthing_security.so", 0);

    g_p2p_so = load_lib("libThingP2PSDK.so", 1);
    if(!g_p2p_so) return -1;

    g_camera_so = load_lib("libThingCameraSDK.so", 1);
    if(!g_camera_so) return -1;

    // Feed the app signing certificate to the JNI mock before any JNI_OnLoad
    // runs: libthing_security hashes it during init and folds the hash into the
    // keys it derives, so it has to be in place first.
    load_app_cert();

    // Run JNI_OnLoad where present so each SDK caches its JavaVM/method IDs.
    struct { const char *name; void *h; } onload[] = {
        { "libThingP2PSDK.so",    g_p2p_so },
        { "libThingCameraSDK.so", g_camera_so },
        { "libthing_security.so", g_security_so },
    };
    for(size_t i = 0; i < sizeof onload / sizeof *onload; i++){
        if(!onload[i].h) continue;
        jint (*fn)(JavaVM*, void*) = (jint(*)(JavaVM*, void*))dlsym(onload[i].h, "JNI_OnLoad");
        if(fn){ jint v = fn(&g_vm, NULL); st_debug("JNI_OnLoad(%s) -> 0x%x", onload[i].name, v); }
    }

    g_loaded = 1;
    return 0;
}

// ---- ThingCameraEngineNative ----------------------------------------------
#define ENG_PREFIX "Java_com_thingclips_smart_camera_nativeapi_ThingCameraEngineNative_"

static void *eng_sym(const char *suffix){
    if(!g_camera_so) return NULL;
    char buf[256];
    snprintf(buf, sizeof buf, ENG_PREFIX "%s", suffix);
    void *p = dlsym(g_camera_so, buf);
    if(!p) st_debug("missing export %s", buf);
    return p;
}

int native_engine_initialize(void){
    jint (*fn)(JNIEnv*, jobject) = (jint(*)(JNIEnv*, jobject))eng_sym("initialize");
    if(!fn){ st_err("libThingCameraSDK: no initialize() export"); return -1; }
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    jint r = fn(&g_env, (jobject)klass);
    st_debug("engine initialize() -> %d", r);
    return (int)r;
}

int native_engine_init_p2p(const char *config_json){
    jint (*fn)(JNIEnv*, jobject, jstring) = (jint(*)(JNIEnv*, jobject, jstring))eng_sym("initP2PModule");
    if(!fn){ st_err("libThingCameraSDK: no initP2PModule() export"); return -1; }
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    jint r = fn(&g_env, (jobject)klass, (jstring)jni_mk_string(config_json ? config_json : "{}"));
    st_debug("engine initP2PModule() -> %d", r);
    return (int)r;
}

int native_engine_deinit_p2p(void){
    jint (*fn)(JNIEnv*, jobject) = (jint(*)(JNIEnv*, jobject))eng_sym("deInitP2PModule");
    if(!fn) return -1;
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    return (int)fn(&g_env, (jobject)klass);
}

int native_engine_deinitialize(void){
    jint (*fn)(JNIEnv*, jobject) = (jint(*)(JNIEnv*, jobject))eng_sym("deInitialize");
    if(!fn) return -1;
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    return (int)fn(&g_env, (jobject)klass);
}

const char *native_engine_version(void){
    jstring (*fn)(JNIEnv*, jobject) = (jstring(*)(JNIEnv*, jobject))eng_sym("getVersion");
    if(!fn) return NULL;
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    MockObj *s = (MockObj*)fn(&g_env, (jobject)klass);
    return s ? s->str : NULL;
}

int native_p2p_init(const char *local_id){
    void *so = native_p2p_so();
    if(!so){ st_err("P2P SDK not loaded"); return -1; }
    jint (*fn)(JNIEnv*, jobject, jstring) =
        (jint(*)(JNIEnv*, jobject, jstring))dlsym(so, "Java_com_thingclips_smart_p2p_p2psdk_ThingP2PSDK_init");
    if(!fn){ st_err("P2P SDK: no init export"); return -1; }
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/p2p/p2psdk/ThingP2PSDK");
    jint r = fn(&g_env, (jobject)klass, (jstring)jni_mk_string(local_id ? local_id : ""));
    st_debug("P2P init(localId=%s) -> %d", local_id ? local_id : "", r);
    return (int)r;
}

int native_engine_set_soft_decode(int on){
    jint (*fn)(JNIEnv*, jobject, jboolean) =
        (jint(*)(JNIEnv*, jobject, jboolean))eng_sym("setSoftDecodeStatus");
    if(!fn){ st_debug("camera SDK: no setSoftDecodeStatus export"); return -1; }
    MockObj *klass = jni_mk(M_CLASS, "com/thingclips/smart/camera/nativeapi/ThingCameraEngineNative");
    jint r = fn(&g_env, (jobject)klass, on ? JNI_TRUE : JNI_FALSE);
    st_debug("setSoftDecodeStatus(%d) -> %d", on, r);
    return (int)r;
}
