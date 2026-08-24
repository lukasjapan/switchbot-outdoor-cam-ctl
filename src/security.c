#include "security.h"
#include "config.h"
#include "jni_mock.h"
#include "status.h"

#include <stdlib.h>
#include <string.h>

// Native prototypes, per the registered signatures. Every JNI native takes
// (JNIEnv*, jclass) first; `Context` arguments are satisfied with a mock object.
typedef jobject (*fn_doCommand_t)(JNIEnv*, jclass, jobject, jint, jbyteArray, jbyteArray, jboolean);
typedef jbyteArray (*fn_encryptPost_t)(JNIEnv*, jclass, jstring, jbyteArray);
typedef jbyteArray (*fn_getEncKey_t)(JNIEnv*, jclass, jstring, jstring);
typedef jstring (*fn_genKey_t)(JNIEnv*, jclass, jstring, jstring, jstring);
typedef jstring (*fn_digest_t)(JNIEnv*, jclass, jstring, jstring);
typedef jstring (*fn_decrypt_t)(JNIEnv*, jclass, jstring, jstring);
typedef jstring (*fn_chKey_t)(JNIEnv*, jclass, jobject, jbyteArray);
typedef jstring (*fn_getConfig_t)(JNIEnv*, jclass, jobject, jstring, jstring);
typedef jstring (*fn_testSign_t)(JNIEnv*, jclass, jobject);

static int g_inited;

static jclass  sec_class(void){ return (jclass)jni_mk(M_CLASS, "com/thingclips/smart/security/jni/SecureNativeApi"); }
static jobject mock_ctx(void){ return (jobject)jni_mk(M_OBJECT, "android/content/Context"); }

// MockObj strings are NUL-terminated; copy out so callers own the memory.
static char *take_string(jstring s){
    MockObj *m = (MockObj*)s;
    if(!m || !m->str) return NULL;
    return strdup(m->str);
}
static unsigned char *take_bytes(jbyteArray a, size_t *out_len){
    MockObj *m = (MockObj*)a;
    if(!m || !m->bytes || m->len <= 0){ if(out_len) *out_len = 0; return NULL; }
    unsigned char *buf = malloc((size_t)m->len);
    if(!buf){ if(out_len) *out_len = 0; return NULL; }
    memcpy(buf, m->bytes, (size_t)m->len);
    if(out_len) *out_len = (size_t)m->len;
    return buf;
}

int security_init(void){
    if(g_inited) return 0;
    fn_doCommand_t fn = (fn_doCommand_t)jni_find_native("doCommandNative");
    if(!fn){
        st_err("libthing_security: doCommandNative not registered (%d natives seen)", jni_native_count());
        return -1;
    }
    const SbConfig *cfg = sb_config();
    if(!cfg) return -1;
    // op 0 is the initialiser; it seeds the lib's internal key state, which every
    // other primitive depends on.
    MockObj *sec = jni_mk_bytes((const unsigned char*)cfg->tyAppSecret, (jsize)strlen(cfg->tyAppSecret));
    MockObj *key = jni_mk_bytes((const unsigned char*)cfg->tyAppKey,    (jsize)strlen(cfg->tyAppKey));
    jobject r = fn(&g_env, sec_class(), mock_ctx(), 0, (jbyteArray)sec, (jbyteArray)key, JNI_FALSE);
    (void)r;   // returns an opaque status object; failures surface downstream
    g_inited = 1;
    st_debug("libthing_security initialised (%d natives)", jni_native_count());
    return 0;
}

char *security_sign(const char *sign_string){
    fn_doCommand_t fn = (fn_doCommand_t)jni_find_native("doCommandNative");
    if(!fn || !sign_string) return NULL;
    // op 1 = sign over the raw sign-string bytes. The trailing boolean mirrors
    // ThingSmartNetWork's flag; false is the normal (release) path.
    MockObj *in = jni_mk_bytes((const unsigned char*)sign_string, (jsize)strlen(sign_string));
    jobject r = fn(&g_env, sec_class(), mock_ctx(), 1, (jbyteArray)in, NULL, JNI_FALSE);
    return take_string((jstring)r);
}

char *security_mqtt_password_raw(const char *ecode){
    fn_doCommand_t fn = (fn_doCommand_t)jni_find_native("doCommandNative");
    if(!fn || !ecode) return NULL;
    MockObj *in = jni_mk_bytes((const unsigned char*)ecode, (jsize)strlen(ecode));
    jobject r = fn(&g_env, sec_class(), mock_ctx(), 2, (jbyteArray)in, NULL, JNI_FALSE);
    return take_string((jstring)r);
}

char *security_mqtt_password_16(const char *ecode){
    char *raw = security_mqtt_password_raw(ecode);
    if(!raw) return NULL;
    size_t n = strlen(raw);
    if(n < 16){ return raw; }          // too short to slice; hand it back as-is
    size_t mid = n >> 1;
    char *out = malloc(17);
    if(!out){ free(raw); return NULL; }
    memcpy(out, raw + (mid - 8), 16);
    out[16] = 0;
    free(raw);
    return out;
}

char *security_compute_digest(const char *bundle_id, const char *sign_string){
    fn_digest_t fn = (fn_digest_t)jni_find_native("computeDigest");
    if(!fn || !sign_string) return NULL;
    // bundleId may legitimately be null (the app passes null in that case).
    jstring b = bundle_id ? (jstring)jni_mk_string(bundle_id) : NULL;
    return take_string(fn(&g_env, sec_class(), b, (jstring)jni_mk_string(sign_string)));
}

char *security_gen_key(const char *request_id, const char *token, const char *bundle_id){
    fn_genKey_t fn = (fn_genKey_t)jni_find_native("genKey");
    if(!fn) return NULL;
    return take_string(fn(&g_env, sec_class(),
        request_id ? (jstring)jni_mk_string(request_id) : NULL,
        token ? (jstring)jni_mk_string(token) : NULL,
        bundle_id ? (jstring)jni_mk_string(bundle_id) : NULL));
}

char *security_decrypt_response(const char *key, const char *result){
    fn_decrypt_t fn = (fn_decrypt_t)jni_find_native("decryptResponseData");
    if(!fn || !key || !result) return NULL;
    return take_string(fn(&g_env, sec_class(),
        (jstring)jni_mk_string(key), (jstring)jni_mk_string(result)));
}

char *security_get_ch_key(const char *app_key){
    fn_chKey_t fn = (fn_chKey_t)jni_find_native("getChKey");
    if(!fn) return NULL;
    const char *k = app_key;
    if(!k){ const SbConfig *cfg = sb_config(); if(!cfg) return NULL; k = cfg->tyAppKey; }
    return take_string(fn(&g_env, sec_class(), mock_ctx(),
        (jbyteArray)jni_mk_bytes((const unsigned char*)k, (jsize)strlen(k))));
}

char *security_get_config(const char *a, const char *b){
    fn_getConfig_t fn = (fn_getConfig_t)jni_find_native("getConfig");
    if(!fn) return NULL;
    return take_string(fn(&g_env, sec_class(), mock_ctx(),
        a ? (jstring)jni_mk_string(a) : NULL,
        b ? (jstring)jni_mk_string(b) : NULL));
}

char *security_test_sign(void){
    fn_testSign_t fn = (fn_testSign_t)jni_find_native("testSign");
    if(!fn) return NULL;
    return take_string(fn(&g_env, sec_class(), mock_ctx()));
}

unsigned char *security_get_encrypto_key(const char *request_id, const char *ecode, size_t *out_len){
    fn_getEncKey_t fn = (fn_getEncKey_t)jni_find_native("getEncryptoKey");
    if(out_len) *out_len = 0;
    if(!fn || !request_id) return NULL;
    return take_bytes(fn(&g_env, sec_class(),
        (jstring)jni_mk_string(request_id),
        ecode ? (jstring)jni_mk_string(ecode) : NULL), out_len);
}

unsigned char *security_encrypt_post_data(const char *request_id,
                                          const unsigned char *data, size_t len,
                                          size_t *out_len){
    fn_encryptPost_t fn = (fn_encryptPost_t)jni_find_native("encryptPostData");
    if(out_len) *out_len = 0;
    if(!fn || !request_id) return NULL;
    return take_bytes(fn(&g_env, sec_class(),
        (jstring)jni_mk_string(request_id),
        (jbyteArray)jni_mk_bytes(data, (jsize)len)), out_len);
}
