#include "jni_mock.h"
#include "status.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

JNIEnv g_env;
JavaVM g_vm;
int    g_verbose = 0;
static const char *g_local_ip = "0.0.0.0";
void jni_set_local_ip(const char *ip){ if(ip) g_local_ip = ip; }

// ---- mock object model ----------------------------------------------------
MockObj *jni_mk(MockKind k, const char *name){
    MockObj *o = calloc(1, sizeof *o); o->kind = k; o->name = name ? strdup(name) : NULL; return o;
}
MockObj *jni_mk_string(const char *s){
    MockObj *o = jni_mk(M_STRING, "java/lang/String");
    o->str = strdup(s ? s : ""); o->len = (jsize)strlen(o->str); return o;
}
MockObj *jni_mk_bytes(const uint8_t *d, jsize n){
    MockObj *o = jni_mk(M_BYTEARRAY, "[B"); o->len = n;
    o->bytes = calloc(n > 0 ? n : 1, 1); if(d && n > 0) memcpy(o->bytes, d, n); return o;
}
MockObj *jni_mk_object(const char *cls, void *user){
    MockObj *o = jni_mk(M_OBJECT, cls ? cls : "java/lang/Object"); o->user = user; return o;
}
static MockMember *mk_member(const char *c, const char *n, const char *s){
    MockMember *m = calloc(1, sizeof *m); m->cls = c; m->name = n ? strdup(n) : NULL; m->sig = s ? strdup(s) : NULL; return m;
}

// ---- base64 ---------------------------------------------------------------
static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
char *b64_encode(const uint8_t *in, size_t n){
    char *out = malloc(((n + 2) / 3) * 4 + 1); size_t o = 0;
    for(size_t i = 0; i < n; i += 3){
        uint32_t v = in[i] << 16; if(i + 1 < n) v |= in[i+1] << 8; if(i + 2 < n) v |= in[i+2];
        out[o++] = B64[(v>>18)&63]; out[o++] = B64[(v>>12)&63];
        out[o++] = (i+1<n) ? B64[(v>>6)&63] : '='; out[o++] = (i+2<n) ? B64[v&63] : '=';
    }
    out[o] = 0; return out;
}
static int b64v(char c){
    if(c>='A'&&c<='Z') return c-'A'; if(c>='a'&&c<='z') return c-'a'+26;
    if(c>='0'&&c<='9') return c-'0'+52; if(c=='+') return 62; if(c=='/') return 63; return -1;
}
uint8_t *b64_decode(const char *in, size_t *outlen){
    size_t n = strlen(in); uint8_t *out = malloc(n/4*3 + 4); size_t o = 0; int q[4], qi = 0;
    for(size_t i = 0; i < n; i++){
        if(in[i]=='='||in[i]<=' ') continue; int v = b64v(in[i]); if(v < 0) continue; q[qi++] = v;
        if(qi==4){ out[o++]=(q[0]<<2)|(q[1]>>4); out[o++]=((q[1]&15)<<4)|(q[2]>>2); out[o++]=((q[2]&3)<<6)|q[3]; qi=0; }
    }
    if(qi>=2){ out[o++]=(q[0]<<2)|(q[1]>>4); if(qi>=3) out[o++]=((q[1]&15)<<4)|(q[2]>>2); }
    *outlen = o; return out;
}
char *b64s(const char *s){ return b64_encode((const uint8_t*)(s?s:""), s?strlen(s):0); }

// ---- callback handlers (installed by the media layer) ---------------------
static jni_void_fn g_void_fn = NULL;
static jni_obj_fn  g_obj_fn  = NULL;
static jni_int_fn  g_int_fn  = NULL;
void jni_set_void_handler(jni_void_fn fn){ g_void_fn = fn; }
void jni_set_obj_handler (jni_obj_fn  fn){ g_obj_fn  = fn; }
void jni_set_int_handler (jni_int_fn  fn){ g_int_fn  = fn; }

// ---- app signing certificate (for the security lib's integrity check) -----
static unsigned char *g_cert_der; static size_t g_cert_der_len;
static unsigned char  g_cert_sha[32]; static size_t g_cert_sha_len;
void jni_set_app_cert(const unsigned char *der, size_t der_len,
                      const unsigned char *sha256, size_t sha_len){
    free(g_cert_der); g_cert_der = NULL; g_cert_der_len = 0;
    if(der && der_len){
        g_cert_der = malloc(der_len);
        if(g_cert_der){ memcpy(g_cert_der, der, der_len); g_cert_der_len = der_len; }
    }
    g_cert_sha_len = 0;
    if(sha256 && sha_len == sizeof g_cert_sha){
        memcpy(g_cert_sha, sha256, sha_len); g_cert_sha_len = sha_len;
    }
}

// Built-in object-returning callbacks. Covers what the P2P/camera layers need
// plus the reflection libthing_security walks while initialising.
static jobject builtin_obj(const char *method, MockObj *self){
    (void)self;
    if(!method) return NULL;
    if(!strcmp(method,"onGetDeviceIPAddress")) return (jobject)jni_mk_string(g_local_ip);
    if(!strcmp(method,"getPackageName"))       return (jobject)jni_mk_string("com.theswitchbot.switchbot");
    // Package/asset plumbing: hand back correctly-typed placeholder objects.
    if(!strcmp(method,"getPackageManager")) return (jobject)jni_mk(M_OBJECT,"android/content/pm/PackageManager");
    if(!strcmp(method,"getPackageInfo"))    return (jobject)jni_mk(M_OBJECT,"android/content/pm/PackageInfo");
    if(!strcmp(method,"getAssets"))         return (jobject)jni_mk(M_OBJECT,"android/content/res/AssetManager");
    if(!strcmp(method,"getApplicationContext") || !strcmp(method,"getBaseContext"))
        return (jobject)jni_mk(M_OBJECT,"android/content/Context");
    if(!strcmp(method,"getInstance"))          return (jobject)jni_mk(M_OBJECT,"java/lang/Object");
    if(!strcmp(method,"generateCertificate"))  return (jobject)jni_mk(M_OBJECT,"java/security/cert/X509Certificate");
    // Signature.toByteArray() / Certificate.getEncoded() -> the signing cert DER.
    if(!strcmp(method,"getEncoded") || !strcmp(method,"toByteArray")){
        if(g_cert_der && g_cert_der_len) return (jobject)jni_mk_bytes(g_cert_der,(jsize)g_cert_der_len);
        static const uint8_t zero[32] = {0};
        return (jobject)jni_mk_bytes(zero,(jsize)sizeof zero);   // graceful, but wrong keys
    }
    // MessageDigest.digest() over the cert — must be the real fingerprint or the
    // derived chKey will not match what the genuine app produces.
    if(!strcmp(method,"digest")){
        if(g_cert_sha_len == 32) return (jobject)jni_mk_bytes(g_cert_sha,32);
        static const uint8_t zero[32] = {0};
        return (jobject)jni_mk_bytes(zero,(jsize)sizeof zero);
    }
    if(!strcmp(method,"checkStatus")) return NULL;   // integrity callback: benign
    return NULL;
}

static void route_void(MockMember *m, MockObj *self, va_list *ap){
    const char *name = m ? m->name : NULL;
    if(g_void_fn){ g_void_fn(name, self, ap); return; }
    JLOGF("void callback (unhandled): %s", name ? name : "?");
}
static jobject route_obj(MockMember *m, MockObj *self, va_list *ap){
    const char *name = m ? m->name : NULL;
    if(g_obj_fn){ jobject r = g_obj_fn(name, self, ap); if(r) return r; }
    jobject b = builtin_obj(name, self);
    if(b) return b;
    // Never hand back NULL: real Java would either return an object or throw, and
    // the SDK does not null-check every result — returning NULL for a call we do
    // not recognise gets dereferenced and crashes in a worker thread. A generic
    // placeholder keeps it alive and the log names what we stubbed.
    JLOGF("object call '%s' unrecognised -> placeholder", name ? name : "?");
    return (jobject)jni_mk(M_OBJECT, "java/lang/Object");
}
static jint route_int(MockMember *m, MockObj *self, va_list *ap){
    const char *name = m ? m->name : NULL;
    if(g_int_fn){ int handled = 0; jint r = g_int_fn(name, self, ap, &handled); if(handled) return r; }
    return 0;
}

// ---- JNIEnv shims ---------------------------------------------------------
static jint     J_GetVersion(JNIEnv*e){(void)e; return JNI_VERSION_1_6;}
static jclass   J_FindClass(JNIEnv*e,const char*n){(void)e; return (jclass)jni_mk(M_CLASS,n);}
static jclass   J_GetObjectClass(JNIEnv*e,jobject o){(void)e; MockObj*m=(MockObj*)o; return (jclass)jni_mk(M_CLASS,m?m->name:"java/lang/Object");}
static jboolean J_IsInstanceOf(JNIEnv*e,jobject o,jclass c){(void)e;(void)o;(void)c; return JNI_TRUE;}
static jboolean J_IsSameObject(JNIEnv*e,jobject a,jobject b){(void)e; return a==b;}
static jmethodID J_GetMethodID(JNIEnv*e,jclass c,const char*n,const char*s){(void)e; MockObj*m=(MockObj*)c; return (jmethodID)mk_member(m?m->name:NULL,n,s);}
static jmethodID J_GetStaticMethodID(JNIEnv*e,jclass c,const char*n,const char*s){ return J_GetMethodID(e,c,n,s);}
static jfieldID  J_GetFieldID(JNIEnv*e,jclass c,const char*n,const char*s){(void)e; MockObj*m=(MockObj*)c; return (jfieldID)mk_member(m?m->name:NULL,n,s);}
static jfieldID  J_GetStaticFieldID(JNIEnv*e,jclass c,const char*n,const char*s){ return J_GetFieldID(e,c,n,s);}
static jobject   J_GetObjectField(JNIEnv*e,jobject o,jfieldID f){
    (void)e;(void)o;
    MockMember *m = (MockMember*)f;
    // PackageInfo.signatures -> Signature[1]; the lib then calls toByteArray()
    // on element 0, which builtin_obj answers with the cert DER.
    if(m && m->name && !strcmp(m->name,"signatures")){
        MockObj *arr = jni_mk(M_OBJARRAY,"[Landroid/content/pm/Signature;");
        arr->len = 1;
        arr->elems = calloc(1, sizeof(MockObj*));
        if(arr->elems) arr->elems[0] = jni_mk(M_OBJECT,"android/content/pm/Signature");
        return (jobject)arr;
    }
    return (jobject)jni_mk(M_OBJECT,"java/lang/Object");
}
static jobject   J_GetStaticObjectField(JNIEnv*e,jclass c,jfieldID f){ return J_GetObjectField(e,(jobject)c,f);}
// Field accessors. Every vtable slot the SDK might touch has to be populated:
// an unimplemented slot is a NULL function pointer, and the SDK calling it
// segfaults. Frame delivery in particular constructs a video-frame object and
// fills it in with Set*Field, so the setters matter even though we ignore them.
static jint      J_GetIntField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jboolean  J_GetBooleanField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return JNI_FALSE;}
static jbyte     J_GetByteField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jchar     J_GetCharField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jshort    J_GetShortField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jlong     J_GetLongField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jfloat    J_GetFloatField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static jdouble   J_GetDoubleField(JNIEnv*e,jobject o,jfieldID f){(void)e;(void)o;(void)f; return 0;}
static void J_SetObjectField(JNIEnv*e,jobject o,jfieldID f,jobject v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetBooleanField(JNIEnv*e,jobject o,jfieldID f,jboolean v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetByteField(JNIEnv*e,jobject o,jfieldID f,jbyte v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetCharField(JNIEnv*e,jobject o,jfieldID f,jchar v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetShortField(JNIEnv*e,jobject o,jfieldID f,jshort v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetIntField(JNIEnv*e,jobject o,jfieldID f,jint v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetLongField(JNIEnv*e,jobject o,jfieldID f,jlong v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetFloatField(JNIEnv*e,jobject o,jfieldID f,jfloat v){(void)e;(void)o;(void)f;(void)v;}
static void J_SetDoubleField(JNIEnv*e,jobject o,jfieldID f,jdouble v){(void)e;(void)o;(void)f;(void)v;}
static jint J_GetStaticIntField(JNIEnv*e,jclass c,jfieldID f){(void)e;(void)c;(void)f; return 0;}
static jlong J_GetStaticLongField(JNIEnv*e,jclass c,jfieldID f){(void)e;(void)c;(void)f; return 0;}
static jboolean J_GetStaticBooleanField(JNIEnv*e,jclass c,jfieldID f){(void)e;(void)c;(void)f; return JNI_FALSE;}
static void J_SetStaticObjectField(JNIEnv*e,jclass c,jfieldID f,jobject v){(void)e;(void)c;(void)f;(void)v;}
static void J_SetStaticIntField(JNIEnv*e,jclass c,jfieldID f,jint v){(void)e;(void)c;(void)f;(void)v;}
static void J_SetStaticLongField(JNIEnv*e,jclass c,jfieldID f,jlong v){(void)e;(void)c;(void)f;(void)v;}

// Remaining Call*Method return types.
static jbyte   J_CallByteMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}
static jchar   J_CallCharMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}
static jshort  J_CallShortMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}
static jfloat  J_CallFloatMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}
static jdouble J_CallDoubleMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}
static jboolean J_CallBooleanMethodV(JNIEnv*e,jobject o,jmethodID m,va_list a){(void)e;(void)o;(void)m;(void)a; return JNI_FALSE;}
static jlong    J_CallLongMethodV(JNIEnv*e,jobject o,jmethodID m,va_list a){(void)e;(void)o;(void)m;(void)a; return 0;}
static jint     J_CallStaticIntMethod(JNIEnv*e,jclass c,jmethodID m,...){(void)e;(void)c;(void)m; return 0;}
static jboolean J_CallStaticBooleanMethod(JNIEnv*e,jclass c,jmethodID m,...){(void)e;(void)c;(void)m; return JNI_FALSE;}
static jlong    J_CallStaticLongMethod(JNIEnv*e,jclass c,jmethodID m,...){(void)e;(void)c;(void)m; return 0;}

// Strings / arrays the SDK may reach for while shuttling frames.
static jstring J_NewString(JNIEnv*e,const jchar*u,jsize n){(void)e;(void)u;(void)n; return (jstring)jni_mk_string("");}
static const jchar *J_GetStringChars(JNIEnv*e,jstring s,jboolean*ic){(void)e;(void)s; if(ic)*ic=JNI_FALSE; static const jchar z=0; return &z;}
static void J_ReleaseStringChars(JNIEnv*e,jstring s,const jchar*c){(void)e;(void)s;(void)c;}
static jclass J_GetSuperclass(JNIEnv*e,jclass c){(void)e;(void)c; return (jclass)jni_mk(M_CLASS,"java/lang/Object");}
static jboolean J_IsAssignableFrom(JNIEnv*e,jclass a,jclass b){(void)e;(void)a;(void)b; return JNI_TRUE;}
static jobject J_AllocObject(JNIEnv*e,jclass c){(void)e; MockObj*m=(MockObj*)c; return (jobject)jni_mk(M_OBJECT,m?m->name:"java/lang/Object");}
static jintArray J_NewIntArray(JNIEnv*e,jsize n){(void)e; MockObj*o=jni_mk(M_BYTEARRAY,"[I"); o->len=n; o->bytes=calloc((size_t)(n>0?n:1)*4,1); return (jintArray)o;}
static jint *J_GetIntArrayElements(JNIEnv*e,jintArray a,jboolean*ic){(void)e; if(ic)*ic=JNI_FALSE; MockObj*m=(MockObj*)a; return (jint*)(m?m->bytes:NULL);}
static void J_ReleaseIntArrayElements(JNIEnv*e,jintArray a,jint*p,jint md){(void)e;(void)a;(void)p;(void)md;}
static void J_GetIntArrayRegion(JNIEnv*e,jintArray a,jsize st,jsize len,jint*buf){(void)e; MockObj*m=(MockObj*)a; if(m&&m->bytes&&buf) memcpy(buf,m->bytes+(size_t)st*4,(size_t)len*4);}
static void J_SetIntArrayRegion(JNIEnv*e,jintArray a,jsize st,jsize len,const jint*buf){(void)e; MockObj*m=(MockObj*)a; if(m&&m->bytes&&buf) memcpy(m->bytes+(size_t)st*4,buf,(size_t)len*4);}
static void *J_GetPrimitiveArrayCritical(JNIEnv*e,jarray a,jboolean*ic){(void)e; if(ic)*ic=JNI_FALSE; MockObj*m=(MockObj*)a; return m?m->bytes:NULL;}
static void J_ReleasePrimitiveArrayCritical(JNIEnv*e,jarray a,void*p,jint md){(void)e;(void)a;(void)p;(void)md;}
static jobjectRefType J_GetObjectRefType(JNIEnv*e,jobject o){(void)e;(void)o; return JNILocalRefType;}

static jobject J_CallObjectMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e; va_list a; va_start(a,m); jobject r=route_obj((MockMember*)m,(MockObj*)o,&a); va_end(a); return r;}
static jobject J_CallObjectMethodV(JNIEnv*e,jobject o,jmethodID m,va_list a){(void)e; return route_obj((MockMember*)m,(MockObj*)o,&a);}
static jobject J_CallObjectMethodA(JNIEnv*e,jobject o,jmethodID m,const jvalue*a){(void)e;(void)a; return route_obj((MockMember*)m,(MockObj*)o,NULL);}
static jobject J_CallStaticObjectMethod(JNIEnv*e,jclass c,jmethodID m,...){(void)e; va_list a; va_start(a,m); jobject r=route_obj((MockMember*)m,(MockObj*)c,&a); va_end(a); return r;}
static jobject J_CallStaticObjectMethodV(JNIEnv*e,jclass c,jmethodID m,va_list a){(void)e; return route_obj((MockMember*)m,(MockObj*)c,&a);}
static jobject J_CallStaticObjectMethodA(JNIEnv*e,jclass c,jmethodID m,const jvalue*a){(void)e;(void)a; return route_obj((MockMember*)m,(MockObj*)c,NULL);}
static void J_CallVoidMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e; va_list a; va_start(a,m); route_void((MockMember*)m,(MockObj*)o,&a); va_end(a);}
static void J_CallVoidMethodV(JNIEnv*e,jobject o,jmethodID m,va_list a){(void)e; route_void((MockMember*)m,(MockObj*)o,&a);}
static void J_CallVoidMethodA(JNIEnv*e,jobject o,jmethodID m,const jvalue*a){(void)e;(void)a; route_void((MockMember*)m,(MockObj*)o,NULL);}
static void J_CallStaticVoidMethod(JNIEnv*e,jclass c,jmethodID m,...){(void)e; va_list a; va_start(a,m); route_void((MockMember*)m,(MockObj*)c,&a); va_end(a);}
static void J_CallStaticVoidMethodV(JNIEnv*e,jclass c,jmethodID m,va_list a){(void)e; route_void((MockMember*)m,(MockObj*)c,&a);}
static void J_CallStaticVoidMethodA(JNIEnv*e,jclass c,jmethodID m,const jvalue*a){(void)e;(void)a; route_void((MockMember*)m,(MockObj*)c,NULL);}
static jint J_CallIntMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e; va_list a; va_start(a,m); jint r=route_int((MockMember*)m,(MockObj*)o,&a); va_end(a); return r;}
static jint J_CallIntMethodV(JNIEnv*e,jobject o,jmethodID m,va_list a){(void)e; return route_int((MockMember*)m,(MockObj*)o,&a);}
static jint J_CallIntMethodA(JNIEnv*e,jobject o,jmethodID m,const jvalue*a){(void)e;(void)a; return route_int((MockMember*)m,(MockObj*)o,NULL);}
static jboolean J_CallBooleanMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return JNI_FALSE;}
static jlong J_CallLongMethod(JNIEnv*e,jobject o,jmethodID m,...){(void)e;(void)o;(void)m; return 0;}

static jobject J_NewObject(JNIEnv*e,jclass c,jmethodID m,...){(void)e;(void)m; MockObj*mm=(MockObj*)c; return (jobject)jni_mk(M_OBJECT,mm?mm->name:"java/lang/Object");}
static jobject J_NewObjectV(JNIEnv*e,jclass c,jmethodID m,va_list a){(void)a; return J_NewObject(e,c,m);}
static jobject J_NewObjectA(JNIEnv*e,jclass c,jmethodID m,const jvalue*a){(void)a; return J_NewObject(e,c,m);}
static jstring J_NewStringUTF(JNIEnv*e,const char*s){(void)e; return (jstring)jni_mk_string(s);}
static const char *J_GetStringUTFChars(JNIEnv*e,jstring s,jboolean*ic){(void)e; if(ic)*ic=JNI_FALSE; MockObj*m=(MockObj*)s; return m&&m->str?m->str:"";}
static void J_ReleaseStringUTFChars(JNIEnv*e,jstring s,const char*c){(void)e;(void)s;(void)c;}
static jsize J_GetStringUTFLength(JNIEnv*e,jstring s){(void)e; MockObj*m=(MockObj*)s; return m?m->len:0;}
static jsize J_GetStringLength(JNIEnv*e,jstring s){ return J_GetStringUTFLength(e,s);}
static jsize J_GetArrayLength(JNIEnv*e,jarray a){(void)e; MockObj*m=(MockObj*)a; return m?m->len:0;}
static jbyteArray J_NewByteArray(JNIEnv*e,jsize n){(void)e; return (jbyteArray)jni_mk_bytes(NULL,n);}
static jbyte *J_GetByteArrayElements(JNIEnv*e,jbyteArray a,jboolean*ic){(void)e; if(ic)*ic=JNI_FALSE; MockObj*m=(MockObj*)a; return (jbyte*)(m?m->bytes:NULL);}
static void J_ReleaseByteArrayElements(JNIEnv*e,jbyteArray a,jbyte*p,jint md){(void)e;(void)a;(void)p;(void)md;}
static void J_GetByteArrayRegion(JNIEnv*e,jbyteArray a,jsize st,jsize len,jbyte*buf){(void)e; MockObj*m=(MockObj*)a; if(m&&m->bytes&&buf&&st+len<=m->len)memcpy(buf,m->bytes+st,len);}
static void J_SetByteArrayRegion(JNIEnv*e,jbyteArray a,jsize st,jsize len,const jbyte*buf){(void)e; MockObj*m=(MockObj*)a; if(m&&m->bytes&&buf&&st+len<=m->len)memcpy(m->bytes+st,buf,len);}
static jobjectArray J_NewObjectArray(JNIEnv*e,jsize n,jclass c,jobject init){(void)e;(void)c; MockObj*a=jni_mk(M_OBJARRAY,"[Ljava/lang/Object;"); a->len=n; a->elems=calloc(n>0?n:1,sizeof(MockObj*)); for(jsize i=0;i<n;i++)a->elems[i]=(MockObj*)init; return (jobjectArray)a;}
static jobject J_GetObjectArrayElement(JNIEnv*e,jobjectArray a,jsize i){(void)e; MockObj*m=(MockObj*)a; if(m&&m->elems&&i<m->len)return (jobject)m->elems[i]; return NULL;}
static void J_SetObjectArrayElement(JNIEnv*e,jobjectArray a,jsize i,jobject v){(void)e; MockObj*m=(MockObj*)a; if(m&&m->elems&&i<m->len)m->elems[i]=(MockObj*)v;}
static jobject J_NewDirectByteBuffer(JNIEnv*e,void*addr,jlong cap){(void)e; MockObj*o=jni_mk(M_DIRECTBUF,"java/nio/ByteBuffer"); o->bytes=(uint8_t*)addr; o->len=(jsize)cap; return (jobject)o;}
static void *J_GetDirectBufferAddress(JNIEnv*e,jobject b){(void)e; MockObj*m=(MockObj*)b; return m?m->bytes:NULL;}
static jlong J_GetDirectBufferCapacity(JNIEnv*e,jobject b){(void)e; MockObj*m=(MockObj*)b; return m?m->len:0;}
static jobject J_NewGlobalRef(JNIEnv*e,jobject o){(void)e; return o;}
static jobject J_NewLocalRef(JNIEnv*e,jobject o){(void)e; return o;}
static void J_DeleteRef(JNIEnv*e,jobject o){(void)e;(void)o;}
static jint J_ThrowNew(JNIEnv*e,jclass c,const char*msg){(void)e;(void)c; JLOGF("ThrowNew: %s",msg?msg:""); return 0;}
static jint J_Throw(JNIEnv*e,jthrowable t){(void)e;(void)t; return 0;}
static jthrowable J_ExceptionOccurred(JNIEnv*e){(void)e; return NULL;}
static void J_ExceptionClear(JNIEnv*e){(void)e;}
static void J_ExceptionDescribe(JNIEnv*e){(void)e;}
static jboolean J_ExceptionCheck(JNIEnv*e){(void)e; return JNI_FALSE;}
static jint J_GetJavaVM(JNIEnv*e,JavaVM**vm){(void)e; *vm=&g_vm; return JNI_OK;}
static jint J_EnsureLocalCapacity(JNIEnv*e,jint n){(void)e;(void)n; return 0;}
static jint J_PushLocalFrame(JNIEnv*e,jint n){(void)e;(void)n; return 0;}
static jobject J_PopLocalFrame(JNIEnv*e,jobject r){(void)e; return r;}
static jint J_MonitorEnter(JNIEnv*e,jobject o){(void)e;(void)o; return 0;}
static jint J_MonitorExit(JNIEnv*e,jobject o){(void)e;(void)o; return 0;}
// Capture the natives a library installs dynamically (libthing_security does
// this instead of exporting Java_* symbols), so they can be called by name.
#define MAX_NATIVES 64
static struct { char name[64]; char sig[128]; void *fn; } g_natives[MAX_NATIVES];
static int g_native_count;

void *jni_find_native(const char *name){
    if(!name) return NULL;
    for(int i = 0; i < g_native_count; i++)
        if(!strcmp(g_natives[i].name, name)) return g_natives[i].fn;
    return NULL;
}
int jni_native_count(void){ return g_native_count; }

static jint J_RegisterNatives(JNIEnv*e,jclass c,const JNINativeMethod*m,jint n){
    (void)e;
    MockObj *cls = (MockObj*)c;
    JLOGF("RegisterNatives on %s: %d methods", cls && cls->name ? cls->name : "?", n);
    for(jint i = 0; i < n && g_native_count < MAX_NATIVES; i++){
        if(!m[i].name) continue;
        snprintf(g_natives[g_native_count].name, sizeof g_natives[g_native_count].name, "%s", m[i].name);
        snprintf(g_natives[g_native_count].sig,  sizeof g_natives[g_native_count].sig,  "%s", m[i].signature ? m[i].signature : "");
        g_natives[g_native_count].fn = m[i].fnPtr;
        JLOGF("  [%d] %-24s %-32s -> %p", i, m[i].name, m[i].signature ? m[i].signature : "", m[i].fnPtr);
        g_native_count++;
    }
    return JNI_OK;
}

static jint VM_GetEnv(JavaVM*vm,void**pe,jint v){(void)vm;(void)v; *pe=&g_env; return JNI_OK;}
static jint VM_AttachCurrentThread(JavaVM*vm,JNIEnv**pe,void*a){(void)vm;(void)a; *pe=&g_env; return JNI_OK;}
static jint VM_AttachCurrentThreadAsDaemon(JavaVM*vm,JNIEnv**pe,void*a){ return VM_AttachCurrentThread(vm,pe,a);}
static jint VM_DetachCurrentThread(JavaVM*vm){(void)vm; return JNI_OK;}
static jint VM_DestroyJavaVM(JavaVM*vm){(void)vm; return JNI_OK;}

// Catch-all for JNIEnv slots we have not implemented. Returning 0 keeps the SDK
// moving for the incidental bookkeeping calls; the warning tells us if something
// load-bearing is missing.
static jint J_Unimplemented(JNIEnv *e, ...){
    (void)e;
    static int warned;
    if(!warned){ warned = 1; st_warn("an unimplemented JNI function was called (returning 0)"); }
    return 0;
}

static struct JNINativeInterface g_jni_table;
static struct JNIInvokeInterface g_vm_table;
void jni_mock_init(void){
    memset(&g_jni_table,0,sizeof g_jni_table);
    g_jni_table.GetVersion=J_GetVersion; g_jni_table.FindClass=J_FindClass; g_jni_table.GetObjectClass=J_GetObjectClass;
    g_jni_table.IsInstanceOf=J_IsInstanceOf; g_jni_table.IsSameObject=J_IsSameObject;
    g_jni_table.GetMethodID=J_GetMethodID; g_jni_table.GetStaticMethodID=J_GetStaticMethodID;
    g_jni_table.GetFieldID=J_GetFieldID; g_jni_table.GetStaticFieldID=J_GetStaticFieldID;
    g_jni_table.GetObjectField=J_GetObjectField; g_jni_table.GetStaticObjectField=J_GetStaticObjectField;
    g_jni_table.GetIntField=J_GetIntField; g_jni_table.GetBooleanField=J_GetBooleanField;
    g_jni_table.GetByteField=J_GetByteField; g_jni_table.GetCharField=J_GetCharField;
    g_jni_table.GetShortField=J_GetShortField; g_jni_table.GetLongField=J_GetLongField;
    g_jni_table.GetFloatField=J_GetFloatField; g_jni_table.GetDoubleField=J_GetDoubleField;
    g_jni_table.SetObjectField=J_SetObjectField; g_jni_table.SetBooleanField=J_SetBooleanField;
    g_jni_table.SetByteField=J_SetByteField; g_jni_table.SetCharField=J_SetCharField;
    g_jni_table.SetShortField=J_SetShortField; g_jni_table.SetIntField=J_SetIntField;
    g_jni_table.SetLongField=J_SetLongField; g_jni_table.SetFloatField=J_SetFloatField;
    g_jni_table.SetDoubleField=J_SetDoubleField;
    g_jni_table.GetStaticIntField=J_GetStaticIntField; g_jni_table.GetStaticLongField=J_GetStaticLongField;
    g_jni_table.GetStaticBooleanField=J_GetStaticBooleanField;
    g_jni_table.SetStaticObjectField=J_SetStaticObjectField;
    g_jni_table.SetStaticIntField=J_SetStaticIntField; g_jni_table.SetStaticLongField=J_SetStaticLongField;
    g_jni_table.CallByteMethod=J_CallByteMethod; g_jni_table.CallCharMethod=J_CallCharMethod;
    g_jni_table.CallShortMethod=J_CallShortMethod; g_jni_table.CallFloatMethod=J_CallFloatMethod;
    g_jni_table.CallDoubleMethod=J_CallDoubleMethod;
    g_jni_table.CallBooleanMethodV=J_CallBooleanMethodV; g_jni_table.CallLongMethodV=J_CallLongMethodV;
    g_jni_table.CallStaticIntMethod=J_CallStaticIntMethod;
    g_jni_table.CallStaticBooleanMethod=J_CallStaticBooleanMethod;
    g_jni_table.CallStaticLongMethod=J_CallStaticLongMethod;
    g_jni_table.NewString=J_NewString; g_jni_table.GetStringChars=J_GetStringChars;
    g_jni_table.ReleaseStringChars=J_ReleaseStringChars;
    g_jni_table.GetSuperclass=J_GetSuperclass; g_jni_table.IsAssignableFrom=J_IsAssignableFrom;
    g_jni_table.AllocObject=J_AllocObject;
    g_jni_table.NewIntArray=J_NewIntArray; g_jni_table.GetIntArrayElements=J_GetIntArrayElements;
    g_jni_table.ReleaseIntArrayElements=J_ReleaseIntArrayElements;
    g_jni_table.GetIntArrayRegion=J_GetIntArrayRegion; g_jni_table.SetIntArrayRegion=J_SetIntArrayRegion;
    g_jni_table.GetPrimitiveArrayCritical=J_GetPrimitiveArrayCritical;
    g_jni_table.ReleasePrimitiveArrayCritical=J_ReleasePrimitiveArrayCritical;
    g_jni_table.GetObjectRefType=J_GetObjectRefType;
    g_jni_table.CallObjectMethod=J_CallObjectMethod; g_jni_table.CallObjectMethodV=J_CallObjectMethodV; g_jni_table.CallObjectMethodA=J_CallObjectMethodA;
    g_jni_table.CallStaticObjectMethod=J_CallStaticObjectMethod; g_jni_table.CallStaticObjectMethodV=J_CallStaticObjectMethodV; g_jni_table.CallStaticObjectMethodA=J_CallStaticObjectMethodA;
    g_jni_table.CallVoidMethod=J_CallVoidMethod; g_jni_table.CallVoidMethodV=J_CallVoidMethodV; g_jni_table.CallVoidMethodA=J_CallVoidMethodA;
    g_jni_table.CallStaticVoidMethod=J_CallStaticVoidMethod; g_jni_table.CallStaticVoidMethodV=J_CallStaticVoidMethodV; g_jni_table.CallStaticVoidMethodA=J_CallStaticVoidMethodA;
    g_jni_table.CallIntMethod=J_CallIntMethod; g_jni_table.CallIntMethodV=J_CallIntMethodV; g_jni_table.CallIntMethodA=J_CallIntMethodA;
    g_jni_table.CallBooleanMethod=J_CallBooleanMethod; g_jni_table.CallLongMethod=J_CallLongMethod;
    g_jni_table.NewObject=J_NewObject; g_jni_table.NewObjectV=J_NewObjectV; g_jni_table.NewObjectA=J_NewObjectA;
    g_jni_table.NewStringUTF=J_NewStringUTF; g_jni_table.GetStringUTFChars=J_GetStringUTFChars; g_jni_table.ReleaseStringUTFChars=J_ReleaseStringUTFChars;
    g_jni_table.GetStringUTFLength=J_GetStringUTFLength; g_jni_table.GetStringLength=J_GetStringLength;
    g_jni_table.GetArrayLength=J_GetArrayLength; g_jni_table.NewByteArray=J_NewByteArray;
    g_jni_table.GetByteArrayElements=J_GetByteArrayElements; g_jni_table.ReleaseByteArrayElements=J_ReleaseByteArrayElements;
    g_jni_table.GetByteArrayRegion=J_GetByteArrayRegion; g_jni_table.SetByteArrayRegion=J_SetByteArrayRegion;
    g_jni_table.NewObjectArray=J_NewObjectArray; g_jni_table.GetObjectArrayElement=J_GetObjectArrayElement; g_jni_table.SetObjectArrayElement=J_SetObjectArrayElement;
    g_jni_table.NewDirectByteBuffer=J_NewDirectByteBuffer; g_jni_table.GetDirectBufferAddress=J_GetDirectBufferAddress; g_jni_table.GetDirectBufferCapacity=J_GetDirectBufferCapacity;
    g_jni_table.NewGlobalRef=J_NewGlobalRef; g_jni_table.NewLocalRef=J_NewLocalRef; g_jni_table.DeleteGlobalRef=J_DeleteRef; g_jni_table.DeleteLocalRef=J_DeleteRef;
    g_jni_table.Throw=J_Throw; g_jni_table.ThrowNew=J_ThrowNew; g_jni_table.ExceptionOccurred=J_ExceptionOccurred;
    g_jni_table.ExceptionClear=J_ExceptionClear; g_jni_table.ExceptionDescribe=J_ExceptionDescribe; g_jni_table.ExceptionCheck=J_ExceptionCheck;
    g_jni_table.RegisterNatives=J_RegisterNatives; g_jni_table.GetJavaVM=J_GetJavaVM;
    g_jni_table.EnsureLocalCapacity=J_EnsureLocalCapacity; g_jni_table.PushLocalFrame=J_PushLocalFrame; g_jni_table.PopLocalFrame=J_PopLocalFrame;
    g_jni_table.MonitorEnter=J_MonitorEnter; g_jni_table.MonitorExit=J_MonitorExit;
    // Anything still unset would be a NULL function pointer, and the SDK calling
    // one segfaults with no clue as to which. Backfill every remaining slot with
    // a stub that logs instead of crashing: an unimplemented JNI call then shows
    // up as a warning we can chase, rather than a null dereference in a worker
    // thread. (Integer/pointer returns come back 0; that is fine for the
    // bookkeeping calls the SDK makes while shuttling frames.)
    {
        void **slots = (void**)&g_jni_table;
        size_t n = sizeof g_jni_table / sizeof(void*);
        size_t filled = 0;
        for(size_t i = 0; i < n; i++){
            if(!slots[i]){ slots[i] = (void*)(uintptr_t)J_Unimplemented; filled++; }
        }
        JLOGF("JNIEnv: %zu/%zu slots backfilled with the safety stub", filled, n);
    }
    g_env = &g_jni_table;
    memset(&g_vm_table,0,sizeof g_vm_table);
    g_vm_table.GetEnv=VM_GetEnv; g_vm_table.AttachCurrentThread=VM_AttachCurrentThread;
    g_vm_table.AttachCurrentThreadAsDaemon=VM_AttachCurrentThreadAsDaemon;
    g_vm_table.DetachCurrentThread=VM_DetachCurrentThread; g_vm_table.DestroyJavaVM=VM_DestroyJavaVM;
    g_vm = &g_vm_table;
}
