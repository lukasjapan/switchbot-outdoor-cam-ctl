// JNIEnv / JavaVM mock for driving the ThingClips native .so's with no JVM.
//
// Freshly written for switchbot-outdoor-cam-ctl (technique mirrors thing_p2p/qemu/p2p_harness.c),
// factored into a module and extended with callback-routing hooks so the media
// layer can service the SDK's listener / result callbacks (which the camera SDK
// invokes back into "Java", unlike the pure-transport P2P harness).
#ifndef OUTDOOR_CAM_JNI_MOCK_H
#define OUTDOOR_CAM_JNI_MOCK_H

#include <jni.h>
#include <stdarg.h>
#include <stdint.h>

// ---- mock object model ----------------------------------------------------
// jclass / jobject / jstring / jbyteArray etc. are all MockObj*; jmethodID /
// jfieldID are MockMember*. The native code only ever pokes these through the
// JNIEnv vtable, so as long as the vtable does the right thing the opaque
// representation is free to be whatever we like.
typedef enum { M_CLASS, M_STRING, M_BYTEARRAY, M_OBJARRAY, M_OBJECT, M_DIRECTBUF } MockKind;
typedef struct MockObj {
    MockKind kind;
    const char *name;      // class name (for M_CLASS / M_OBJECT), or "[B" etc.
    char *str;             // M_STRING payload
    uint8_t *bytes;        // M_BYTEARRAY / M_DIRECTBUF payload
    jsize len;             // length of str/bytes/elems
    struct MockObj **elems;// M_OBJARRAY elements
    void *user;            // free-use tag for handlers (e.g. which callback slot)
} MockObj;
typedef struct { const char *cls, *name, *sig; } MockMember;

MockObj *jni_mk(MockKind k, const char *name);
MockObj *jni_mk_string(const char *s);
MockObj *jni_mk_bytes(const uint8_t *d, jsize n);
MockObj *jni_mk_object(const char *cls, void *user); // tagged object for callbacks

// ---- base64 (shared) ------------------------------------------------------
char    *b64_encode(const uint8_t *in, size_t n);      // caller frees
uint8_t *b64_decode(const char *in, size_t *outlen);   // caller frees
char    *b64s(const char *s);                          // encode a C string

// ---- lifecycle ------------------------------------------------------------
extern JNIEnv  g_env;   // the single shared env handed to every thread
extern JavaVM  g_vm;
extern int     g_verbose;
void jni_mock_init(void);              // build the vtables (call once, first)
void jni_set_local_ip(const char *ip); // answer for onGetDeviceIPAddress

// ---- dynamically registered natives --------------------------------------
// libthing_security installs its natives via RegisterNatives rather than
// exporting Java_* symbols, so the table has to be captured as it registers.
void *jni_find_native(const char *name);   // fnPtr, or NULL
int   jni_native_count(void);

// ---- Android reflection the security lib performs during init -------------
// It walks PackageManager -> PackageInfo.signatures[0].toByteArray() and hashes
// the result, so supply the app's signing certificate (DER) and its SHA-256
// fingerprint; otherwise the derived keys come out wrong and the server rejects
// them. Both are optional — without them init still completes, but the keys are
// not the ones the genuine app would compute.
void jni_set_app_cert(const unsigned char *der, size_t der_len,
                      const unsigned char *sha256, size_t sha_len);

// ---- callback routing -----------------------------------------------------
// The SDK invokes Java callbacks through Call{Void,Object,Int}Method[V]. We
// route them by (method name, self) to a handler the media layer installs. The
// handler reads arguments straight off the va_list per the method's known
// signature. `self->user` carries whatever tag jni_mk_object() was given, so a
// handler can tell which callback instance is firing.
//
// `ap` is a POINTER to the va_list (it is NULL for the JNI ...A variants, which
// pass a jvalue array instead; va_list itself is not a pointer type on aarch64
// so it cannot represent "absent"). Handlers must null-check before reading.
typedef void    (*jni_void_fn)(const char *method, MockObj *self, va_list *ap);
typedef jobject (*jni_obj_fn) (const char *method, MockObj *self, va_list *ap);
typedef jint    (*jni_int_fn) (const char *method, MockObj *self, va_list *ap, int *handled);
void jni_set_void_handler(jni_void_fn fn);
void jni_set_obj_handler(jni_obj_fn fn);
void jni_set_int_handler(jni_int_fn fn);

#define JLOGF(...) do{ if(g_verbose){ fprintf(stderr,"[jni] " __VA_ARGS__); fputc('\n',stderr);} }while(0)

#endif
