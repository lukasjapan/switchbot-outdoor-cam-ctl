// libthing_security bindings — the Tuya ATOP crypto primitives.
//
// The lib registers its natives dynamically (class
// com/thingclips/smart/security/jni/SecureNativeApi), so they are reached via
// the JNI mock's captured RegisterNatives table rather than dlsym. Signatures
// below were read straight off that table:
//
//   doCommandNative     (Landroid/content/Context;I[B[BZ)Ljava/lang/Object;
//   encryptPostData     (Ljava/lang/String;[B)[B
//   getEncryptoKey      (Ljava/lang/String;Ljava/lang/String;)[B
//   genKey              (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
//   computeDigest       (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
//   decryptResponseData (Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
//   getChKey            (Landroid/content/Context;[B)Ljava/lang/String;
//   getConfig           (Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
//   testSign            (Landroid/content/Context;)Ljava/lang/String;
//
// Calling the real lib avoids reimplementing its key derivation (which folds in
// the app signing cert, a steganographic key in t_s.bmp, and a keystream
// transform) — that is exactly why switchbot-outdoor-cam-ctl runs under qemu.
#ifndef OUTDOOR_CAM_SECURITY_H
#define OUTDOOR_CAM_SECURITY_H

#include <stddef.h>

// Run the initialiser: doCommandNative(ctx, 0, appSecret, appKey, false).
// Must be called after native_load(). Returns 0 on success.
int security_init(void);

// Sign an ATOP sign-string: doCommandNative(ctx, 1, signString, null, flag).
// This is the request signature (ThingApiSignManager -> qpppdqb.bdpdqbp), and is
// a different operation from computeDigest.
char *security_sign(const char *sign_string);

// MQTT broker password material: doCommandNative(ctx, 2, ecode, null, false).
// The broker wants only the MIDDLE 16 chars of this (dqqbdqb.qddqppb does
// substring(len/2 - 8, len/2 + 8)); security_mqtt_password_16() applies that.
char *security_mqtt_password_raw(const char *ecode);
char *security_mqtt_password_16(const char *ecode);

// All returned strings are heap-allocated; caller frees. NULL on failure.
char *security_compute_digest(const char *bundle_id, const char *sign_string);
char *security_gen_key(const char *request_id, const char *token, const char *bundle_id);
char *security_decrypt_response(const char *key, const char *result);
char *security_get_ch_key(const char *app_key);
char *security_get_config(const char *a, const char *b);
char *security_test_sign(void);

// Byte-array results: returns malloc'd buffer, sets *out_len. NULL on failure.
unsigned char *security_get_encrypto_key(const char *request_id, const char *ecode, size_t *out_len);
unsigned char *security_encrypt_post_data(const char *request_id,
                                          const unsigned char *data, size_t len,
                                          size_t *out_len);

#endif
