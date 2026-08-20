// Crypto helpers, all resolved from the app's own libcrypto.1.1.so / libz.so at
// runtime (the NDK ships no OpenSSL headers, so prototypes are declared locally).
#ifndef OUTDOOR_CAM_CRYPTO_H
#define OUTDOOR_CAM_CRYPTO_H

#include <stddef.h>

// Lowercase hex MD5 of a string. `out` must hold 33 bytes.
int crypto_md5_hex(const char *s, char out[33]);

// AES-128-GCM, Tuya's AesGcmUtil layout: nonce(12) || ciphertext || tag(16),
// base64-encoded. Returns a malloc'd base64 string (caller frees) or NULL.
char *crypto_aes_gcm_encrypt_b64(const unsigned char key[16], const char *plaintext);

// Inverse: base64 in, plaintext bytes out (malloc'd, NUL-terminated for
// convenience; *out_len excludes the terminator). NULL on failure.
unsigned char *crypto_aes_gcm_decrypt_b64(const unsigned char key[16], const char *b64, size_t *out_len);

// AES-128-ECB (the et="0.0.1" path), base64 in/out.
char *crypto_aes_ecb_encrypt_b64(const unsigned char key[16], const char *plaintext);
unsigned char *crypto_aes_ecb_decrypt_b64(const unsigned char key[16], const char *b64, size_t *out_len);

// AES-128-ECB over raw bytes (the pv-2.2 MQTT control frame body, keyed by the
// device localKey). Both malloc'd; decrypt result is NUL-terminated.
unsigned char *crypto_aes_ecb_encrypt(const unsigned char key[16], const char *plaintext, size_t *out_len);
unsigned char *crypto_aes_ecb_decrypt(const unsigned char key[16], const unsigned char *ct, size_t ct_len, size_t *out_len);

// CRC-32 (zlib polynomial) — used in the pv-2.2 frame header and device wake.
unsigned int crypto_crc32(const unsigned char *buf, size_t len);

// gzip/zlib inflate (auto-detecting). Returns malloc'd buffer or NULL. If the
// input is not compressed, returns a copy so callers can apply it blindly.
unsigned char *crypto_gunzip(const unsigned char *in, size_t in_len, size_t *out_len);

// RSA PKCS#1 v1.5 public encrypt with a raw modulus/exponent (hex or decimal, as
// the Tuya token endpoint returns them). Returns malloc'd lowercase hex.
char *crypto_rsa_encrypt_hex(const char *plaintext, const char *modulus, const char *exponent);

// Base64 of arbitrary bytes (malloc'd).
char *crypto_b64_encode(const unsigned char *in, size_t n);

#endif
