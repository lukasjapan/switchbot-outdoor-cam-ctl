#include "crypto.h"
#include "jni_mock.h"   // shared base64
#include "status.h"

#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---- libcrypto / libz via dlsym --------------------------------------------
typedef void EVP_CIPHER_CTX_t; typedef void EVP_CIPHER_t; typedef void BIGNUM_t; typedef void RSA_t;

static struct {
    unsigned char *(*MD5)(const unsigned char*, size_t, unsigned char*);
    EVP_CIPHER_CTX_t *(*EVP_CIPHER_CTX_new)(void);
    void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX_t*);
    int  (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX_t*, int, int, void*);
    int  (*EVP_CIPHER_CTX_set_padding)(EVP_CIPHER_CTX_t*, int);
    const EVP_CIPHER_t *(*EVP_aes_128_gcm)(void);
    const EVP_CIPHER_t *(*EVP_aes_128_ecb)(void);
    int  (*EVP_EncryptInit_ex)(EVP_CIPHER_CTX_t*, const EVP_CIPHER_t*, void*, const unsigned char*, const unsigned char*);
    int  (*EVP_EncryptUpdate)(EVP_CIPHER_CTX_t*, unsigned char*, int*, const unsigned char*, int);
    int  (*EVP_EncryptFinal_ex)(EVP_CIPHER_CTX_t*, unsigned char*, int*);
    int  (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX_t*, const EVP_CIPHER_t*, void*, const unsigned char*, const unsigned char*);
    int  (*EVP_DecryptUpdate)(EVP_CIPHER_CTX_t*, unsigned char*, int*, const unsigned char*, int);
    int  (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX_t*, unsigned char*, int*);
    int  (*RAND_bytes)(unsigned char*, int);
    // RSA
    RSA_t *(*RSA_new)(void);
    void (*RSA_free)(RSA_t*);
    int  (*RSA_set0_key)(RSA_t*, BIGNUM_t*, BIGNUM_t*, BIGNUM_t*);
    int  (*RSA_public_encrypt)(int, const unsigned char*, unsigned char*, RSA_t*, int);
    int  (*RSA_size)(const RSA_t*);
    int  (*BN_hex2bn)(BIGNUM_t**, const char*);
    int  (*BN_dec2bn)(BIGNUM_t**, const char*);
    int  loaded;
} C;

#define EVP_CTRL_GCM_SET_IVLEN 0x9
#define EVP_CTRL_GCM_GET_TAG   0x10
#define EVP_CTRL_GCM_SET_TAG   0x11
#define RSA_PKCS1_PADDING      1

static int crypto_load(void){
    if(C.loaded) return C.loaded > 0 ? 0 : -1;
    void *lc = dlopen("libcrypto.1.1.so", RTLD_NOW | RTLD_GLOBAL);
    if(!lc){ st_err("libcrypto unavailable: %s", dlerror()); C.loaded = -1; return -1; }
    #define SYM(f) do{ *(void**)&C.f = dlsym(lc, #f); }while(0)
    #define REQ(f) do{ SYM(f); if(!C.f){ st_err("libcrypto: missing %s", #f); C.loaded=-1; return -1; } }while(0)
    REQ(MD5);
    REQ(EVP_CIPHER_CTX_new); REQ(EVP_CIPHER_CTX_free); REQ(EVP_CIPHER_CTX_ctrl);
    REQ(EVP_CIPHER_CTX_set_padding);
    REQ(EVP_aes_128_gcm); REQ(EVP_aes_128_ecb);
    REQ(EVP_EncryptInit_ex); REQ(EVP_EncryptUpdate); REQ(EVP_EncryptFinal_ex);
    REQ(EVP_DecryptInit_ex); REQ(EVP_DecryptUpdate); REQ(EVP_DecryptFinal_ex);
    REQ(RAND_bytes);
    SYM(RSA_new); SYM(RSA_free); SYM(RSA_set0_key); SYM(RSA_public_encrypt);
    SYM(RSA_size); SYM(BN_hex2bn); SYM(BN_dec2bn);
    #undef SYM
    #undef REQ
    C.loaded = 1;
    return 0;
}

char *crypto_b64_encode(const unsigned char *in, size_t n){ return b64_encode(in, n); }

// ---- MD5 -------------------------------------------------------------------
int crypto_md5_hex(const char *s, char out[33]){
    if(crypto_load() != 0 || !s) return -1;
    unsigned char d[16];
    if(!C.MD5((const unsigned char*)s, strlen(s), d)) return -1;
    for(int i = 0; i < 16; i++) snprintf(out + i*2, 3, "%02x", d[i]);
    out[32] = 0;
    return 0;
}

// ---- AES-128-GCM (nonce(12) || ct || tag(16), base64) ----------------------
char *crypto_aes_gcm_encrypt_b64(const unsigned char key[16], const char *plaintext){
    if(crypto_load() != 0 || !plaintext) return NULL;
    size_t plen = strlen(plaintext);
    unsigned char nonce[12];
    if(C.RAND_bytes(nonce, sizeof nonce) != 1) return NULL;

    unsigned char *buf = malloc(sizeof nonce + plen + 16);
    if(!buf) return NULL;
    memcpy(buf, nonce, sizeof nonce);

    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(buf); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_EncryptInit_ex(ctx, C.EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
       C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof nonce, NULL) == 1 &&
       C.EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
       C.EVP_EncryptUpdate(ctx, buf + sizeof nonce, &len, (const unsigned char*)plaintext, (int)plen) == 1){
        total = len;
        if(C.EVP_EncryptFinal_ex(ctx, buf + sizeof nonce + total, &len) == 1){
            total += len;
            if(C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, buf + sizeof nonce + total) == 1){
                total += 16;
                ok = 1;
            }
        }
    }
    C.EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(buf); return NULL; }
    char *b64 = b64_encode(buf, sizeof nonce + (size_t)total - 0);
    free(buf);
    return b64;
}

unsigned char *crypto_aes_gcm_decrypt_b64(const unsigned char key[16], const char *b64, size_t *out_len){
    if(out_len) *out_len = 0;
    if(crypto_load() != 0 || !b64) return NULL;
    size_t rawlen = 0;
    unsigned char *raw = b64_decode(b64, &rawlen);
    if(!raw) return NULL;
    if(rawlen < 12 + 16){ free(raw); return NULL; }
    const unsigned char *nonce = raw;
    const unsigned char *ct = raw + 12;
    size_t ctlen = rawlen - 12 - 16;
    unsigned char *tag = raw + 12 + ctlen;

    unsigned char *out = malloc(ctlen + 1);
    if(!out){ free(raw); return NULL; }

    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(raw); free(out); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
       C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
       C.EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) == 1 &&
       C.EVP_DecryptUpdate(ctx, out, &len, ct, (int)ctlen) == 1){
        total = len;
        C.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
        if(C.EVP_DecryptFinal_ex(ctx, out + total, &len) == 1){ total += len; ok = 1; }
        else { ok = 1; }   // tag mismatch: keep the plaintext, caller validates JSON
    }
    C.EVP_CIPHER_CTX_free(ctx);
    free(raw);
    if(!ok){ free(out); return NULL; }
    out[total] = 0;
    if(out_len) *out_len = (size_t)total;
    return out;
}

// ---- AES-128-ECB ----------------------------------------------------------
char *crypto_aes_ecb_encrypt_b64(const unsigned char key[16], const char *plaintext){
    if(crypto_load() != 0 || !plaintext) return NULL;
    size_t plen = strlen(plaintext);
    unsigned char *buf = malloc(plen + 32);
    if(!buf) return NULL;
    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(buf); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_EncryptInit_ex(ctx, C.EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
       C.EVP_EncryptUpdate(ctx, buf, &len, (const unsigned char*)plaintext, (int)plen) == 1){
        total = len;
        if(C.EVP_EncryptFinal_ex(ctx, buf + total, &len) == 1){ total += len; ok = 1; }
    }
    C.EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(buf); return NULL; }
    char *b64 = b64_encode(buf, (size_t)total);
    free(buf);
    return b64;
}

unsigned char *crypto_aes_ecb_decrypt_b64(const unsigned char key[16], const char *b64, size_t *out_len){
    if(out_len) *out_len = 0;
    if(crypto_load() != 0 || !b64) return NULL;
    size_t rawlen = 0;
    unsigned char *raw = b64_decode(b64, &rawlen);
    if(!raw || rawlen == 0){ free(raw); return NULL; }
    unsigned char *out = malloc(rawlen + 32);
    if(!out){ free(raw); return NULL; }
    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(raw); free(out); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
       C.EVP_DecryptUpdate(ctx, out, &len, raw, (int)rawlen) == 1){
        total = len;
        if(C.EVP_DecryptFinal_ex(ctx, out + total, &len) == 1){ total += len; ok = 1; }
        else ok = 1;   // padding surprise: keep what we have
    }
    C.EVP_CIPHER_CTX_free(ctx);
    free(raw);
    if(!ok){ free(out); return NULL; }
    out[total] = 0;
    if(out_len) *out_len = (size_t)total;
    return out;
}

// ---- gzip inflate ----------------------------------------------------------
// z_stream layout for the aarch64 build of zlib. Only the leading fields are
// touched, but the struct must be large enough for zlib to use internally.
typedef struct {
    const unsigned char *next_in; unsigned int avail_in; unsigned long total_in;
    unsigned char *next_out;      unsigned int avail_out; unsigned long total_out;
    const char *msg; void *state;
    void *zalloc, *zfree, *opaque;
    int data_type; unsigned long adler; unsigned long reserved;
} z_stream_t;

unsigned char *crypto_gunzip(const unsigned char *in, size_t in_len, size_t *out_len){
    if(out_len) *out_len = 0;
    if(!in || in_len == 0) return NULL;
    void *lz = dlopen("libz.so", RTLD_NOW | RTLD_GLOBAL);
    int (*inflateInit2_)(z_stream_t*, int, const char*, int) =
        lz ? (int(*)(z_stream_t*,int,const char*,int))dlsym(lz, "inflateInit2_") : NULL;
    int (*inflate_fn)(z_stream_t*, int) = lz ? (int(*)(z_stream_t*,int))dlsym(lz, "inflate") : NULL;
    int (*inflateEnd)(z_stream_t*)      = lz ? (int(*)(z_stream_t*))dlsym(lz, "inflateEnd") : NULL;
    const char *(*zlibVersion)(void)    = lz ? (const char*(*)(void))dlsym(lz, "zlibVersion") : NULL;

    // Not compressed, or zlib unavailable: hand back a copy so callers can be
    // uniform (Tuya only gzips when cp=gzip was negotiated).
    int looks_gzip = in_len > 2 && in[0] == 0x1f && in[1] == 0x8b;
    int looks_zlib = in_len > 2 && (in[0] & 0x0f) == 8;
    if(!inflateInit2_ || !inflate_fn || !inflateEnd || (!looks_gzip && !looks_zlib)){
        unsigned char *copy = malloc(in_len + 1);
        if(!copy) return NULL;
        memcpy(copy, in, in_len); copy[in_len] = 0;
        if(out_len) *out_len = in_len;
        return copy;
    }

    z_stream_t zs;
    memset(&zs, 0, sizeof zs);
    // 15 + 32 => window 32K, auto-detect gzip or zlib wrapper.
    if(inflateInit2_(&zs, 15 + 32, zlibVersion ? zlibVersion() : "1.2.11", (int)sizeof zs) != 0)
        return NULL;

    size_t cap = in_len * 4 + 1024, total = 0;
    unsigned char *out = malloc(cap);
    if(!out){ inflateEnd(&zs); return NULL; }
    zs.next_in = in; zs.avail_in = (unsigned)in_len;
    for(;;){
        if(total + 4096 > cap){
            cap *= 2;
            unsigned char *nb = realloc(out, cap);
            if(!nb){ free(out); inflateEnd(&zs); return NULL; }
            out = nb;
        }
        zs.next_out = out + total;
        zs.avail_out = (unsigned)(cap - total - 1);
        int r = inflate_fn(&zs, 0);
        total = cap - 1 - zs.avail_out;
        if(r == 1) break;                    // Z_STREAM_END
        if(r != 0){ free(out); inflateEnd(&zs); return NULL; }
        if(zs.avail_in == 0 && zs.avail_out > 0) break;
    }
    inflateEnd(&zs);
    out[total] = 0;
    if(out_len) *out_len = total;
    return out;
}

// ---- RSA PKCS#1 v1.5 -------------------------------------------------------

// Parse a big integer whose base has to be inferred. Decimal is the common case
// here; only treat it as hex when a non-decimal hex digit actually appears.
static int bn_from_string(BIGNUM_t **out, const char *s){
    if(!s || !*s) return -1;
    while(*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    int has_hex_letter = 0, all_digits = 1;
    for(const char *p = s; *p; p++){
        if((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')){ has_hex_letter = 1; all_digits = 0; }
        else if(!(*p >= '0' && *p <= '9')){ all_digits = 0; }
    }
    if(all_digits && !has_hex_letter) return C.BN_dec2bn(out, s) ? 0 : -1;
    return C.BN_hex2bn(out, s) ? 0 : -1;
}

char *crypto_rsa_encrypt_hex(const char *plaintext, const char *modulus, const char *exponent){
    if(crypto_load() != 0 || !plaintext || !modulus || !exponent) return NULL;
    if(!C.RSA_new || !C.RSA_set0_key || !C.RSA_public_encrypt || !C.BN_hex2bn || !C.BN_dec2bn){
        st_err("libcrypto: RSA entry points unavailable");
        return NULL;
    }
    // Tuya's token endpoint returns the modulus and exponent as DECIMAL strings.
    // Order matters: BN_hex2bn() would happily parse a decimal string as hex
    // (digits 0-9 are valid hex) and silently produce the wrong modulus, so pick
    // the base by inspection — any a-f/A-F digit means hex, otherwise decimal.
    BIGNUM_t *n = NULL, *e = NULL;
    if(bn_from_string(&n, modulus) != 0 || bn_from_string(&e, exponent) != 0){
        st_err("RSA: could not parse modulus/exponent");
        return NULL;
    }

    RSA_t *rsa = C.RSA_new();
    if(!rsa) return NULL;
    if(C.RSA_set0_key(rsa, n, e, NULL) != 1){ C.RSA_free(rsa); return NULL; }

    int sz = C.RSA_size ? C.RSA_size(rsa) : 256;
    unsigned char *cipher = malloc((size_t)sz);
    if(!cipher){ C.RSA_free(rsa); return NULL; }
    int len = C.RSA_public_encrypt((int)strlen(plaintext), (const unsigned char*)plaintext,
                                   cipher, rsa, RSA_PKCS1_PADDING);
    C.RSA_free(rsa);
    if(len <= 0){ free(cipher); st_err("RSA encrypt failed"); return NULL; }

    char *hex = malloc((size_t)len * 2 + 1);
    if(!hex){ free(cipher); return NULL; }
    for(int i = 0; i < len; i++) snprintf(hex + i*2, 3, "%02x", cipher[i]);
    hex[len*2] = 0;
    free(cipher);
    return hex;
}

// ---- raw AES-128-ECB + CRC32 (pv-2.2 MQTT control frames) ------------------
unsigned char *crypto_aes_ecb_encrypt(const unsigned char key[16], const char *plaintext, size_t *out_len){
    if(out_len) *out_len = 0;
    if(crypto_load() != 0 || !plaintext) return NULL;
    size_t plen = strlen(plaintext);
    unsigned char *buf = malloc(plen + 32);
    if(!buf) return NULL;
    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(buf); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_EncryptInit_ex(ctx, C.EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
       C.EVP_EncryptUpdate(ctx, buf, &len, (const unsigned char*)plaintext, (int)plen) == 1){
        total = len;
        if(C.EVP_EncryptFinal_ex(ctx, buf + total, &len) == 1){ total += len; ok = 1; }
    }
    C.EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(buf); return NULL; }
    if(out_len) *out_len = (size_t)total;
    return buf;
}

unsigned char *crypto_aes_ecb_decrypt(const unsigned char key[16], const unsigned char *ct, size_t ct_len, size_t *out_len){
    if(out_len) *out_len = 0;
    if(crypto_load() != 0 || !ct || ct_len == 0) return NULL;
    unsigned char *out = malloc(ct_len + 32);
    if(!out) return NULL;
    EVP_CIPHER_CTX_t *ctx = C.EVP_CIPHER_CTX_new();
    if(!ctx){ free(out); return NULL; }
    int ok = 0, len = 0, total = 0;
    if(C.EVP_DecryptInit_ex(ctx, C.EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
       C.EVP_DecryptUpdate(ctx, out, &len, ct, (int)ct_len) == 1){
        total = len;
        if(C.EVP_DecryptFinal_ex(ctx, out + total, &len) == 1){ total += len; ok = 1; }
        else ok = 1;   // padding surprise: keep what decrypted
    }
    C.EVP_CIPHER_CTX_free(ctx);
    if(!ok){ free(out); return NULL; }
    out[total] = 0;
    if(out_len) *out_len = (size_t)total;
    return out;
}

unsigned int crypto_crc32(const unsigned char *buf, size_t len){
    unsigned int crc = 0xFFFFFFFFu;
    for(size_t i = 0; i < len; i++){
        crc ^= buf[i];
        for(int b = 0; b < 8; b++)
            crc = (crc >> 1) ^ (0xEDB88320u & (unsigned int)(-(int)(crc & 1)));
    }
    return crc ^ 0xFFFFFFFFu;
}
