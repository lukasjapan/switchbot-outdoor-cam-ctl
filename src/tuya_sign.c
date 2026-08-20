#include "tuya_sign.h"
#include "crypto.h"
#include "http.h"
#include "jni_mock.h"
#include "security.h"
#include "status.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// App identity + ATOP defaults (from the decompiled app / switchbot_config.json).
#define TUYA_APP_KEY     "u93ven8vjtcc9ycmc7nx"
#define TUYA_APP_VERSION "9.11.15.13"
#define TUYA_LANG        "en"
#define TUYA_TTID        "sdk_super_new"
#define TUYA_ET          "3"          // ThingApiParams default: AES-GCM + gzip
#define SIGN_SEP         "||"
#define TUYA_UA          "User-Agent: Thing-UA=APP/Android/9.29/SDK/5.8.0"

// ThingApiSignManager's sign whitelist — only these params are signed.
static const char *SIGN_KEYS[] = {
    "a","v","lat","lon","lang","deviceId","appVersion","ttid","h5","h5Token",
    "os","clientId","postData","time","requestId","et","n4h5","sid","chKey","sp",
    NULL
};

static int is_signed_key(const char *k){
    for(int i = 0; SIGN_KEYS[i]; i++) if(!strcmp(SIGN_KEYS[i], k)) return 1;
    return 0;
}

void tuya_session_free(TuyaSession *s){
    if(!s) return;
    free(s->sid); free(s->ecode); free(s->uid); free(s->partnerIdentity);
    s->sid = s->ecode = s->uid = s->partnerIdentity = NULL;
}

// ThingApiSignManager.swapSignString — reorder the four 8-char blocks of an
// md5-hex from (A,B,C,D) to (B,A,D,C).
static void swap_sign_string(const char *in, char out[33]){
    if(strlen(in) < 32){ snprintf(out, 33, "%s", in); return; }
    memcpy(out +  0, in +  8, 8);   // B
    memcpy(out +  8, in +  0, 8);   // A
    memcpy(out + 16, in + 24, 8);   // D
    memcpy(out + 24, in + 16, 8);   // C
    out[32] = 0;
}

const char *tuya_client_device_id(const char *seed){
    static char id[25];
    if(id[0]) return id;
    const char *env = getenv("TUYA_CLIENT_DEVICE_ID");
    if(env && *env){ snprintf(id, sizeof id, "%s", env); return id; }
    char md5[33];
    if(crypto_md5_hex(seed && *seed ? seed : "switchbot", md5) == 0)
        snprintf(id, sizeof id, "%.24s", md5);      // app sends a 24-char id
    else
        snprintf(id, sizeof id, "outdoorcam00000000000000");
    return id;
}

// chKey is a signed url param derived natively from the app key; constant per
// install, so compute once.
static const char *ch_key(void){
    static char cached[64];
    static int done;
    if(done) return cached[0] ? cached : NULL;
    done = 1;
    const char *env = getenv("TUYA_CHKEY");
    if(env && *env){ snprintf(cached, sizeof cached, "%s", env); return cached; }
    char *k = security_get_ch_key(NULL);
    if(k && *k) snprintf(cached, sizeof cached, "%s", k);
    free(k);
    st_debug("chKey: %s", cached[0] ? cached : "(empty)");
    return cached[0] ? cached : NULL;
}

static void rand_uuid(char out[37]){
    unsigned char b[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0){ if(read(fd, b, sizeof b) < 0){ /* fallback */ } close(fd); }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

// ---- parameter table (kept sorted-insensitive; sorted at sign time) --------
#define MAX_PARAMS 24
typedef struct { const char *k; char *v; int owned; } Param;

static void param_set(Param *p, int *n, const char *k, const char *v, int owned){
    if(!v || !*v || *n >= MAX_PARAMS){ if(owned) free((char*)v); return; }
    p[*n].k = k;
    p[*n].v = owned ? (char*)v : strdup(v);
    p[*n].owned = 1;
    (*n)++;
}
static void params_free(Param *p, int n){ for(int i = 0; i < n; i++) if(p[i].owned) free(p[i].v); }

static int param_cmp(const void *a, const void *b){
    return strcmp(((const Param*)a)->k, ((const Param*)b)->k);
}

// URL-encode for the form body.
static void append_urlencoded(JBuf *b, const char *s){
    static const char *hex = "0123456789ABCDEF";
    for(const unsigned char *p = (const unsigned char*)s; *p; p++){
        if((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') ||
           (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.' || *p == '~'){
            char c[2] = { (char)*p, 0 };
            jbuf_raw(b, c);
        } else {
            char esc[4] = { '%', hex[*p >> 4], hex[*p & 0xF], 0 };
            jbuf_raw(b, esc);
        }
    }
}

JDoc *tuya_atop(const char *api_url, const char *api_name, const char *api_version,
                const char *post_json, const TuyaSession *session, const char *gid){
    if(!api_url || !api_name) return NULL;

    char request_id[37];
    rand_uuid(request_id);
    char time_s[24];
    snprintf(time_s, sizeof time_s, "%lld", (long long)time(NULL));

    // Body key first: signWhitEncryptedBody is true, so the signature covers the
    // ENCRYPTED postData — encrypt before signing.
    size_t keylen = 0;
    unsigned char *bodykey = security_get_encrypto_key(request_id,
                                 session && session->ecode ? session->ecode : NULL, &keylen);
    if(!bodykey || keylen < 16){
        st_err("getEncryptoKey returned %zu bytes (need 16)", keylen);
        free(bodykey);
        return NULL;
    }

    char *enc_post = NULL;
    if(post_json && *post_json){
        enc_post = strcmp(TUYA_ET, "3") == 0
                 ? crypto_aes_gcm_encrypt_b64(bodykey, post_json)
                 : crypto_aes_ecb_encrypt_b64(bodykey, post_json);
        if(!enc_post){ st_err("postData encryption failed"); free(bodykey); return NULL; }
    }

    Param p[MAX_PARAMS];
    int n = 0;
    param_set(p, &n, "a",          api_name, 0);
    param_set(p, &n, "v",          api_version ? api_version : "1.0", 0);
    param_set(p, &n, "clientId",   TUYA_APP_KEY, 0);
    param_set(p, &n, "time",       time_s, 0);
    param_set(p, &n, "requestId",  request_id, 0);
    param_set(p, &n, "et",         TUYA_ET, 0);
    param_set(p, &n, "os",         "Android", 0);
    param_set(p, &n, "lang",       TUYA_LANG, 0);
    param_set(p, &n, "appVersion", TUYA_APP_VERSION, 0);
    param_set(p, &n, "ttid",       TUYA_TTID, 0);
    param_set(p, &n, "deviceId",   tuya_client_device_id(session ? session->uid : NULL), 0);
    const char *ck = ch_key();
    if(ck)                       param_set(p, &n, "chKey",   ck, 0);
    if(session && session->sid)  param_set(p, &n, "sid",     session->sid, 0);
    if(enc_post)                 param_set(p, &n, "postData", enc_post, 0);

    // Sign string: sorted keys, whitelisted, non-empty, joined by "||", with
    // postData collapsed to swapSignString(md5hex(ciphertext)).
    Param sorted[MAX_PARAMS];
    memcpy(sorted, p, sizeof(Param) * (size_t)n);
    qsort(sorted, (size_t)n, sizeof(Param), param_cmp);

    JBuf sb; jbuf_init(&sb);
    int first = 1;
    for(int i = 0; i < n; i++){
        if(!is_signed_key(sorted[i].k) || !sorted[i].v || !*sorted[i].v) continue;
        if(!first) jbuf_raw(&sb, SIGN_SEP);
        first = 0;
        jbuf_raw(&sb, sorted[i].k);
        jbuf_raw(&sb, "=");
        if(!strcmp(sorted[i].k, "postData")){
            char md5[33], swapped[33];
            if(crypto_md5_hex(sorted[i].v, md5) == 0){ swap_sign_string(md5, swapped); jbuf_raw(&sb, swapped); }
        } else {
            jbuf_raw(&sb, sorted[i].v);
        }
    }
    if(getenv("OUTDOOR_CAM_DEBUG_SIGN")) st_debug("signStr: %s", sb.buf ? sb.buf : "");

    char *sign = security_sign(sb.buf ? sb.buf : "");
    jbuf_free(&sb);
    if(!sign || !*sign){
        st_err("native sign failed for %s", api_name);
        free(sign); free(enc_post); free(bodykey); params_free(p, n);
        return NULL;
    }

    // Form body: every param (postData last), plus sign, cp, and unsigned gid.
    JBuf body; jbuf_init(&body);
    for(int i = 0; i < n; i++){
        if(!strcmp(p[i].k, "postData")) continue;
        if(body.len) jbuf_raw(&body, "&");
        jbuf_raw(&body, p[i].k); jbuf_raw(&body, "=");
        append_urlencoded(&body, p[i].v);
    }
    jbuf_raw(&body, "&sign="); append_urlencoded(&body, sign);
    if(!strcmp(TUYA_ET, "3")) jbuf_raw(&body, "&cp=gzip");
    if(gid && *gid){ jbuf_raw(&body, "&gid="); append_urlencoded(&body, gid); }
    if(enc_post){ jbuf_raw(&body, "&postData="); append_urlencoded(&body, enc_post); }

    st_debug("ATOP %s v%s reqId=%s sid=%s", api_name, api_version ? api_version : "1.0",
             request_id, session && session->sid ? "yes" : "no");

    const char *hdrs[] = {
        "Content-Type: application/x-www-form-urlencoded",
        TUYA_UA,
        NULL
    };
    HttpResponse hr;
    int rc = http_request("POST", api_url, hdrs, body.buf, &hr);
    jbuf_free(&body);
    free(sign);
    free(enc_post);
    if(rc != 0){ free(bodykey); params_free(p, n); return NULL; }

    JDoc *doc = json_parse(hr.body);
    if(!doc){
        st_err("%s: non-JSON response (HTTP %d): %.160s", api_name, hr.status, hr.body ? hr.body : "");
        http_response_free(&hr); free(bodykey); params_free(p, n);
        return NULL;
    }

    // The envelope is {t, sign, result:<encrypted>}; decrypting `result` yields
    // the real payload, so swap the document for that.
    JNode *res = json_get(json_root(doc), "result");
    const char *enc = json_str(res, NULL);
    if(enc && *enc){
        size_t plen = 0;
        unsigned char *plain = strcmp(TUYA_ET, "3") == 0
            ? crypto_aes_gcm_decrypt_b64(bodykey, enc, &plen)
            : crypto_aes_ecb_decrypt_b64(bodykey, enc, &plen);
        if(plain){
            size_t ulen = 0;
            unsigned char *unz = crypto_gunzip(plain, plen, &ulen);
            const char *payload = unz ? (const char*)unz : (const char*)plain;
            JDoc *inner = json_parse(payload);
            if(inner){ json_free(doc); doc = inner; }
            else st_debug("%s: decrypted payload was not JSON", api_name);
            free(unz);
            free(plain);
        } else {
            st_debug("%s: result decrypt failed", api_name);
        }
    }

    http_response_free(&hr);
    free(bodykey);
    params_free(p, n);
    return doc;
}

int tuya_ok(JDoc *doc){
    if(!doc) return 0;
    JNode *s = json_get(json_root(doc), "success");
    return json_bool(s, 0);
}

void tuya_log_error(const char *api_name, JDoc *doc){
    if(!doc){ st_err("%s: no response", api_name); return; }
    JNode *r = json_root(doc);
    const char *code = json_gets(r, "errorCode", NULL);
    const char *msg  = json_gets(r, "errorMsg", NULL);
    st_err("%s failed%s%s%s%s", api_name,
           code ? " [" : "", code ? code : "", code ? "]" : "",
           msg ? msg : "");
}
