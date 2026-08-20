#include "cloud.h"
#include "crypto.h"
#include "http.h"
#include "jni_mock.h"   // shared base64 helpers
#include "json.h"
#include "security.h"
#include "status.h"
#include "tuya_sign.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ---- helpers ---------------------------------------------------------------
static void rand_uuid(char out[37]){
    unsigned char b[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0){ if(read(fd, b, sizeof b) < 0){ /* fallback below */ } close(fd); }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

static void set_str(char **dst, const char *v){
    free(*dst);
    *dst = v ? strdup(v) : NULL;
}

// The SwitchBot API wraps everything as {statusCode, body, message};
// statusCode 100 means success (NetResponse.java).
static JNode *sb_body(JDoc *d, const char *what){
    JNode *root = json_root(d);
    int code = (int)json_getn(root, "statusCode", -1);
    if(code != 100){
        const char *msg = json_gets(root, "message", NULL);
        st_err("%s failed: statusCode=%d%s%s", what, code, msg ? " — " : "", msg ? msg : "");
        return NULL;
    }
    return json_get(root, "body");
}

// ---- stage 1: SwitchBot account login --------------------------------------
int cloud_switchbot_login(Creds *c, const char *email, const char *password){
    char reqid[37], devuuid[37];
    rand_uuid(reqid);
    snprintf(devuuid, sizeof devuuid, "%s", creds_device_uuid(c));

    // Body per LoginReq.java. The password travels as-is under TLS (the app
    // does not hash it).
    JBuf b; jbuf_init(&b);
    jbuf_raw(&b, "{");
    int first = 1;
    jbuf_kv(&b, "username",  email,        &first);
    jbuf_kv(&b, "password",  password,     &first);
    jbuf_kv(&b, "verifyCode", "",          &first);
    jbuf_kv(&b, "clientId",  SB_CLIENT_ID, &first);
    jbuf_kv(&b, "grantType", "password",   &first);
    // deviceName/model are self-declared client labels (a user-agent, in effect):
    // they only show up in the account's device list. Session identity is deviceId,
    // the stable UUID from creds_device_uuid(), so renaming these is cosmetic.
    jbuf_raw(&b, ",\"deviceInfo\":{");
    int f2 = 1;
    jbuf_kv(&b, "deviceId",   devuuid,        &f2);
    jbuf_kv(&b, "deviceName", "switchbot-outdoor-cam-ctl", &f2);
    jbuf_kv(&b, "model",      "switchbot-outdoor-cam-ctl", &f2);
    jbuf_kv(&b, "appVersion", SB_APP_VERSION, &f2);
    jbuf_raw(&b, "},\"dialCode\":null,\"aliCaptcha\":null}");

    char h_req[64], h_uuid[64];
    snprintf(h_req,  sizeof h_req,  "requestID: %s", reqid);
    snprintf(h_uuid, sizeof h_uuid, "uuid: %s", devuuid);
    const char *hdrs[] = {
        "Content-Type: application/json",
        h_req, h_uuid,
        "appVersion: " SB_APP_VERSION,
        "versionFlag: " SB_APP_VERSION,
        NULL
    };

    st_info("logging in to SwitchBot…");
    HttpResponse r;
    int rc = http_request("POST", SB_ACCOUNT_BASE "/account/api/v2/user/login", hdrs, b.buf, &r);
    jbuf_free(&b);
    if(rc != 0) return -1;

    JDoc *d = json_parse(r.body);
    if(!d){ st_err("login: unexpected response (HTTP %d)", r.status); http_response_free(&r); return -1; }
    JNode *body = sb_body(d, "SwitchBot login");
    if(!body){ json_free(d); http_response_free(&r); return -1; }

    if(json_bool(json_get(body, "mfa_enabled"), 0)){
        st_err("this account has MFA enabled — switchbot-outdoor-cam-ctl cannot complete the MFA challenge.");
        st_err("obtain the app's session token (JWT) and use: switchbot-outdoor-cam-ctl login --session-token <jwt>");
        json_free(d); http_response_free(&r); return -1;
    }

    const char *at = json_gets(body, "access_token", NULL);
    const char *rt = json_gets(body, "refresh_token", NULL);
    if(!at){ st_err("login: no access_token in response"); json_free(d); http_response_free(&r); return -1; }

    long long now = (long long)time(NULL);
    set_str(&c->sbAccess, at);
    set_str(&c->sbRefresh, rt);
    c->sbAccessExpiresAt  = now + (long long)json_getn(body, "expires_in", 3600);
    c->sbRefreshExpiresAt = now + (long long)json_getn(body, "refresh_expires_in", 30 * 24 * 3600);

    st_info("SwitchBot login ok (access token valid %lldm)", (c->sbAccessExpiresAt - now) / 60);
    json_free(d);
    http_response_free(&r);
    return 0;
}

// The SwitchBot access token is a JWT; read its real expiry from the `exp`
// claim rather than guessing a lifetime. Returns 0 if it cannot be determined.
static long long jwt_exp(const char *tok){
    if(!tok) return 0;
    const char *p1 = strchr(tok, '.');
    if(!p1) return 0;
    const char *p2 = strchr(p1 + 1, '.');
    if(!p2) return 0;
    size_t n = (size_t)(p2 - p1 - 1);
    if(n == 0 || n > 4096) return 0;
    // base64url -> base64 so the standard decoder can handle it.
    char *b64 = malloc(n + 5);
    if(!b64) return 0;
    memcpy(b64, p1 + 1, n);
    for(size_t i = 0; i < n; i++){
        if(b64[i] == '-') b64[i] = '+';
        else if(b64[i] == '_') b64[i] = '/';
    }
    while(n % 4){ b64[n++] = '='; }
    b64[n] = 0;
    size_t outlen = 0;
    uint8_t *raw = b64_decode(b64, &outlen);
    free(b64);
    if(!raw) return 0;
    char *js = malloc(outlen + 1);
    if(!js){ free(raw); return 0; }
    memcpy(js, raw, outlen); js[outlen] = 0;
    free(raw);
    JDoc *d = json_parse(js);
    free(js);
    if(!d) return 0;
    long long exp = (long long)json_getn(json_root(d), "exp", 0);
    json_free(d);
    return exp;
}

// The Open API token is 32/96 hex chars with a paired secret; the session token
// is a JWT. They belong to different APIs, and only the JWT can reach the Tuya
// shadow account — so catch the mix-up here instead of surfacing a bare 401.
static int looks_like_open_api_token(const char *t){
    size_t n = strlen(t);
    if(n < 24) return 0;
    for(size_t i = 0; i < n; i++)
        if(!((t[i] >= '0' && t[i] <= '9') || (t[i] >= 'a' && t[i] <= 'f') || (t[i] >= 'A' && t[i] <= 'F')))
            return 0;
    return 1;   // all hex, no dots => not a JWT
}

int cloud_switchbot_use_token(Creds *c, const char *token){
    if(!token || !*token){ st_err("empty --session-token"); return -1; }
    if(looks_like_open_api_token(token)){
        st_err("that looks like the Open API token (all hex, %zu chars), not a session token.", strlen(token));
        st_err("--session-token wants the app's JWT (starts with \"eyJ\"). The Open API");
        st_err("token+secret authenticate a different API and cannot fetch the Tuya account.");
        st_err("Use --email/--password instead, or supply the JWT.");
        return -1;
    }
    set_str(&c->sbAccess, token);
    long long exp = jwt_exp(token);
    long long now = (long long)time(NULL);
    if(exp > 0){
        c->sbAccessExpiresAt = exp;
        if(exp <= now) st_warn("supplied token expired %llds ago — it will likely be rejected", now - exp);
        else st_info("using supplied SwitchBot token (valid %lldm)", (exp - now) / 60);
    } else {
        // Not a decodable JWT: assume a short window so staleness surfaces fast.
        c->sbAccessExpiresAt = now + 3600;
        st_info("using supplied SwitchBot token (unknown expiry)");
    }
    return 0;
}

// Refresh the access token from the stored refresh token (no re-login).
static int sb_refresh(Creds *c){
    if(!c->sbRefresh || !*c->sbRefresh){
        st_err("SwitchBot token expired and no refresh token is cached — run: switchbot-outdoor-cam-ctl login");
        return -1;
    }
    if(!creds_valid(c->sbRefreshExpiresAt, 0)){
        st_err("SwitchBot refresh token has expired — run: switchbot-outdoor-cam-ctl login");
        return -1;
    }
    char reqid[37];
    rand_uuid(reqid);
    char h_req[64];
    snprintf(h_req, sizeof h_req, "requestID: %s", reqid);
    // switchBotTK:none tells the app's interceptor NOT to attach the (expired)
    // authorization header — mirrored here for parity with ApiService.java.
    const char *hdrs[] = {
        "Content-Type: application/json",
        "switchBotTK: none",
        h_req,
        "appVersion: " SB_APP_VERSION,
        "versionFlag: " SB_APP_VERSION,
        NULL
    };
    JBuf b; jbuf_init(&b);
    jbuf_raw(&b, "{");
    int first = 1;
    jbuf_kv(&b, "refreshToken", c->sbRefresh, &first);
    jbuf_kv(&b, "clientId",     SB_CLIENT_ID, &first);
    jbuf_raw(&b, "}");

    st_info("SwitchBot token expired — refreshing…");
    HttpResponse r;
    int rc = http_request("POST", SB_ACCOUNT_BASE "/account/api/v1/user/token/refresh", hdrs, b.buf, &r);
    jbuf_free(&b);
    if(rc != 0) return -1;

    JDoc *d = json_parse(r.body);
    JNode *body = d ? sb_body(d, "token refresh") : NULL;
    if(!body){
        st_err("token refresh failed — run: switchbot-outdoor-cam-ctl login");
        if(d) json_free(d);
        http_response_free(&r);
        return -1;
    }
    const char *at = json_gets(body, "access_token", NULL);
    if(at){
        long long now = (long long)time(NULL);
        set_str(&c->sbAccess, at);
        c->sbAccessExpiresAt = now + (long long)json_getn(body, "expires_in", 3600);
        const char *rt = json_gets(body, "refresh_token", NULL);
        if(rt){
            set_str(&c->sbRefresh, rt);
            c->sbRefreshExpiresAt = now + (long long)json_getn(body, "refresh_expires_in", 30 * 24 * 3600);
        }
        st_info("token refreshed");
    }
    json_free(d);
    http_response_free(&r);
    return at ? 0 : -1;
}

int cloud_switchbot_ensure_token(Creds *c){
    // The anti-spam gate: only touch the network when the token is actually
    // expired (60s of skew so we do not race an expiry mid-request).
    if(c->sbAccess && creds_valid(c->sbAccessExpiresAt, 60)){
        st_debug("SwitchBot token still valid (%llds left) — skipping refresh",
                 c->sbAccessExpiresAt - (long long)time(NULL));
        return 0;
    }
    if(!c->sbAccess && !c->sbRefresh){
        st_err("not logged in — run: switchbot-outdoor-cam-ctl login --email <e> --password <p>");
        return -1;
    }
    return sb_refresh(c);
}

// ---- stage 2: Tuya shadow account ------------------------------------------
int cloud_fetch_tuya_account(Creds *c){
    if(cloud_switchbot_ensure_token(c) != 0) return -1;

    char reqid[37];
    rand_uuid(reqid);
    char h_auth[2048], h_req[64], h_uuid[64];
    snprintf(h_auth, sizeof h_auth, "authorization: %s", c->sbAccess);
    snprintf(h_req,  sizeof h_req,  "requestID: %s", reqid);
    snprintf(h_uuid, sizeof h_uuid, "uuid: %s", creds_device_uuid(c));
    const char *hdrs[] = {
        "Content-Type: application/json",
        h_auth, h_req, h_uuid,
        "appVersion: " SB_APP_VERSION,
        "versionFlag: " SB_APP_VERSION,
        NULL
    };

    st_info("fetching Tuya account…");
    HttpResponse r;
    if(http_request("GET", SB_WONDERLABS_BASE "/wonder/ty/v1/account", hdrs, NULL, &r) != 0) return -1;

    JDoc *d = json_parse(r.body);
    JNode *body = d ? sb_body(d, "Tuya account lookup") : NULL;
    if(!body){
        if(!d) st_err("Tuya account lookup: unexpected response (HTTP %d)", r.status);
        if(d) json_free(d);
        http_response_free(&r);
        return -1;
    }
    const char *uid = json_gets(body, "uid", NULL);
    const char *pw  = json_gets(body, "password", NULL);
    const char *cc  = json_gets(body, "countryCode", NULL);
    if(!uid || !pw){
        st_err("Tuya account lookup: missing uid/password");
        json_free(d); http_response_free(&r); return -1;
    }
    set_str(&c->tyUid, uid);
    set_str(&c->tyPassword, pw);
    set_str(&c->tyCountryCode, cc ? cc : "1");
    st_info("Tuya account: uid=%s country=%s", uid, c->tyCountryCode);

    json_free(d);
    http_response_free(&r);
    return 0;
}

// ============================================================================
// Tuya side — driven entirely by the cached shadow account (no SwitchBot calls).
// ============================================================================

// Region routing (mirrors the app's country-code -> region mapping). Country
// codes in the "America" set land on the US endpoint; 86 is mainland China.
const char *cloud_tuya_api_url(const char *country_code){
    const char *env = getenv("TUYA_API_URL");
    if(env && *env) return env;
    if(!country_code || !*country_code) return "https://a1-us.iotbing.com/api.json";
    if(!strcmp(country_code, "86")) return "https://a1.tuyacn.com/api.json";
    if(!strcmp(country_code, "91")) return "https://a1-in.iotbing.com/api.json";
    static const char *america[] = {
        "1","51","52","54","55","56","57","58","60","62","63","64","66","81","82",
        "84","95","502","591","593","594","595","597","598","852","853","886","1787", NULL
    };
    for(int i = 0; america[i]; i++)
        if(!strcmp(country_code, america[i])) return "https://a1-us.iotbing.com/api.json";
    return "https://a1-eu.iotbing.com/api.json";
}

int cloud_tuya_login(Creds *c, TuyaSession *out){
    memset(out, 0, sizeof *out);
    if(!c->tyUid || !c->tyPassword){
        st_err("no Tuya account cached — run: switchbot-outdoor-cam-ctl login");
        return -1;
    }
    const char *cc  = c->tyCountryCode && *c->tyCountryCode ? c->tyCountryCode : "1";
    const char *url = cloud_tuya_api_url(cc);
    if(!c->tyApiUrl || strcmp(c->tyApiUrl, url) != 0) set_str(&c->tyApiUrl, url);

    if(security_init() != 0) return -1;

    // Step 1: fetch a login token plus the RSA public key to wrap the password.
    JBuf pb; jbuf_init(&pb);
    jbuf_raw(&pb, "{");
    int first = 1;
    jbuf_kv(&pb, "countryCode", cc, &first);
    jbuf_kv(&pb, "username", c->tyUid, &first);
    jbuf_kv_raw(&pb, "isUid", "true", &first);
    jbuf_raw(&pb, "}");

    st_info("Tuya login (uid=%s, %s)…", c->tyUid, url);
    JDoc *tok = tuya_atop(url, "thing.m.user.username.token.get", "2.0", pb.buf, NULL, NULL);
    jbuf_free(&pb);
    if(!tuya_ok(tok)){ tuya_log_error("token.get", tok); json_free(tok); return -1; }

    JNode *tr = json_get(json_root(tok), "result");
    const char *token   = json_gets(tr, "token", NULL);
    const char *pubkey  = json_gets(tr, "publicKey", NULL);
    const char *exponent= json_gets(tr, "exponent", "65537");
    if(!token || !pubkey){
        st_err("token.get response missing token/publicKey");
        json_free(tok); return -1;
    }

    // passwd = hex(RSA-PKCS1(publicKey, md5hex(shadow password)))
    char md5[33];
    if(crypto_md5_hex(c->tyPassword, md5) != 0){ json_free(tok); return -1; }
    char *passwd = crypto_rsa_encrypt_hex(md5, pubkey, exponent);
    char *token_copy = strdup(token);
    json_free(tok);
    if(!passwd || !token_copy){
        st_err("failed to wrap the password for login");
        free(passwd); free(token_copy); return -1;
    }

    // Step 2: exchange it for a session.
    JBuf lb; jbuf_init(&lb);
    jbuf_raw(&lb, "{");
    first = 1;
    jbuf_kv(&lb, "countryCode", cc, &first);
    jbuf_kv(&lb, "uid", c->tyUid, &first);
    jbuf_kv(&lb, "passwd", passwd, &first);
    jbuf_kv(&lb, "token", token_copy, &first);
    jbuf_kv_raw(&lb, "ifencrypt", "1", &first);
    jbuf_kv_raw(&lb, "createGroup", "false", &first);
    jbuf_kv(&lb, "options", "{\"group\": 1}", &first);
    jbuf_raw(&lb, "}");
    free(passwd); free(token_copy);

    JDoc *res = tuya_atop(url, "thing.m.user.uid.password.login.reg", "1.0", lb.buf, NULL, NULL);
    jbuf_free(&lb);
    if(!tuya_ok(res)){ tuya_log_error("uid.password.login.reg", res); json_free(res); return -1; }

    JNode *rr = json_get(json_root(res), "result");
    const char *sid   = json_gets(rr, "sid", json_gets(rr, "sessionId", NULL));
    const char *ecode = json_gets(rr, "ecode", "");
    const char *uid   = json_gets(rr, "uid", c->tyUid);
    // partnerIdentity keys the MQTT username and the subscribe topic.
    const char *pident = json_gets(rr, "partnerIdentity", json_gets(rr, "partner_identity", ""));
    if(!sid || !*sid){
        st_err("login succeeded but returned no sid");
        json_free(res); return -1;
    }
    out->sid   = strdup(sid);
    out->ecode = strdup(ecode ? ecode : "");
    out->uid   = strdup(uid ? uid : c->tyUid);
    out->partnerIdentity = strdup(pident ? pident : "");
    if(!*out->partnerIdentity)
        st_warn("login returned no partnerIdentity — MQTT signaling will likely fail");

    // Cache the session so later commands can skip the login while it is valid.
    set_str(&c->tySid, out->sid);
    set_str(&c->tySecret, out->ecode);
    set_str(&c->tyPartnerIdentity, out->partnerIdentity);
    set_str(&c->tyLoginUid, out->uid);
    c->tyExpiresAt = (long long)time(NULL) + 6 * 3600;

    st_info("Tuya session established");
    json_free(res);
    return 0;
}

int cloud_device_detail(Creds *c, const TuyaSession *s, const char *dev_id){
    if(!dev_id || !*dev_id){ st_err("no device id"); return -1; }
    CredDevice *dev = creds_device_add(c, dev_id);
    if(!dev){ st_err("device cache full"); return -1; }

    // localKey is a static per-device secret (changes only on re-pair), so a
    // cached one is reused indefinitely.
    if(dev->localKey[0] && !getenv("OUTDOOR_CAM_DEVICE_REFRESH")){
        st_debug("localKey for %s served from cache", dev_id);
        return 0;
    }

    JBuf pb; jbuf_init(&pb);
    jbuf_raw(&pb, "{");
    int first = 1;
    jbuf_kv(&pb, "devId", dev_id, &first);
    jbuf_raw(&pb, "}");

    st_info("fetching device detail for %s…", dev_id);
    JDoc *d = tuya_atop(c->tyApiUrl ? c->tyApiUrl : cloud_tuya_api_url(c->tyCountryCode),
                        "thing.m.device.get", "1.0", pb.buf, s, NULL);
    jbuf_free(&pb);
    if(!tuya_ok(d)){ tuya_log_error("thing.m.device.get", d); json_free(d); return -1; }

    JNode *r = json_get(json_root(d), "result");
    const char *lk = json_gets(r, "localKey", json_gets(r, "local_key", NULL));
    const char *pv = json_gets(r, "pv", json_gets(r, "protocolVer", "2.2"));
    const char *nm = json_gets(r, "name", "");
    if(!lk || !*lk){
        st_err("device detail returned no localKey");
        json_free(d); return -1;
    }
    snprintf(dev->localKey, sizeof dev->localKey, "%s", lk);
    snprintf(dev->pv,       sizeof dev->pv,       "%s", pv);
    snprintf(dev->name,     sizeof dev->name,     "%s", nm);
    st_info("device: name=%s pv=%s localKey=<set>", nm[0] ? nm : "(unnamed)", pv);
    json_free(d);
    return 0;
}

int cloud_auth_pwd(const CredDevice *dev, char out[33]){
    if(!dev || !dev->password[0] || !dev->localKey[0]){
        st_err("cannot derive the P2P password (missing device password or localKey)");
        return -1;
    }
    // IPCThingP2PCamera: MD5Utils.md5AsBase64(password + "||" + localKey), which
    // despite the name returns lowercase hex.
    char joined[320];
    snprintf(joined, sizeof joined, "%s||%s", dev->password, dev->localKey);
    return crypto_md5_hex(joined, out);
}

int cloud_rtc_config(Creds *c, const TuyaSession *s, const char *dev_id, int force){
    CredDevice *dev = creds_device_add(c, dev_id);
    if(!dev){ st_err("device cache full"); return -1; }

    // Only inspection may reuse a cached blob; a connect always needs a freshly
    // minted session (see the header note — reuse yields connect() == -3).
    if(!force && dev->p2pConfig && dev->password[0] && creds_valid(dev->p2pExpiresAt, 120)){
        st_info("p2pConfig valid for %llds — reusing (no cloud call)",
                dev->p2pExpiresAt - (long long)time(NULL));
        return 0;
    }
    if(force) st_debug("minting a fresh P2P session…");
    else if(dev->p2pConfig) st_info("p2pConfig expired — refetching…");

    const char *url = c->tyApiUrl ? c->tyApiUrl : cloud_tuya_api_url(c->tyCountryCode);
    JBuf pb; jbuf_init(&pb);
    jbuf_raw(&pb, "{");
    int first = 1;
    jbuf_kv(&pb, "devId", dev_id, &first);
    jbuf_raw(&pb, "}");

    JDoc *cfg = tuya_atop(url, "thing.m.rtc.config.get", "1.0", pb.buf, s, NULL);
    if(!tuya_ok(cfg)){
        tuya_log_error("thing.m.rtc.config.get", cfg);
        jbuf_free(&pb); json_free(cfg);
        return -1;
    }
    JNode *r = json_get(json_root(cfg), "result");

    JNode *p2p = json_get(r, "p2pConfig");
    if(p2p){
        free(dev->p2pConfig);
        dev->p2pConfig = json_dump(p2p);
        // The blob carries its own expiry (session.expire, or a top-level one).
        JNode *sess = json_get(p2p, "session");
        long long exp = (long long)json_getn(sess, "expire", json_getn(p2p, "expire", 0));
        dev->p2pExpiresAt = exp;
    }
    JNode *skill = json_get(r, "skill");
    if(skill){
        free(dev->skill);
        // skill is a JSON *string* in some responses and an object in others.
        dev->skill = (skill->type == J_STR && skill->str) ? strdup(skill->str) : json_dump(skill);
    }
    const char *pw = json_gets(r, "password", NULL);
    if(pw) snprintf(dev->password, sizeof dev->password, "%s", pw);
    int ptype = (int)json_getn(r, "p2pSpecifiedType", 4);
    if(ptype > 0) dev->p2pType = ptype;
    json_free(cfg);

    // session.init mints the per-connection p2pId / sessionTid / skill / password;
    // merge whatever it returns over the config values.
    JDoc *init = tuya_atop(url, "thing.m.rtc.session.init", "1.0", pb.buf, s, NULL);
    jbuf_free(&pb);
    if(tuya_ok(init)){
        JNode *ir = json_get(json_root(init), "result");
        const char *ipw = json_gets(ir, "password", NULL);
        if(ipw) snprintf(dev->password, sizeof dev->password, "%s", ipw);
        JNode *isk = json_get(ir, "skill");
        if(isk){
            free(dev->skill);
            dev->skill = (isk->type == J_STR && isk->str) ? strdup(isk->str) : json_dump(isk);
        }
        st_debug("rtc.session.init merged");
    } else if(init){
        st_debug("rtc.session.init unavailable (continuing with config.get values)");
    }
    json_free(init);

    if(!dev->p2pConfig || !dev->password[0]){
        st_err("rtc.config.get did not return a usable p2pConfig/password");
        return -1;
    }
    if(dev->p2pExpiresAt > 0)
        st_info("p2pConfig fetched (expires in %llds)", dev->p2pExpiresAt - (long long)time(NULL));
    else
        st_info("p2pConfig fetched (no expiry advertised)");
    return 0;
}
