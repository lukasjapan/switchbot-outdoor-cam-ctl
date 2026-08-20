// Tuya ATOP mobile-API client.
//
// Mirrors ThingApiParams.getRequestBody: every parameter (including the
// encrypted postData and the signature) travels in the form-encoded POST body;
// the URL carries no query string.
//
// Request shape, with et="3" (the app default -> AES-GCM + gzip):
//   bodyKey = getEncryptoKey(requestId, ecode|null)              [native]
//   postData = base64( nonce(12) || AES-128-GCM(bodyKey) || tag(16) )
//   signStr  = sorted(whitelisted, non-empty) "k=v" joined by "||",
//              with postData replaced by swapSignString(md5hex(postData))
//   sign     = doCommandNative(ctx, 1, signStr, ...)             [native]
// Response envelope {t, sign, result:<enc>} decrypts with the same bodyKey to
// the real payload {success, result, errorCode, ...}.
#ifndef OUTDOOR_CAM_TUYA_SIGN_H
#define OUTDOOR_CAM_TUYA_SIGN_H

#include "json.h"

// A logged-in Tuya session (from the uid/password login).
typedef struct {
    char *sid;
    char *ecode;            // folded into the body key when a session is present
    char *uid;
    char *partnerIdentity;  // needed for the MQTT username and subscribe topic
} TuyaSession;

void tuya_session_free(TuyaSession *s);

// One ATOP call. `post_json` may be NULL (no postData). `session` may be NULL
// for pre-login calls. `gid` (home id) is sent unsigned when non-NULL.
// Returns the decrypted payload document (caller json_free's) or NULL.
JDoc *tuya_atop(const char *api_url, const char *api_name, const char *api_version,
                const char *post_json, const TuyaSession *session, const char *gid);

// Convenience: was the call successful, and what did it say if not?
int  tuya_ok(JDoc *doc);
void tuya_log_error(const char *api_name, JDoc *doc);

// The stable per-install client device id (part of the signed parameters).
const char *tuya_client_device_id(const char *seed);

#endif
