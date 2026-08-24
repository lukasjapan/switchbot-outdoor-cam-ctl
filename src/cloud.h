// SwitchBot + Tuya cloud provisioning.
//
// Ported from the working TS in scripts/lib/{switchbot-api,tuya-mobile-api}.ts.
// Chain: SwitchBot login (email/pw) -> access+refresh token
//        -> GET /wonder/ty/v1/account -> Tuya shadow account {uid,password,cc}
//        -> Tuya uid login -> session (sid/secret)   [needs ATOP signing]
//        -> device list (localKey) / thing.m.rtc.config.get (p2pConfig)
//
// Everything is expiry-gated: nothing is re-fetched while the cached copy is
// still valid, so a warm cache makes a media command do zero cloud calls.
#ifndef OUTDOOR_CAM_CLOUD_H
#define OUTDOOR_CAM_CLOUD_H

#include "creds.h"

// Endpoints + app identity now come from switchbot_config.json (`prd` block)
// via sb_config() (config.h). SB_APP_VERSION is not in that config, so it stays.
#define SB_APP_VERSION    "9.11.15"

// Stage 1: log in with account credentials. Fills sbAccess/sbRefresh/expiries.
// Returns 0 on success. If the account has MFA enabled this fails with a clear
// message (use a pre-obtained token instead).
int cloud_switchbot_login(Creds *c, const char *email, const char *password);

// Adopt a pre-obtained SwitchBot session token (skips stage 1).
int cloud_switchbot_use_token(Creds *c, const char *token);

// Ensure a usable SwitchBot access token, refreshing ONLY if expired. Never
// prompts for credentials — the stored refresh token is the durable credential.
int cloud_switchbot_ensure_token(Creds *c);

// Stage 2: fetch the Tuya shadow account for the logged-in user.
int cloud_fetch_tuya_account(Creds *c);

// ---- Tuya side (uses only the cached shadow account) -----------------------
#include "tuya_sign.h"

// The region-routed mobile API endpoint for a country code (TUYA_API_URL wins).
const char *cloud_tuya_api_url(const char *country_code);

// Stage 3: log in to Tuya with the shadow account:
//   thing.m.user.username.token.get v2.0 -> {token, publicKey, exponent}
//   passwd = hex(RSA-PKCS1(publicKey, exponent, md5hex(password)))
//   thing.m.user.uid.password.login.reg  -> {sid, ecode, uid}
// Fills `out`; caller tuya_session_free()s it.
int cloud_tuya_login(Creds *c, TuyaSession *out);

// Device detail: thing.m.device.get {devId} -> localKey + pv + name, cached.
// NB: the shadow account owns no home, so the home/group device-list APIs return
// USER_GROUP_ID_IS_BLANK — the devId has to come from elsewhere (it is the same
// id the SwitchBot Open API reports for the camera).
int cloud_device_detail(Creds *c, const TuyaSession *s, const char *dev_id);

// Session config: thing.m.rtc.config.get + thing.m.rtc.session.init {devId} ->
// password, p2pConfig (ICE / TURN / aesKey / sessionId / expire), skill, p2pId.
//
// IMPORTANT: although the blob advertises a long `expire`, session.init mints
// PER-CONNECTION values (sessionId, password), so a cached copy cannot be used to
// open a second session — the camera rejects it and connect() fails with -3.
// Pass force=1 before every connect; force=0 only for read-only inspection,
// where a cached copy is fine.
int cloud_rtc_config(Creds *c, const TuyaSession *s, const char *dev_id, int force);

// Compute the P2P auth password: lowercase_hex(MD5(password + "||" + localKey)).
// `out` needs 33 bytes.
int cloud_auth_pwd(const CredDevice *dev, char out[33]);

#endif
