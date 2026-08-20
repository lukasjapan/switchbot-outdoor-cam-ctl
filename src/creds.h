// Credential cache (~/.switchbot-outdoor-cam-ctl/creds.json).
//
// Login runs exactly once. The durable credential is the **Tuya shadow account**
// (uid + password + countryCode) that SwitchBot provisions for the user: it is
// stable and does not expire, so normal operation never contacts SwitchBot at
// all — Tuya sessions are minted from the shadow account.
//
// The SwitchBot session token is cached too, purely so the shadow account can be
// (re)fetched later without asking for credentials again.
//
// Everything else is derived on demand and gated on real expiry, so a warm cache
// makes a media command do zero cloud calls:
//   shadow account (permanent) -> Tuya session (expires) -> device localKey
//   (stable, cached per devId) -> p2pConfig (expires, cached with its own TTL)
#ifndef OUTDOOR_CAM_CREDS_H
#define OUTDOOR_CAM_CREDS_H

#include <time.h>

#define CREDS_MAX_DEVICES 32

typedef struct {
    char devId[64];
    char localKey[64];
    char pv[16];
    char name[128];
    long long homeId;
    // Session config from thing.m.rtc.config.get — rotates, cached with its
    // own expiry so a still-valid blob means a cloud-free LAN connect.
    char *p2pConfig;      // raw JSON (owned)
    char *skill;          // raw JSON (owned)
    char  password[128];
    int   p2pType;
    long long p2pExpiresAt;   // unix seconds; 0 = unknown/absent
} CredDevice;

typedef struct {
    // SwitchBot session — cached only to (re)fetch the shadow account later.
    char *sbAccess, *sbRefresh;
    long long sbAccessExpiresAt, sbRefreshExpiresAt;
    // Tuya shadow account: THE durable credential (permanent) + derived session.
    char *tyUid, *tyPassword, *tyCountryCode;
    char *tySid, *tySecret;
    char *tyPartnerIdentity;     // MQTT username + subscribe topic depend on it
    // The uid the Tuya LOGIN returns, which is not the shadow-account uid above.
    // The MQTT subscribe topic (<partnerIdentity>/mb/<uid>) needs this one.
    char *tyLoginUid;
    long long tyExpiresAt;
    char *tyApiUrl;              // region-routed mobile API endpoint
    // Stable per-device info
    CredDevice devices[CREDS_MAX_DEVICES];
    int deviceCount;
    // Stable device id we present to the cloud (kept so sessions look stable)
    char *deviceUuid;
} Creds;

// Path helpers ("~/.switchbot-outdoor-cam-ctl", override with OUTDOOR_CAM_HOME).
const char *creds_dir(void);
const char *creds_path(void);

int  creds_load(Creds *c);          // 0 if loaded, -1 if absent/unreadable
int  creds_save(const Creds *c);    // writes 0600
void creds_free(Creds *c);

// Expiry helpers — the anti-spam gate. `skew` seconds of safety margin.
int creds_valid(long long expires_at, int skew);

CredDevice *creds_device(Creds *c, const char *devId);      // NULL if absent
CredDevice *creds_device_add(Creds *c, const char *devId);  // find-or-create

// A stable random UUID for this install (created on first use).
const char *creds_device_uuid(Creds *c);

#endif
