// SwitchBot app config — loaded from the bundled APK asset switchbot_config.json
// (the `prd` block) instead of being hardcoded in source.
//
// The mock libandroid.so already stages the APK assets into $ASSETS_DIR, so the
// same file libthing_security reads its key material from also carries the app
// identity and cloud endpoints. sb_config() reads it once, lazily, and caches it.
#ifndef OCC_CONFIG_H
#define OCC_CONFIG_H

typedef struct {
    // Tuya app identity (ATOP clientId + native init secret).
    char *tyAppKey;
    char *tyAppSecret;
    // SwitchBot cloud.
    char *accountBase;     // endPoint.account
    char *wonderlabsBase;  // endPoint.wonderlabs
    char *publishBase;     // endPoint.publish (loaded but currently unused)
    char *clientId;        // SwitchBot account clientId
} SbConfig;

// Load (once) and return the parsed `prd` config, or NULL on failure (missing
// file / parse error / missing required key). Failures are logged via st_err.
// The returned struct is owned by this module — do not free.
//
// Path: $SWITCHBOT_CONFIG if set, else $ASSETS_DIR/switchbot_config.json.
const SbConfig *sb_config(void);

#endif
