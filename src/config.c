#include "config.h"
#include "json.h"
#include "status.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static SbConfig g_cfg;
static int g_loaded;   // 0 = not tried, 1 = ok, -1 = failed

static char *dupz(const char *s){ return s ? strdup(s) : NULL; }

static char *config_path(char *buf, size_t n){
    const char *p = getenv("SWITCHBOT_CONFIG");
    if(p && *p){ snprintf(buf, n, "%s", p); return buf; }
    const char *assets = getenv("ASSETS_DIR");
    if(!assets || !*assets){
        st_err("switchbot_config.json: neither SWITCHBOT_CONFIG nor ASSETS_DIR is set");
        return NULL;
    }
    snprintf(buf, n, "%s/switchbot_config.json", assets);
    return buf;
}

static char *read_file(const char *path){
    FILE *f = fopen(path, "rb");
    if(!f){ st_err("switchbot_config.json: cannot open %s", path); return NULL; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if(n <= 0){ fclose(f); st_err("switchbot_config.json: %s is empty", path); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if(!buf){ fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = 0;
    return buf;
}

// Fetch a required string; logs and flags failure via *ok if absent/empty.
static char *req(const JNode *obj, const char *key, const char *where, int *ok){
    const char *v = json_gets(obj, key, NULL);
    if(!v || !*v){
        st_err("switchbot_config.json: missing %s.%s", where, key);
        *ok = 0;
        return NULL;
    }
    return strdup(v);
}

const SbConfig *sb_config(void){
    if(g_loaded == 1) return &g_cfg;
    if(g_loaded == -1) return NULL;
    g_loaded = -1;   // pessimistic until we fully succeed

    char path[1024];
    if(!config_path(path, sizeof path)) return NULL;

    char *text = read_file(path);
    if(!text) return NULL;

    JDoc *d = json_parse(text);
    free(text);
    if(!d){ st_err("switchbot_config.json: parse error (%s)", path); return NULL; }

    JNode *prd = json_get(json_root(d), "prd");
    if(!prd){ st_err("switchbot_config.json: no `prd` block"); json_free(d); return NULL; }
    JNode *ep = json_get(prd, "endPoint");

    int ok = 1;
    g_cfg.tyAppKey       = req(prd, "tyAppKey",    "prd", &ok);
    g_cfg.tyAppSecret    = req(prd, "tyAppSecret", "prd", &ok);
    g_cfg.clientId       = req(prd, "clientId",    "prd", &ok);
    g_cfg.accountBase    = req(ep,  "account",     "prd.endPoint", &ok);
    g_cfg.wonderlabsBase = req(ep,  "wonderlabs",  "prd.endPoint", &ok);
    g_cfg.publishBase    = dupz(json_gets(ep, "publish", NULL));   // optional

    json_free(d);

    if(!ok){
        free(g_cfg.tyAppKey); free(g_cfg.tyAppSecret); free(g_cfg.clientId);
        free(g_cfg.accountBase); free(g_cfg.wonderlabsBase); free(g_cfg.publishBase);
        memset(&g_cfg, 0, sizeof g_cfg);
        return NULL;
    }

    g_loaded = 1;
    st_debug("switchbot_config.json loaded from %s (prd)", path);
    return &g_cfg;
}
