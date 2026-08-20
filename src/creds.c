#include "creds.h"
#include "json.h"
#include "status.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_dir[512], g_path[600];

const char *creds_dir(void){
    if(!g_dir[0]){
        const char *base = getenv("OUTDOOR_CAM_HOME");
        if(base && *base) snprintf(g_dir, sizeof g_dir, "%s", base);
        else {
            const char *home = getenv("HOME");
            snprintf(g_dir, sizeof g_dir, "%s/.switchbot-outdoor-cam-ctl", home && *home ? home : ".");
        }
    }
    return g_dir;
}
const char *creds_path(void){
    if(!g_path[0]) snprintf(g_path, sizeof g_path, "%s/creds.json", creds_dir());
    return g_path;
}

int creds_valid(long long expires_at, int skew){
    if(expires_at <= 0) return 0;               // unknown expiry => treat as stale
    return (long long)time(NULL) + skew < expires_at;
}

static char *dupz(const char *s){ return s ? strdup(s) : NULL; }

CredDevice *creds_device(Creds *c, const char *devId){
    if(!devId) return NULL;
    for(int i = 0; i < c->deviceCount; i++)
        if(!strcmp(c->devices[i].devId, devId)) return &c->devices[i];
    return NULL;
}
CredDevice *creds_device_add(Creds *c, const char *devId){
    CredDevice *d = creds_device(c, devId);
    if(d) return d;
    if(c->deviceCount >= CREDS_MAX_DEVICES) return NULL;
    d = &c->devices[c->deviceCount++];
    memset(d, 0, sizeof *d);
    snprintf(d->devId, sizeof d->devId, "%s", devId);
    return d;
}

const char *creds_device_uuid(Creds *c){
    if(c->deviceUuid && *c->deviceUuid) return c->deviceUuid;
    unsigned char b[16] = {0};
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0){ if(read(fd, b, sizeof b) < 0){ /* fall through to fallback */ } close(fd); }
    if(!b[0] && !b[1]){ // urandom unavailable: derive something stable-ish
        unsigned long t = (unsigned long)time(NULL) ^ (unsigned long)getpid();
        for(size_t i = 0; i < sizeof b; i++) b[i] = (unsigned char)(t >> ((i % 8) * 8));
    }
    b[6] = (unsigned char)((b[6] & 0x0F) | 0x40);   // version 4
    b[8] = (unsigned char)((b[8] & 0x3F) | 0x80);   // variant
    char *s = malloc(37);
    snprintf(s, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
    free(c->deviceUuid);
    c->deviceUuid = s;
    return c->deviceUuid;
}

int creds_load(Creds *c){
    memset(c, 0, sizeof *c);
    FILE *f = fopen(creds_path(), "rb");
    if(!f) return -1;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if(n <= 0){ fclose(f); return -1; }
    char *buf = malloc((size_t)n + 1);
    if(!buf){ fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[rd] = 0;

    JDoc *d = json_parse(buf);
    free(buf);
    if(!d){ st_warn("credential cache is corrupt — ignoring it"); return -1; }
    JNode *root = json_root(d);

    JNode *sb = json_get(root, "switchbot");
    c->sbAccess  = dupz(json_gets(sb, "access_token", NULL));
    c->sbRefresh = dupz(json_gets(sb, "refresh_token", NULL));
    c->sbAccessExpiresAt  = (long long)json_getn(sb, "access_expires_at", 0);
    c->sbRefreshExpiresAt = (long long)json_getn(sb, "refresh_expires_at", 0);

    JNode *ty = json_get(root, "tuya");
    c->tyUid         = dupz(json_gets(ty, "uid", NULL));
    c->tyPassword    = dupz(json_gets(ty, "password", NULL));
    c->tyCountryCode = dupz(json_gets(ty, "country_code", NULL));
    c->tySid         = dupz(json_gets(ty, "sid", NULL));
    c->tySecret      = dupz(json_gets(ty, "secret", NULL));
    c->tyPartnerIdentity = dupz(json_gets(ty, "partner_identity", NULL));
    c->tyLoginUid        = dupz(json_gets(ty, "login_uid", NULL));
    c->tyApiUrl      = dupz(json_gets(ty, "api_url", NULL));
    c->tyExpiresAt   = (long long)json_getn(ty, "expires_at", 0);

    c->deviceUuid = dupz(json_gets(root, "device_uuid", NULL));

    JNode *devs = json_get(root, "devices");
    for(JNode *m = devs ? devs->child : NULL; m; m = m->next){
        if(!m->key) continue;
        CredDevice *dev = creds_device_add(c, m->key);
        if(!dev) break;
        snprintf(dev->localKey, sizeof dev->localKey, "%s", json_gets(m, "local_key", ""));
        snprintf(dev->pv,       sizeof dev->pv,       "%s", json_gets(m, "pv", ""));
        snprintf(dev->name,     sizeof dev->name,     "%s", json_gets(m, "name", ""));
        snprintf(dev->password, sizeof dev->password, "%s", json_gets(m, "password", ""));
        dev->homeId       = (long long)json_getn(m, "home_id", 0);
        dev->p2pType      = (int)json_getn(m, "p2p_type", 0);
        dev->p2pExpiresAt = (long long)json_getn(m, "p2p_expires_at", 0);
        JNode *pc = json_get(m, "p2p_config");
        if(pc && pc->type != J_NULL) dev->p2pConfig = json_dump(pc);
        JNode *sk = json_get(m, "skill");
        if(sk && sk->type != J_NULL)
            dev->skill = (sk->type == J_STR) ? dupz(sk->str) : json_dump(sk);
    }
    json_free(d);
    return 0;
}

int creds_save(const Creds *c){
    mkdir(creds_dir(), 0700);   // ignore EEXIST

    JBuf b; jbuf_init(&b);
    // SwitchBot session is kept so the shadow account can be (re)fetched later
    // without asking for credentials again.
    jbuf_raw(&b, "{\n  \"switchbot\": {");
    int first = 1;
    if(c->sbAccess)  jbuf_kv(&b, "access_token",  c->sbAccess,  &first);
    if(c->sbRefresh) jbuf_kv(&b, "refresh_token", c->sbRefresh, &first);
    if(!first) jbuf_raw(&b, ",");
    jbuf_printf(&b, "\"access_expires_at\":%lld,\"refresh_expires_at\":%lld",
                c->sbAccessExpiresAt, c->sbRefreshExpiresAt);
    jbuf_raw(&b, "},\n  \"tuya\": {");
    first = 1;
    if(c->tyUid)         jbuf_kv(&b, "uid",          c->tyUid,         &first);
    if(c->tyPassword)    jbuf_kv(&b, "password",     c->tyPassword,    &first);
    if(c->tyCountryCode) jbuf_kv(&b, "country_code", c->tyCountryCode, &first);
    if(c->tySid)         jbuf_kv(&b, "sid",          c->tySid,         &first);
    if(c->tySecret)      jbuf_kv(&b, "secret",       c->tySecret,      &first);
    if(c->tyPartnerIdentity) jbuf_kv(&b, "partner_identity", c->tyPartnerIdentity, &first);
    if(c->tyLoginUid)        jbuf_kv(&b, "login_uid",        c->tyLoginUid,        &first);
    if(c->tyApiUrl)      jbuf_kv(&b, "api_url",      c->tyApiUrl,      &first);
    if(!first) jbuf_raw(&b, ",");
    jbuf_printf(&b, "\"expires_at\":%lld", c->tyExpiresAt);
    jbuf_raw(&b, "},\n  \"devices\": {");
    for(int i = 0; i < c->deviceCount; i++){
        const CredDevice *d = &c->devices[i];
        if(i) jbuf_raw(&b, ",");
        jbuf_raw(&b, "\n    ");
        jbuf_escaped(&b, d->devId);
        jbuf_raw(&b, ": {");
        int f2 = 1;
        jbuf_kv(&b, "local_key", d->localKey, &f2);
        jbuf_kv(&b, "pv",        d->pv,       &f2);
        jbuf_kv(&b, "name",      d->name,     &f2);
        if(d->password[0]) jbuf_kv(&b, "password", d->password, &f2);
        jbuf_raw(&b, ",");
        jbuf_printf(&b, "\"home_id\":%lld,\"p2p_type\":%d,\"p2p_expires_at\":%lld",
                    d->homeId, d->p2pType, d->p2pExpiresAt);
        if(d->p2pConfig){ jbuf_raw(&b, ",\"p2p_config\":"); jbuf_raw(&b, d->p2pConfig); }
        if(d->skill){     jbuf_raw(&b, ",\"skill\":");      jbuf_escaped(&b, d->skill); }
        jbuf_raw(&b, "}");
    }
    jbuf_raw(&b, "\n  }");
    if(c->deviceUuid){ jbuf_raw(&b, ",\n  \"device_uuid\": "); jbuf_escaped(&b, c->deviceUuid); }
    jbuf_raw(&b, "\n}\n");

    // Write via a temp file so a crash can't truncate a good cache.
    char tmp[700];
    snprintf(tmp, sizeof tmp, "%s.tmp", creds_path());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if(fd < 0){ st_warn("cannot write %s", creds_path()); jbuf_free(&b); return -1; }
    ssize_t w = write(fd, b.buf, b.len);
    close(fd);
    jbuf_free(&b);
    if(w < 0){ unlink(tmp); return -1; }
    if(rename(tmp, creds_path()) != 0){ unlink(tmp); return -1; }
    return 0;
}

void creds_free(Creds *c){
    free(c->sbAccess); free(c->sbRefresh);
    free(c->tyUid); free(c->tyPassword); free(c->tyCountryCode);
    free(c->tySid); free(c->tySecret); free(c->tyPartnerIdentity);
    free(c->tyLoginUid); free(c->tyApiUrl);
    free(c->deviceUuid);
    for(int i = 0; i < c->deviceCount; i++){ free(c->devices[i].p2pConfig); free(c->devices[i].skill); }
    memset(c, 0, sizeof *c);
}
