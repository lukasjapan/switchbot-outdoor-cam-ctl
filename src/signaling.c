#include "signaling.h"
#include "config.h"
#include "crypto.h"
#include "json.h"
#include "mqtt.h"
#include "security.h"
#include "status.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TUYA_PKG     "com.theswitchbot.switchbot"

struct Signaling {
    MqttConn *mq;
    // The SDK publishes from its own worker threads while a pump thread polls, so
    // every MQTT operation is serialised.
    pthread_mutex_t lock;
    char devId[64];
    char localKey[64];
    char pubTopic[128];
    char subTopic[160];
    char devTopic[128];
    // com.thingclips.sdk.mqtt.SandO: per-device sequence + a fixed origin id.
    unsigned int seq_s;
    unsigned int seq_o;
    // Handed to the inbound callback during a poll.
    signaling_on_message cb;
    void *user;
};

// Region -> mobile MQTT host. Mirrors the ATOP region routing.
static const char *broker_host(const char *country_code){
    const char *env = getenv("TUYA_MQTT_HOST");
    if(env && *env) return env;
    if(!country_code || !*country_code) return "m1.tuyaus.com";
    if(!strcmp(country_code, "86")) return "m1.tuyacn.com";
    if(!strcmp(country_code, "91")) return "m1.tuyain.com";
    static const char *america[] = {
        "1","51","52","54","55","56","57","58","60","62","63","64","66","81","82",
        "84","95","502","591","593","594","595","597","598","852","853","886","1787", NULL
    };
    for(int i = 0; america[i]; i++)
        if(!strcmp(country_code, america[i])) return "m1.tuyaus.com";
    return "m1.tuyaeu.com";
}

static unsigned int rand_origin(void){
    unsigned int v = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if(fd >= 0){ if(read(fd, &v, sizeof v) < 0) v = 0; close(fd); }
    if(!v) v = (unsigned int)time(NULL);
    return 1000u + (v % 999000u);   // [1000, 1000000)
}

static void put_be32(unsigned char *p, unsigned int v){
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

Signaling *signaling_start(const TuyaSession *s, const CredDevice *dev, const char *country_code){
    if(!s || !s->sid || !dev || !dev->localKey[0]){
        st_err("signaling: missing session or device localKey");
        return NULL;
    }
    if(!s->partnerIdentity || !*s->partnerIdentity){
        st_err("signaling: no partnerIdentity in the session — cannot build the MQTT username");
        return NULL;
    }

    Signaling *sg = calloc(1, sizeof *sg);
    if(!sg) return NULL;
    pthread_mutex_init(&sg->lock, NULL);
    snprintf(sg->devId,    sizeof sg->devId,    "%s", dev->devId);
    snprintf(sg->localKey, sizeof sg->localKey, "%s", dev->localKey);
    sg->seq_s = 2;                  // incremented before each send => first is 3
    sg->seq_o = rand_origin();

    // username: <partnerIdentity>_v1_<appId>_<chKey>_mb_<sid><md5tail>
    const SbConfig *cfg = sb_config();
    if(!cfg){ free(sg); return NULL; }
    char *chkey = security_get_ch_key(NULL);
    char inner[64], md5_1[33], md5_2[33];
    if(crypto_md5_hex(cfg->tyAppKey, md5_1) != 0){ free(chkey); free(sg); return NULL; }
    snprintf(inner, sizeof inner, "%s%s", md5_1, s->ecode ? s->ecode : "");
    if(crypto_md5_hex(inner, md5_2) != 0){ free(chkey); free(sg); return NULL; }
    const char *md5tail = md5_2 + 16;          // last 16 chars of the hex digest

    char username[512];
    snprintf(username, sizeof username, "%s_v1_%s_%s_mb_%s%s",
             s->partnerIdentity, cfg->tyAppKey, chkey ? chkey : "", s->sid, md5tail);
    free(chkey);

    char client_id[600];
    snprintf(client_id, sizeof client_id, "%s_mb_%s", TUYA_PKG, username);

    char *password = security_mqtt_password_16(s->ecode ? s->ecode : "");
    if(!password){
        st_err("signaling: could not derive the MQTT password (native op 2 failed)");
        free(sg);
        return NULL;
    }

    snprintf(sg->subTopic, sizeof sg->subTopic, "%s/mb/%s", s->partnerIdentity, s->uid ? s->uid : "");
    snprintf(sg->devTopic, sizeof sg->devTopic, "smart/mb/in/%s",  sg->devId);
    snprintf(sg->pubTopic, sizeof sg->pubTopic, "smart/mb/out/%s", sg->devId);

    const char *host = broker_host(country_code);
    int port = getenv("TUYA_MQTT_PORT") ? atoi(getenv("TUYA_MQTT_PORT")) : 8883;
    st_info("connecting signaling broker %s:%d…", host, port);
    sg->mq = mqtt_connect(host, port, 1, client_id, username, password, 60);
    free(password);
    if(!sg->mq){ free(sg); return NULL; }

    if(mqtt_subscribe(sg->mq, sg->subTopic) != 0) st_warn("signaling: could not subscribe %s", sg->subTopic);
    if(mqtt_subscribe(sg->mq, sg->devTopic) != 0) st_warn("signaling: could not subscribe %s", sg->devTopic);
    st_info("signaling ready (sub %s, %s)", sg->subTopic, sg->devTopic);
    return sg;
}

int signaling_publish(Signaling *sg, const char *dev_id, const char *json){
    if(!sg || !json) return -1;

    // The SDK hands us a DEVICE ID, not an MQTT topic — in the app,
    // IThingHomeCamera.publish() derives the real topic from it. Build
    // smart/mb/out/<devId> here; publishing to the bare id goes nowhere the
    // camera is listening.
    char topic[160];
    if(dev_id && *dev_id && strchr(dev_id, '/'))
        snprintf(topic, sizeof topic, "%s", dev_id);          // already a topic
    else if(dev_id && *dev_id)
        snprintf(topic, sizeof topic, "smart/mb/out/%s", dev_id);
    else
        snprintf(topic, sizeof topic, "%s", sg->pubTopic);

    // {data:<signaling>, protocol:302, t:<sec>} — fastjson emits keys sorted, so
    // build them in that order.
    JBuf b; jbuf_init(&b);
    jbuf_raw(&b, "{\"data\":");
    jbuf_raw(&b, json);
    jbuf_printf(&b, ",\"protocol\":302,\"t\":%lld}", (long long)time(NULL));

    size_t enc_len = 0;
    unsigned char *enc = crypto_aes_ecb_encrypt((const unsigned char*)sg->localKey, b.buf, &enc_len);
    jbuf_free(&b);
    if(!enc){ st_err("signaling: frame encryption failed"); return -1; }

    // body = s || o || enc ; frame = "2.2" || crc32(body) || body
    // The SDK publishes from several threads at once, so take the sequence number
    // under the lock — otherwise two frames go out with the same `s`.
    pthread_mutex_lock(&sg->lock);
    unsigned int seq = ++sg->seq_s;
    pthread_mutex_unlock(&sg->lock);

    size_t body_len = 8 + enc_len;
    unsigned char *body = malloc(body_len);
    if(!body){ free(enc); return -1; }
    put_be32(body,     seq);
    put_be32(body + 4, sg->seq_o);
    memcpy(body + 8, enc, enc_len);
    free(enc);

    size_t frame_len = 3 + 4 + body_len;
    unsigned char *frame = malloc(frame_len);
    if(!frame){ free(body); return -1; }
    memcpy(frame, "2.2", 3);
    put_be32(frame + 3, crypto_crc32(body, body_len));
    memcpy(frame + 7, body, body_len);
    free(body);

    pthread_mutex_lock(&sg->lock);
    int rc = mqtt_publish(sg->mq, topic, frame, frame_len);
    pthread_mutex_unlock(&sg->lock);
    st_debug("signaling -> %s (%zu bytes, s=%u)", topic, frame_len, seq);
    free(frame);
    return rc;
}

int signaling_wake(Signaling *sg){
    if(!sg) return -1;
    // m/w/<devId> with CRC32(localKey) big-endian — wakes a low-power camera.
    char topic[128];
    snprintf(topic, sizeof topic, "m/w/%s", sg->devId);
    unsigned char payload[4];
    put_be32(payload, crypto_crc32((const unsigned char*)sg->localKey, strlen(sg->localKey)));
    st_debug("signaling: wake -> %s", topic);
    pthread_mutex_lock(&sg->lock);
    int rc = mqtt_publish(sg->mq, topic, payload, sizeof payload);
    pthread_mutex_unlock(&sg->lock);
    return rc;
}

// Decode a pv-2.2 frame and hand the inner `data` to the caller's callback.
static void on_mqtt_message(const char *topic, const unsigned char *payload, size_t len, void *user){
    Signaling *sg = (Signaling*)user;
    if(!sg || len < 15){ st_debug("signaling: short frame on %s (%zu)", topic, len); return; }

    size_t plain_len = 0;
    unsigned char *plain = crypto_aes_ecb_decrypt((const unsigned char*)sg->localKey,
                                                 payload + 15, len - 15, &plain_len);
    if(!plain){ st_debug("signaling: could not decrypt frame on %s", topic); return; }

    JDoc *d = json_parse((const char*)plain);
    if(!d){
        st_debug("signaling: frame on %s was not JSON", topic);
        free(plain);
        return;
    }
    JNode *root = json_root(d);
    int protocol = (int)json_getn(root, "protocol", 0);
    JNode *data = json_get(root, "data");
    if(protocol == 302 && data){
        char *inner = json_dump(data);
        if(inner){
            st_debug("signaling <- %s (302)", topic);
            if(sg->cb) sg->cb(inner, sg->user);
            free(inner);
        }
    } else {
        st_debug("signaling: ignoring protocol %d on %s", protocol, topic);
    }
    json_free(d);
    free(plain);
}

int signaling_poll(Signaling *sg, int timeout_ms, signaling_on_message cb, void *user){
    if(!sg) return -1;
    pthread_mutex_lock(&sg->lock);
    sg->cb = cb;
    sg->user = user;
    int rc = mqtt_poll(sg->mq, timeout_ms, on_mqtt_message, sg);
    pthread_mutex_unlock(&sg->lock);
    return rc;
}

void signaling_stop(Signaling *sg){
    if(!sg) return;
    pthread_mutex_lock(&sg->lock);
    mqtt_close(sg->mq);
    sg->mq = NULL;
    pthread_mutex_unlock(&sg->lock);
    pthread_mutex_destroy(&sg->lock);
    free(sg);
}
