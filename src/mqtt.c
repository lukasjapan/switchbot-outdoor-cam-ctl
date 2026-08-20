#include "mqtt.h"
#include "http.h"     // net_connect / net_read / net_write
#include "status.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Control packet types (upper nibble of byte 0).
#define PKT_CONNECT     0x10
#define PKT_CONNACK     0x20
#define PKT_PUBLISH     0x30
#define PKT_PUBACK      0x40
#define PKT_SUBSCRIBE   0x82   // type 8 with the required flags 0x02
#define PKT_SUBACK      0x90
#define PKT_PINGREQ     0xC0
#define PKT_PINGRESP    0xD0
#define PKT_DISCONNECT  0xE0

struct MqttConn {
    NetConn *net;
    unsigned short packet_id;
    int keepalive;
    time_t last_send;
    // Inbound accumulator: TLS records do not align with MQTT packets.
    unsigned char *buf;
    size_t len, cap;
};

// ---- wire helpers ----------------------------------------------------------
typedef struct { unsigned char *p; size_t len, cap; } Wbuf;

static int w_need(Wbuf *w, size_t extra){
    if(w->len + extra <= w->cap) return 0;
    size_t nc = w->cap ? w->cap : 256;
    while(w->len + extra > nc) nc *= 2;
    unsigned char *np = realloc(w->p, nc);
    if(!np) return -1;
    w->p = np; w->cap = nc;
    return 0;
}
static int w_u8(Wbuf *w, unsigned char v){ if(w_need(w,1)) return -1; w->p[w->len++]=v; return 0; }
static int w_bytes(Wbuf *w, const void *b, size_t n){
    if(w_need(w,n)) return -1; memcpy(w->p + w->len, b, n); w->len += n; return 0;
}
// MQTT strings are big-endian uint16 length + bytes.
static int w_str(Wbuf *w, const char *s){
    size_t n = s ? strlen(s) : 0;
    if(n > 0xFFFF) return -1;
    if(w_u8(w, (unsigned char)(n >> 8)) || w_u8(w, (unsigned char)(n & 0xFF))) return -1;
    return n ? w_bytes(w, s, n) : 0;
}
// Remaining Length: 7 bits per byte, high bit = continuation.
static int w_varint(Wbuf *w, size_t v){
    do {
        unsigned char b = (unsigned char)(v & 0x7F);
        v >>= 7;
        if(v) b |= 0x80;
        if(w_u8(w, b)) return -1;
    } while(v);
    return 0;
}

// Send one packet: fixed header byte, then varint length, then the body.
static int send_packet(MqttConn *m, unsigned char type, const unsigned char *body, size_t n){
    Wbuf w = {0};
    if(w_u8(&w, type) || w_varint(&w, n) || (n && w_bytes(&w, body, n))){ free(w.p); return -1; }
    int rc = net_write(m->net, w.p, w.len);
    free(w.p);
    if(rc == 0) m->last_send = time(NULL);
    else st_debug("mqtt: write failed");
    return rc;
}

// Decode a Remaining Length starting at buf[off]. Returns bytes consumed, or -1
// if incomplete/malformed; *value gets the length.
static int read_varint(const unsigned char *buf, size_t len, size_t off, size_t *value){
    size_t v = 0; int shift = 0;
    for(int i = 0; i < 4; i++){
        if(off + (size_t)i >= len) return -1;          // need more bytes
        unsigned char b = buf[off + i];
        v |= (size_t)(b & 0x7F) << shift;
        if(!(b & 0x80)){ *value = v; return i + 1; }
        shift += 7;
    }
    return -1;
}

// Pull whatever is available into the accumulator.
static int fill(MqttConn *m, int timeout_ms){
    if(m->len + 4096 > m->cap){
        size_t nc = m->cap ? m->cap * 2 : 8192;
        while(m->len + 4096 > nc) nc *= 2;
        unsigned char *nb = realloc(m->buf, nc);
        if(!nb) return -1;
        m->buf = nb; m->cap = nc;
    }
    int r = net_read(m->net, m->buf + m->len, m->cap - m->len, timeout_ms);
    if(r > 0){ m->len += (size_t)r; return r; }
    if(r == 0) return 0;      // timeout or EOF; caller decides
    return -1;
}

// Extract one complete packet from the accumulator. Returns 1 if `*type`,
// `*body`, `*blen` were set (body points into m->buf), 0 if incomplete.
static int take_packet(MqttConn *m, unsigned char *type, const unsigned char **body, size_t *blen,
                       size_t *consumed){
    if(m->len < 2) return 0;
    size_t rem = 0;
    int vlen = read_varint(m->buf, m->len, 1, &rem);
    if(vlen < 0) return 0;
    size_t total = 1 + (size_t)vlen + rem;
    if(m->len < total) return 0;
    *type = m->buf[0];
    *body = m->buf + 1 + vlen;
    *blen = rem;
    *consumed = total;
    return 1;
}

static void drop_bytes(MqttConn *m, size_t n){
    if(n >= m->len){ m->len = 0; return; }
    memmove(m->buf, m->buf + n, m->len - n);
    m->len -= n;
}

// ---- public API ------------------------------------------------------------
MqttConn *mqtt_connect(const char *host, int port, int use_tls,
                       const char *client_id, const char *username, const char *password,
                       int keepalive_sec){
    if(!host || !client_id) return NULL;
    MqttConn *m = calloc(1, sizeof *m);
    if(!m) return NULL;
    m->keepalive = keepalive_sec > 0 ? keepalive_sec : 60;
    m->packet_id = 1;

    st_debug("mqtt: connecting to %s:%d (tls=%d)", host, port, use_tls ? 1 : 0);
    m->net = net_connect(host, port, use_tls);
    if(!m->net){ st_err("mqtt: cannot reach broker %s:%d", host, port); free(m); return NULL; }

    // CONNECT: "MQTT"/level 4, clean session, username+password present.
    Wbuf w = {0};
    unsigned char flags = 0x02;                       // clean session
    if(username && *username) flags |= 0x80;
    if(password && *password) flags |= 0x40;
    if(w_str(&w, "MQTT") || w_u8(&w, 4) || w_u8(&w, flags) ||
       w_u8(&w, (unsigned char)(m->keepalive >> 8)) || w_u8(&w, (unsigned char)(m->keepalive & 0xFF)) ||
       w_str(&w, client_id) ||
       ((flags & 0x80) && w_str(&w, username)) ||
       ((flags & 0x40) && w_str(&w, password))){
        free(w.p); mqtt_close(m); return NULL;
    }
    int rc = send_packet(m, PKT_CONNECT, w.p, w.len);
    free(w.p);
    if(rc != 0){ st_err("mqtt: CONNECT send failed"); mqtt_close(m); return NULL; }

    // Await CONNACK.
    for(int tries = 0; tries < 40; tries++){
        unsigned char type; const unsigned char *body; size_t blen, used;
        while(take_packet(m, &type, &body, &blen, &used)){
            if((type & 0xF0) == PKT_CONNACK){
                int code = blen >= 2 ? body[1] : 0xFF;
                drop_bytes(m, used);
                if(code != 0){
                    // 4 = bad username/password, 5 = not authorised.
                    st_err("mqtt: broker refused the connection (CONNACK 0x%02x)", code);
                    mqtt_close(m);
                    return NULL;
                }
                st_debug("mqtt: connected");
                return m;
            }
            drop_bytes(m, used);
        }
        if(fill(m, 500) < 0) break;
    }
    st_err("mqtt: no CONNACK from broker");
    mqtt_close(m);
    return NULL;
}

int mqtt_subscribe(MqttConn *m, const char *topic){
    if(!m || !topic) return -1;
    Wbuf w = {0};
    unsigned short pid = m->packet_id++;
    if(w_u8(&w, (unsigned char)(pid >> 8)) || w_u8(&w, (unsigned char)(pid & 0xFF)) ||
       w_str(&w, topic) || w_u8(&w, 1)){       // requested QoS 1
        free(w.p); return -1;
    }
    int rc = send_packet(m, PKT_SUBSCRIBE, w.p, w.len);
    free(w.p);
    if(rc != 0) return -1;

    for(int tries = 0; tries < 20; tries++){
        unsigned char type; const unsigned char *body; size_t blen, used;
        while(take_packet(m, &type, &body, &blen, &used)){
            int is_suback = (type & 0xF0) == PKT_SUBACK;
            int failed = is_suback && blen >= 3 && body[2] == 0x80;
            drop_bytes(m, used);
            if(is_suback){
                if(failed){ st_err("mqtt: subscribe to %s rejected", topic); return -1; }
                st_debug("mqtt: subscribed to %s", topic);
                return 0;
            }
        }
        if(fill(m, 500) < 0) return -1;
    }
    st_warn("mqtt: no SUBACK for %s (continuing)", topic);
    return 0;
}

int mqtt_publish(MqttConn *m, const char *topic, const unsigned char *payload, size_t len){
    if(!m || !topic) return -1;
    Wbuf w = {0};
    unsigned short pid = m->packet_id++;
    // QoS 1 => a packet identifier follows the topic.
    if(w_str(&w, topic) ||
       w_u8(&w, (unsigned char)(pid >> 8)) || w_u8(&w, (unsigned char)(pid & 0xFF)) ||
       (len && w_bytes(&w, payload, len))){
        free(w.p); return -1;
    }
    int rc = send_packet(m, PKT_PUBLISH | 0x02, w.p, w.len);
    free(w.p);
    return rc;
}

int mqtt_poll(MqttConn *m, int timeout_ms, mqtt_on_message cb, void *user){
    if(!m) return -1;

    // Keepalive: ping at roughly half the negotiated interval.
    if(difftime(time(NULL), m->last_send) >= m->keepalive / 2.0)
        if(send_packet(m, PKT_PINGREQ, NULL, 0) != 0) return -1;

    int r = fill(m, timeout_ms);
    if(r < 0) return -1;

    unsigned char type; const unsigned char *body; size_t blen, used;
    while(take_packet(m, &type, &body, &blen, &used)){
        unsigned char kind = type & 0xF0;
        if(kind == PKT_PUBLISH){
            unsigned char qos = (type >> 1) & 0x03;
            if(blen >= 2){
                size_t tlen = ((size_t)body[0] << 8) | body[1];
                if(2 + tlen <= blen){
                    char topic[512];
                    size_t tcopy = tlen < sizeof topic - 1 ? tlen : sizeof topic - 1;
                    memcpy(topic, body + 2, tcopy);
                    topic[tcopy] = 0;
                    size_t off = 2 + tlen;
                    unsigned short pid = 0;
                    if(qos > 0 && off + 2 <= blen){
                        pid = (unsigned short)((body[off] << 8) | body[off+1]);
                        off += 2;
                    }
                    if(cb && off <= blen) cb(topic, body + off, blen - off, user);
                    if(qos == 1){
                        unsigned char ack[2] = { (unsigned char)(pid >> 8), (unsigned char)(pid & 0xFF) };
                        send_packet(m, PKT_PUBACK, ack, sizeof ack);
                    }
                }
            }
        }
        // CONNACK/SUBACK/PUBACK/PINGRESP need no action here.
        drop_bytes(m, used);
    }
    return 0;
}

void mqtt_close(MqttConn *m){
    if(!m) return;
    if(m->net){
        send_packet(m, PKT_DISCONNECT, NULL, 0);
        net_close(m->net);
    }
    free(m->buf);
    free(m);
}
