#include "rawmedia.h"
#include "native.h"
#include "status.h"
#include "stream.h"

#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// libThingP2PSDK's C API (same signatures p2p_harness.c uses).
typedef int (*fn_senddata_t)(int session, unsigned channel, const unsigned char *buf, int len, int timeout_ms);
typedef int (*fn_recvdata_t)(int session, unsigned channel, unsigned char *buf, int *len, int timeout_ms);

#define CMD_CHANNEL   0     // ThingNetProtocolManager commands
#define MEDIA_CHANNEL 1     // Tuya-framed RTP, audio and video interleaved
#define PORT          0     // the camera's only video port

// ThingNetProtocolManager::AsyncSendCommand (high, low) pairs, from
// ThingCameraSimple::StartPreview/StopPreview. Every payload is 8 bytes:
// [port][value], where value is the clarity for SET_CLARITY and otherwise echoes
// the low id (StartPreview builds CONCAT44(3, port) for stop, CONCAT44(4, port)
// for open-audio, and a bare port for start-video).
#define CMD_SET_CLARITY 9, 0
#define CMD_START_VIDEO 6, 0
#define CMD_STOP_VIDEO  6, 3

static fn_senddata_t g_send;
static fn_recvdata_t g_real_recv;
static volatile int  g_session = -1;
static volatile int  g_tap;          // 1 while media reads are being taken over
static uint32_t      g_reqid;
static FILE         *g_dump;
static long          g_chunks;
// Held while the tap feeds, so rawmedia_stop can know no write is still in flight
// on the SDK's thread once it returns (the caller closes the stream next).
static pthread_mutex_t g_tap_lock = PTHREAD_MUTEX_INITIALIZER;

// Wire format (p2p_harness.c): magic | reqId | 0 | high(2) | low(2) | len | payload.
static int send_cmd(int session, int high, int low, uint32_t v0, uint32_t v1){
    unsigned char c[28];
    memset(c, 0, sizeof c);
    uint32_t magic = 0x12345678u, req = ++g_reqid, plen = 8;
    uint16_t h = (uint16_t)high, l = (uint16_t)low;
    memcpy(c + 0x00, &magic, 4);
    memcpy(c + 0x04, &req,   4);
    memcpy(c + 0x0c, &h,     2);
    memcpy(c + 0x0e, &l,     2);
    memcpy(c + 0x10, &plen,  4);
    memcpy(c + 0x14, &v0,    4);
    memcpy(c + 0x18, &v1,    4);
    int rc = g_send(session, CMD_CHANNEL, c, (int)sizeof c, 5000);
    st_debug("cmd %d/%d [%u,%u] on session %d -> %d", high, low, v0, v1, session, rc);
    return rc;
}

// ---- de-framer (C port of scripts/cam/tuya-media.ts) -----------------------
// Tuya frame header, little-endian: 24 bytes; if u32@16 != 0, 8 more, and if that
// block's byte 7 == 1, another 0x34; then a u32 length and that many bytes of one
// RTP packet. Frame type 1 is video; the rest (audio) is dropped for now.
typedef struct { unsigned char *p; size_t len, cap; } Buf;

static int buf_add(Buf *b, const unsigned char *d, size_t n){
    if(b->len + n > b->cap){
        size_t cap = b->cap ? b->cap : 65536;
        while(cap < b->len + n) cap *= 2;
        unsigned char *np = realloc(b->p, cap);
        if(!np) return -1;
        b->p = np; b->cap = cap;
    }
    memcpy(b->p + b->len, d, n);
    b->len += n;
    return 0;
}

static Buf         g_in;         // unparsed channel bytes
static Buf         g_nal;        // NAL being assembled (start code + FU pieces)
static const char *g_codec;      // decided by the first video packet's payload type
static int         g_h265;

static uint32_t rd32(const unsigned char *p){ uint32_t v; memcpy(&v, p, 4); return v; }
static unsigned rd16be(const unsigned char *p){ return (unsigned)p[0] << 8 | p[1]; }

static const unsigned char SC[4] = { 0, 0, 0, 1 };

static void emit(const unsigned char *nal, size_t n){
    g_nal.len = 0;
    if(buf_add(&g_nal, SC, 4) == 0 && buf_add(&g_nal, nal, n) == 0)
        stream_write_bytes(g_nal.p, g_nal.len);
}

// Fragmented NALs: FU-A (h264) and FU (h265) rebuild the NAL header and
// accumulate in g_nal behind the start code until the end bit.
static int g_fu_open;
static void fu_begin(const unsigned char *hdr, size_t hlen){
    g_nal.len = 0;
    g_fu_open = buf_add(&g_nal, SC, 4) == 0 && buf_add(&g_nal, hdr, hlen) == 0;
}
static void fu_part(const unsigned char *d, size_t n, int end){
    if(!g_fu_open) return;                  // missed the start — drop the rest
    if(buf_add(&g_nal, d, n) != 0){ g_fu_open = 0; return; }
    if(end){ stream_write_bytes(g_nal.p, g_nal.len); g_fu_open = 0; }
}

static void depkt_h264(const unsigned char *pl, size_t n){
    if(n < 1) return;
    int t = pl[0] & 0x1f;
    if(t >= 1 && t <= 23) emit(pl, n);
    else if(t == 24){                                   // STAP-A
        size_t o = 1;
        while(o + 2 <= n){ size_t sz = rd16be(pl + o); o += 2; if(o + sz > n) break; emit(pl + o, sz); o += sz; }
    } else if(t == 28 && n >= 2){                       // FU-A
        unsigned char fuh = pl[1];
        if(fuh & 0x80){ unsigned char h = (unsigned char)((pl[0] & 0xe0) | (fuh & 0x1f)); fu_begin(&h, 1); }
        fu_part(pl + 2, n - 2, fuh & 0x40);
    }
}

static void depkt_h265(const unsigned char *pl, size_t n){
    if(n < 2) return;
    int t = (pl[0] >> 1) & 0x3f;
    if(t < 48) emit(pl, n);
    else if(t == 48){                                   // AP
        size_t o = 2;
        while(o + 2 <= n){ size_t sz = rd16be(pl + o); o += 2; if(o + sz > n) break; emit(pl + o, sz); o += sz; }
    } else if(t == 49 && n >= 3){                       // FU
        unsigned char fuh = pl[2];
        if(fuh & 0x80){
            unsigned char h[2] = { (unsigned char)((pl[0] & 0x81) | ((fuh & 0x3f) << 1)), pl[1] };
            fu_begin(h, 2);
        }
        fu_part(pl + 3, n - 3, fuh & 0x40);
    }
}

static void handle_rtp(const unsigned char *p, size_t n){
    if(n <= 12) return;
    if(!g_codec){
        // Payload type 95 = H.265 (hd), 96 = H.264 (sd), as tuya-media.ts found.
        g_h265 = (p[1] & 0x7f) == 95;
        g_codec = g_h265 ? "h265" : "h264";
        st_info("live: camera is sending %s (rtp pt=%d)", g_codec, p[1] & 0x7f);
    }
    // Always a bare 12-byte RTP header, as tuya-media.ts has it. Do NOT honour the
    // CC/P bits: the camera sends a first byte of 0xa8 (P=1, CC=8) on most
    // packets, yet the payload — a well-formed FU-A — starts right at offset 12.
    if(g_h265) depkt_h265(p + 12, n - 12);
    else       depkt_h264(p + 12, n - 12);
}

// Largest plausible frame, and the most unparsed input we hold on to: a header
// that never resolves means we lost sync, so start over rather than grow forever.
#define MAX_FRAME   0xa00000
#define MAX_PENDING (16u << 20)

static void feed(const unsigned char *chunk, size_t n){
    if(buf_add(&g_in, chunk, n) != 0){ g_in.len = 0; return; }
    const unsigned char *b = g_in.p;
    size_t pos = 0, len = g_in.len;
    while(pos + 28 <= len){
        // Frame type: 2 on every video frame this camera has sent (tuya-media.ts
        // said 1 = video, which did not hold), so video is told apart by the RTP
        // payload type instead, in handle_rtp.
        uint32_t ftype = rd32(b + pos);
        if(ftype > 8) break;                            // desync guard, as in the TS
        size_t hp = pos + 24;
        if(rd32(b + pos + 16) != 0){
            if(hp + 8 > len) break;
            int flag = b[hp + 7]; hp += 8;
            if(flag == 1) hp += 0x34;
        }
        if(hp + 4 > len) break;
        uint32_t flen = rd32(b + hp); hp += 4;
        if(flen == 0 || flen > MAX_FRAME) break;
        if(hp + flen > len) break;                      // not all here yet
        if(flen > 1 && ((b[hp + 1] & 0x7f) == 95 || (b[hp + 1] & 0x7f) == 96))
            handle_rtp(b + hp, flen);
        pos = hp + flen;
    }
    if(pos){ memmove(g_in.p, g_in.p + pos, len - pos); g_in.len = len - pos; }
    if(g_in.len > MAX_PENDING){
        st_warn("media stream lost sync (%zu bytes unparsed) — resetting", g_in.len);
        g_in.len = 0;
    }
}

// ---- taking the media over from the camera SDK ---------------------------
// libThingCameraSDK runs its own reader on the media channel from the moment the
// session is up — preview or not — and it pulls through the dynamic symbol
// ThingP2PRecvData. A second reader of our own just splits the stream between the
// two of us (seen on the camera: RTP sequence jumping 0x09 -> 0x2c, frames arriving
// without their header, and the SDK itself complaining "rtp video package is too
// large"). So there is no reader here. Instead the executable exports its own
// ThingP2PRecvData (see the Dockerfile's --export-dynamic-symbol), which the
// loader binds the SDK's import to ahead of libThingP2PSDK's. Every call is
// forwarded to the real one; while `live` is tapping, media-channel bytes go to
// the de-framer and the SDK is told it got nothing — so it never has anything to
// decode. All other channels, and all calls outside `live`, pass through untouched.
__attribute__((visibility("default")))
int ThingP2PRecvData(int session, unsigned channel, unsigned char *buf, int *len, int timeout_ms){
    if(!g_real_recv){
        void *so = native_p2p_so();
        g_real_recv = so ? (fn_recvdata_t)dlsym(so, "ThingP2PRecvData") : NULL;
        if(!g_real_recv){ if(len) *len = 0; return -1; }
    }
    if(!g_tap || channel != MEDIA_CHANNEL || session != g_session || !len)
        return g_real_recv(session, channel, buf, len, timeout_ms);

    int rc = g_real_recv(session, channel, buf, len, timeout_ms);
    if(rc < 0 || *len <= 0) return rc;

    pthread_mutex_lock(&g_tap_lock);
    if(g_tap){
        if(g_chunks++ < 3)
            st_debug("media chunk %d bytes: %02x%02x%02x%02x %02x%02x%02x%02x", *len,
                     buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        if(g_dump) fwrite(buf, 1, (size_t)*len, g_dump);
        if(!stream_broken()) feed(buf, (size_t)*len);
        *len = 0;
    }
    pthread_mutex_unlock(&g_tap_lock);
    return rc;
}

int rawmedia_start(int session, int clarity){
    void *so = native_p2p_so();
    g_send      = so ? (fn_senddata_t)dlsym(so, "ThingP2PSendData") : NULL;
    g_real_recv = so ? (fn_recvdata_t)dlsym(so, "ThingP2PRecvData") : NULL;
    if(!g_send || !g_real_recv){ st_err("P2P SDK: no ThingP2PSendData/RecvData export"); return -1; }
    if(session < 0){ st_err("the P2P SDK reported no session handle"); return -1; }

    // OUTDOOR_CAM_DUMP_MEDIA=<path>: also write the channel's bytes, undecoded,
    // for working out the framing when the camera sends something new.
    const char *dump = getenv("OUTDOOR_CAM_DUMP_MEDIA");
    g_dump = dump && *dump ? fopen(dump, "wb") : NULL;

    // Tap before any command goes out, so the first keyframe is not lost to the SDK.
    g_codec = NULL; g_in.len = 0; g_fu_open = 0; g_chunks = 0;
    g_session = session;
    g_tap = 1;

    // StartPreview passes the clarity mode through to the wire unchanged; on the
    // camera, 2 gave 640x360 at 15 fps (the frame header's geometry block says so).
    if(send_cmd(g_session, CMD_SET_CLARITY, PORT, (uint32_t)clarity) < 0){
        st_err("set-clarity command was not sent");
        return -1;
    }
    usleep(200000);                                     // as the harness does

    if(send_cmd(g_session, CMD_START_VIDEO, PORT, 0) < 0){
        st_err("start-video command was not sent");
        return -1;
    }
    return 0;
}

void rawmedia_stop(void){
    if(g_session >= 0 && g_send) send_cmd(g_session, CMD_STOP_VIDEO, PORT, 3);
    // The tap runs on the SDK's thread. Taking the lock waits out a feed in
    // progress; after this every read passes through untouched.
    pthread_mutex_lock(&g_tap_lock);
    g_tap = 0;
    if(g_dump){ fclose(g_dump); g_dump = NULL; }
    pthread_mutex_unlock(&g_tap_lock);
    st_debug("media tap released after %ld chunks", g_chunks);
    g_session = -1;
}

const char *rawmedia_codec(void){ return g_codec; }
