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
#include <time.h>
#include <unistd.h>

// libThingP2PSDK's C API (same signatures p2p_harness.c uses).
typedef int (*fn_senddata_t)(int session, unsigned channel, const unsigned char *buf, int len, int timeout_ms);
typedef int (*fn_recvdata_t)(int session, unsigned channel, unsigned char *buf, int *len, int timeout_ms);

#define CMD_CHANNEL   0     // ThingNetProtocolManager commands
#define MEDIA_CHANNEL 1     // Tuya-framed RTP video
#define AUDIO_CHANNEL 2     // the same framing, PCM audio (seen in playback)
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
static fn_senddata_t g_real_send;
static fn_recvdata_t g_real_recv;
static volatile int  g_session = -1;
static volatile int  g_tap;          // 1 while media reads are being taken over
static uint32_t      g_reqid;
// OUTDOOR_CAM_TRACE_CMDS=1: log every command-channel packet in both directions,
// the SDK's included. How the playback path's commands were read off the wire.
static int           g_trace = -1;
// What the media channel carried, for the summary: packets per RTP payload type,
// and the frame header's own clock. Playback frames carry their recording time
// in ms (u64 at +8); the RTP timestamps there do not follow a 90 kHz clock.
static long          g_pt_count[128];
static unsigned long long g_ms_first, g_ms_last;
static long          g_ms_changes;
static double        g_wall_first, g_wall_last;   // when media bytes arrived
static long long     g_chan_bytes[8];             // bytes read per channel while tapping
static long          g_foreign_reads;             // media reads on some other session
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

static double now_s(void){
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
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

// One channel's byte stream, cut into Tuya frames. Video and audio share the
// framing: video on channel 1 (frame type 2 live, 5 in playback), audio on
// channel 2 (type 9, RTP payload type 99, 16-bit little-endian PCM).
typedef struct {
    Buf    in;
    long   skipped;      // bytes thrown away hunting for the next frame header
    void (*on_frame)(const unsigned char *hdr, const unsigned char *rtp, size_t len);
} Deframer;

// Whether a frame header plausibly starts at b: a known frame type, a length that
// fits, an RTP version 2 packet. 1 = yes, 0 = not all here yet, -1 = no.
static int frame_at(const unsigned char *b, size_t avail, size_t *rtp_off, size_t *rtp_len){
    if(avail < 28) return 0;
    // Low half: 2 on live video, 5 on playback video (high half 1), 9 on audio.
    uint32_t ftype = rd32(b) & 0xffff;
    if(ftype == 0 || ftype > 15) return -1;
    size_t hp = 24;
    if(rd32(b + 16) != 0){
        if(hp + 8 > avail) return 0;
        int flag = b[hp + 7]; hp += 8;
        if(flag == 1) hp += 0x34;
    }
    if(hp + 4 > avail) return 0;
    uint32_t flen = rd32(b + hp); hp += 4;
    if(flen < 12 || flen > MAX_FRAME) return -1;
    if((b[hp] & 0xc0) != 0x80 && hp < avail) return -1;   // RTP version 2
    if(hp + flen > avail) return 0;
    *rtp_off = hp; *rtp_len = flen;
    return 1;
}

static void deframe(Deframer *d, const unsigned char *chunk, size_t n){
    if(buf_add(&d->in, chunk, n) != 0){ d->in.len = 0; return; }
    const unsigned char *b = d->in.p;
    size_t pos = 0, len = d->in.len;
    while(pos < len){
        size_t off, flen;
        int r = frame_at(b + pos, len - pos, &off, &flen);
        if(r == 0) break;                               // wait for more bytes
        if(r < 0){                                      // lost: hunt for the next header
            pos++;
            d->skipped++;
            continue;
        }
        d->on_frame(b + pos, b + pos + off, flen);
        pos += off + flen;
    }
    if(pos){ memmove(d->in.p, d->in.p + pos, len - pos); d->in.len = len - pos; }
    if(d->in.len > MAX_PENDING){
        st_warn("media stream lost sync (%zu bytes unparsed) — resetting", d->in.len);
        d->in.len = 0;
    }
}

static void on_video(const unsigned char *hdr, const unsigned char *rtp, size_t len){
    int pt = rtp[1] & 0x7f;
    g_pt_count[pt]++;
    if(pt != 95 && pt != 96) return;
    unsigned long long ms;
    memcpy(&ms, hdr + 8, 8);
    if(g_ms_changes == 0 || ms != g_ms_last){
        if(g_ms_changes == 0) g_ms_first = ms;
        g_ms_last = ms;
        g_ms_changes++;
    }
    handle_rtp(rtp, len);
}

static FILE              *g_audio;
static long               g_audio_bytes;
static unsigned long long g_audio_ms_first;

static void on_audio(const unsigned char *hdr, const unsigned char *rtp, size_t len){
    int pt = rtp[1] & 0x7f;
    g_pt_count[pt]++;
    if(pt != 99 || !g_audio || len <= 12) return;
    if(g_audio_bytes == 0) memcpy(&g_audio_ms_first, hdr + 8, 8);
    // A bare 12-byte RTP header, as on the video side; the rest is the samples.
    if(fwrite(rtp + 12, 1, len - 12, g_audio) == len - 12) g_audio_bytes += (long)(len - 12);
}

static Deframer g_vdf = { .on_frame = on_video };
static Deframer g_adf = { .on_frame = on_audio };

static void feed(const unsigned char *chunk, size_t n){ deframe(&g_vdf, chunk, n); }

// ---- the command channel, observed -----------------------------------------
static int tracing(void){
    if(g_trace < 0){ const char *e = getenv("OUTDOOR_CAM_TRACE_CMDS"); g_trace = e && *e && *e != '0'; }
    return g_trace;
}

// One read or write on channel 0 may hold several packets; walk them by their
// length field and logs each. Only the SDK's own commands carry the magic; the
// camera's replies do not, and are logged raw.
static void observe_cmds(const char *dir, const unsigned char *b, int n){
    int pos = 0;
    while(pos + 20 <= n){
        if(rd32(b + pos) != 0x12345678u){
            if(tracing()){
                char hex[3 * 48 + 1] = "";
                for(int i = 0; i < 48 && pos + i < n; i++) snprintf(hex + 3 * i, 4, "%02x ", b[pos + i]);
                st_info("cmd %s %d bytes, no magic: %s", dir, n - pos, hex);
            }
            return;
        }
        unsigned high, low;
        { uint16_t h, l; memcpy(&h, b + pos + 0x0c, 2); memcpy(&l, b + pos + 0x0e, 2); high = h; low = l; }
        uint32_t plen = rd32(b + pos + 0x10);
        if(tracing()){
            char hex[3 * 64 + 1] = "";
            size_t show = plen < 64 ? plen : 64;
            for(size_t i = 0; i < show && pos + 20 + (int)i < n; i++)
                snprintf(hex + 3 * i, 4, "%02x ", b[pos + 20 + i]);
            st_info("cmd %s 0x%x/%u req=%u len=%u: %s", dir, high, low,
                    rd32(b + pos + 4), plen, hex);
        }
        if(plen > (uint32_t)n) return;
        pos += 20 + (int)plen;
    }
}

// Exported like ThingP2PRecvData, so the SDK's own commands pass through here:
// forwarded unchanged, and only looked at.
__attribute__((visibility("default")))
int ThingP2PSendData(int session, unsigned channel, const unsigned char *buf, int len, int timeout_ms){
    if(!g_real_send){
        void *so = native_p2p_so();
        g_real_send = so ? (fn_senddata_t)dlsym(so, "ThingP2PSendData") : NULL;
        if(!g_real_send) return -1;
    }
    if(channel == CMD_CHANNEL && buf && len > 0 && tracing()) observe_cmds(">", buf, len);
    return g_real_send(session, channel, buf, len, timeout_ms);
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
// forwarded to the real one; while `live --native` is tapping, media-channel bytes go to
// the de-framer and the SDK is told it got nothing — so it never has anything to
// decode. All other channels, and all calls outside `live --native`, pass through untouched.
__attribute__((visibility("default")))
int ThingP2PRecvData(int session, unsigned channel, unsigned char *buf, int *len, int timeout_ms){
    if(!g_real_recv){
        void *so = native_p2p_so();
        g_real_recv = so ? (fn_recvdata_t)dlsym(so, "ThingP2PRecvData") : NULL;
        if(!g_real_recv){ if(len) *len = 0; return -1; }
    }
    // Audio: copied out, and still handed to the SDK — PCM costs it nothing.
    if(channel == AUDIO_CHANNEL && g_tap && session == g_session && len){
        int rc = g_real_recv(session, channel, buf, len, timeout_ms);
        if(rc >= 0 && *len > 0){
            pthread_mutex_lock(&g_tap_lock);
            g_chan_bytes[AUDIO_CHANNEL] += *len;
            if(g_tap && g_audio) deframe(&g_adf, buf, (size_t)*len);
            pthread_mutex_unlock(&g_tap_lock);
        }
        return rc;
    }
    if(channel == CMD_CHANNEL && tracing() && len){
        int rc = g_real_recv(session, channel, buf, len, timeout_ms);
        if(rc >= 0 && *len > 0) observe_cmds("<", buf, *len);
        return rc;
    }
    if(g_tap && channel == MEDIA_CHANNEL && session != g_session) g_foreign_reads++;
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
        g_wall_last = now_s();
        if(g_wall_first == 0) g_wall_first = g_wall_last;
        g_chan_bytes[MEDIA_CHANNEL] += *len;
        if(!stream_broken()) feed(buf, (size_t)*len);
        *len = 0;
    }
    pthread_mutex_unlock(&g_tap_lock);
    return rc;
}

int rawmedia_tap(int session){
    void *so = native_p2p_so();
    g_send      = so ? (fn_senddata_t)dlsym(so, "ThingP2PSendData") : NULL;
    g_real_recv = so ? (fn_recvdata_t)dlsym(so, "ThingP2PRecvData") : NULL;
    if(!g_send || !g_real_recv){ st_err("P2P SDK: no ThingP2PSendData/RecvData export"); return -1; }
    if(session < 0){ st_err("the P2P SDK reported no session handle"); return -1; }

    // OUTDOOR_CAM_DUMP_MEDIA=<path>: also write the channel's bytes, undecoded,
    // for working out the framing when the camera sends something new.
    const char *dump = getenv("OUTDOOR_CAM_DUMP_MEDIA");
    g_dump = dump && *dump ? fopen(dump, "wb") : NULL;

    g_codec = NULL; g_vdf.in.len = 0; g_vdf.skipped = 0; g_adf.in.len = 0; g_adf.skipped = 0;
    g_fu_open = 0; g_chunks = 0; g_foreign_reads = 0; g_audio_bytes = 0;
    g_ms_changes = 0; g_wall_first = g_wall_last = 0;
    memset(g_chan_bytes, 0, sizeof g_chan_bytes);
    memset(g_pt_count, 0, sizeof g_pt_count);
    g_session = session;
    g_tap = 1;
    return 0;
}

int rawmedia_start(int session, int clarity){
    // Tap before any command goes out, so the first keyframe is not lost to the SDK.
    if(rawmedia_tap(session) != 0) return -1;

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
    rawmedia_untap();
}

void rawmedia_untap(void){
    // The tap runs on the SDK's thread. Taking the lock waits out a feed in
    // progress; after this every read passes through untouched.
    pthread_mutex_lock(&g_tap_lock);
    g_tap = 0;
    if(g_dump){ fclose(g_dump); g_dump = NULL; }
    if(g_audio){ fclose(g_audio); g_audio = NULL; }
    pthread_mutex_unlock(&g_tap_lock);
    st_debug("media tap released after %ld chunks", g_chunks);
    g_session = -1;
}

const char *rawmedia_codec(void){ return g_codec; }

void rawmedia_summary(void){
    for(int pt = 0; pt < 128; pt++)
        if(g_pt_count[pt]) st_info("media: rtp pt=%d: %ld packets", pt, g_pt_count[pt]);
    if(g_ms_changes > 1){
        double secs = (double)(g_ms_last - g_ms_first) / 1000.0;
        st_info("media: %ld video frames covering %.2fs (%.2f fps), received over %.2fs",
                g_ms_changes, secs, secs > 0 ? (double)(g_ms_changes - 1) / secs : 0.0,
                g_wall_last - g_wall_first);
    }
    if(g_audio_bytes > 0)
        st_info("media: %ld bytes of audio (%.2fs at 8 kHz s16le), starting %+lld ms from the video",
                g_audio_bytes, (double)g_audio_bytes / 16000.0,
                (long long)(g_audio_ms_first - g_ms_first));
    if(g_vdf.skipped || g_adf.skipped)
        st_warn("media: resynced past %ld video / %ld audio bytes", g_vdf.skipped, g_adf.skipped);
    if(g_foreign_reads) st_warn("media: %ld reads on a session other than the tapped one", g_foreign_reads);
    for(int c = 1; c < 8; c++)
        if(g_chan_bytes[c]) st_debug("media: channel %d: %lld bytes", c, g_chan_bytes[c]);
}

int rawmedia_audio_out(const char *path){
    g_audio = fopen(path, "wb");
    if(!g_audio){ st_err("cannot open %s for writing", path); return -1; }
    return 0;
}

unsigned long long rawmedia_last_ms(void){ return g_ms_changes ? g_ms_last : 0; }
