#include "stream.h"
#include "status.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int  g_fd = -1;
static int  g_own_fd;           // 1 when we opened a file (so we must close it)
static int  g_w, g_h, g_fps;
static long g_frames;
static int  g_broken;
static int  g_geom_warned;

// How long the destination may refuse to accept bytes before we give up.
//
// This is the whole reason writes are bounded. When a consumer on the far side of
// `docker compose run` exits, we do NOT get EPIPE: the break is between the docker
// CLI and that consumer, outside the container. The CLI dies, the daemon stops
// draining our stdout, the pipe fills, and a plain write() blocks forever — with
// the container still alive and still holding the camera session open. Bounding the
// wait turns that hang into a clean teardown.
#define STALL_LIMIT_MS 8000
#define POLL_SLICE_MS  500

static int write_all(const void *buf, size_t len){
    const char *p = (const char *)buf;
    int stalled_ms = 0;
    while(len){
        struct pollfd pfd;
        pfd.fd = g_fd; pfd.events = POLLOUT; pfd.revents = 0;
        int pr = poll(&pfd, 1, POLL_SLICE_MS);
        if(pr < 0){
            if(errno == EINTR) continue;
            return -1;
        }
        if(pr == 0){                       // nobody is reading right now
            stalled_ms += POLL_SLICE_MS;
            if(stalled_ms >= STALL_LIMIT_MS){ errno = ETIMEDOUT; return -1; }
            continue;
        }
        if(pfd.revents & (POLLERR | POLLHUP | POLLNVAL)){ errno = EPIPE; return -1; }

        ssize_t n = write(g_fd, p, len);
        if(n < 0){
            if(errno == EINTR || errno == EAGAIN) continue;
            return -1;                     // EPIPE lands here when it does arrive
        }
        p += n; len -= (size_t)n;
        stalled_ms = 0;
    }
    return 0;
}

// Raw fds throughout rather than stdio: we need poll() on the descriptor, and a
// FILE* would also buffer frames instead of releasing them as they are produced.
static int open_dest(const char *out){
    g_frames = 0; g_broken = 0; g_geom_warned = 0;
    if(!out || !*out || !strcmp(out, "-")){
        g_fd = STDOUT_FILENO;
        g_own_fd = 0;
    } else {
        g_fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if(g_fd < 0){ st_err("cannot open %s for writing", out); return -1; }
        g_own_fd = 1;
    }
    return 0;
}

static void report_write_failure(void){
    g_broken = 1;
    if(errno == ETIMEDOUT)
        st_err("output stopped being read for %ds — assuming the consumer is "
               "gone, stopping after %ld frames", STALL_LIMIT_MS / 1000, g_frames);
    else if(errno == EPIPE)
        st_info("output closed after %ld frames", g_frames);
    else
        st_err("write failed after %ld frames: %s", g_frames, strerror(errno));
}

int stream_open_bytes(const char *out){ return open_dest(out); }

void stream_write_bytes(const uint8_t *buf, size_t len){
    if(g_fd < 0 || g_broken || !buf || !len) return;
    if(write_all(buf, len) != 0){ report_write_failure(); return; }
    g_frames++;
}

int stream_open(const char *out, int w, int h, int fps){
    g_w = w; g_h = h; g_fps = fps > 0 ? fps : 15;
    if(open_dest(out) != 0) return -1;

    // YUV4MPEG2 stream header. Ip = progressive, A1:1 = square pixels,
    // C420mpeg2 = 4:2:0 planar. Written up front so a consumer that attaches
    // immediately can identify the stream before the first frame lands.
    char hdr[128];
    int n = snprintf(hdr, sizeof hdr, "YUV4MPEG2 W%d H%d F%d:1 Ip A1:1 C420mpeg2\n",
                     g_w, g_h, g_fps);
    if(n <= 0 || write_all(hdr, (size_t)n) != 0){
        st_err("cannot write the stream header");
        g_broken = 1;
        return -1;
    }

    st_info("live: %dx%d Y4M (yuv420p), nominal %d fps", g_w, g_h, g_fps);
    st_info("play with: ffplay -i pipe:0     (or: ffplay -)");
    return 0;
}

void stream_write_frame(const uint8_t *y, size_t ylen,
                        const uint8_t *u, size_t ulen,
                        const uint8_t *v, size_t vlen){
    if(g_fd < 0 || g_broken) return;
    if(!y || !u || !v || !ylen || !ulen || !vlen) return;

    // The header has committed to a geometry, so a mismatch here means the stream
    // is mislabelled and the picture will shear. Say so once rather than emit
    // something quietly wrong.
    if(!g_geom_warned){
        size_t want_y = (size_t)g_w * (size_t)g_h;
        if(ylen != want_y || ulen != want_y / 4 || vlen != want_y / 4){
            st_err("frame planes do not match the declared %dx%d "
                   "(y=%zu u=%zu v=%zu) — the picture will be wrong",
                   g_w, g_h, ylen, ulen, vlen);
            g_geom_warned = 1;
        }
    }

    // One Y4M frame: the FRAME magic, then the planes in I420 order.
    if(write_all("FRAME\n", 6) != 0 ||
       write_all(y, ylen) != 0 ||
       write_all(u, ulen) != 0 ||
       write_all(v, vlen) != 0){
        report_write_failure();
        return;
    }
    g_frames++;
}

long stream_frame_count(void){ return g_frames; }
int  stream_broken(void){ return g_broken; }

void stream_close(void){
    if(g_fd < 0) return;
    if(g_own_fd) close(g_fd);
    g_fd = -1;
    g_own_fd = 0;
}
