#include "http.h"
#include "status.h"

#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// ---- OpenSSL 1.1 via dlsym -------------------------------------------------
// No headers available, so declare only what we use. Types stay opaque (void*).
typedef void SSL_CTX_t; typedef void SSL_t; typedef void SSL_METHOD_t;

static struct {
    int   (*OPENSSL_init_ssl)(unsigned long long, const void*);
    const SSL_METHOD_t *(*TLS_client_method)(void);
    SSL_CTX_t *(*SSL_CTX_new)(const SSL_METHOD_t*);
    void  (*SSL_CTX_free)(SSL_CTX_t*);
    int   (*SSL_CTX_set_default_verify_paths)(SSL_CTX_t*);
    int   (*SSL_CTX_load_verify_locations)(SSL_CTX_t*, const char*, const char*);
    void  (*SSL_CTX_set_verify)(SSL_CTX_t*, int, void*);
    SSL_t *(*SSL_new)(SSL_CTX_t*);
    void  (*SSL_free)(SSL_t*);
    int   (*SSL_set_fd)(SSL_t*, int);
    int   (*SSL_connect)(SSL_t*);
    int   (*SSL_read)(SSL_t*, void*, int);
    int   (*SSL_write)(SSL_t*, const void*, int);
    int   (*SSL_shutdown)(SSL_t*);
    int   (*SSL_get_error)(const SSL_t*, int);
    long  (*SSL_ctrl)(SSL_t*, int, long, void*);
    int   (*SSL_set1_host)(SSL_t*, const char*);
    long  (*SSL_get_verify_result)(const SSL_t*);
    int   loaded;
} S;

// SSL_set_tlsext_host_name is a macro over SSL_ctrl in OpenSSL.
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_host_name     0
#define SSL_VERIFY_PEER               1
#define SSL_ERROR_WANT_READ           2
#define SSL_ERROR_WANT_WRITE          3
#define SSL_ERROR_SYSCALL             5

static int ssl_load(void){
    if(S.loaded) return S.loaded > 0 ? 0 : -1;
    void *lc = dlopen("libcrypto.1.1.so", RTLD_NOW | RTLD_GLOBAL);
    void *ls = dlopen("libssl.1.1.so",    RTLD_NOW | RTLD_GLOBAL);
    if(!ls || !lc){ st_err("TLS unavailable: %s", dlerror()); S.loaded = -1; return -1; }
    #define SYM(f) do{ *(void**)&S.f = dlsym(ls, #f); if(!S.f){ st_err("libssl: missing %s", #f); S.loaded=-1; return -1; } }while(0)
    SYM(OPENSSL_init_ssl); SYM(TLS_client_method);
    SYM(SSL_CTX_new); SYM(SSL_CTX_free); SYM(SSL_CTX_set_default_verify_paths);
    SYM(SSL_CTX_load_verify_locations); SYM(SSL_CTX_set_verify);
    SYM(SSL_new); SYM(SSL_free); SYM(SSL_set_fd); SYM(SSL_connect);
    SYM(SSL_read); SYM(SSL_write); SYM(SSL_shutdown); SYM(SSL_get_error);
    SYM(SSL_ctrl); SYM(SSL_set1_host); SYM(SSL_get_verify_result);
    #undef SYM
    S.OPENSSL_init_ssl(0, NULL);
    S.loaded = 1;
    return 0;
}

// ---- URL parsing -----------------------------------------------------------
typedef struct { char scheme[8], host[256], path[1024]; int port, tls; } Url;

static int url_parse(const char *url, Url *u){
    memset(u, 0, sizeof *u);
    const char *p = strstr(url, "://");
    if(!p){ st_err("bad url '%s'", url); return -1; }
    size_t sl = (size_t)(p - url);
    if(sl >= sizeof u->scheme){ st_err("bad url scheme"); return -1; }
    memcpy(u->scheme, url, sl); u->scheme[sl] = 0;
    u->tls = !strcmp(u->scheme, "https");
    u->port = u->tls ? 443 : 80;

    const char *h = p + 3;
    const char *slash = strchr(h, '/');
    const char *colon = memchr(h, ':', slash ? (size_t)(slash - h) : strlen(h));
    size_t hl = colon ? (size_t)(colon - h) : (slash ? (size_t)(slash - h) : strlen(h));
    if(hl >= sizeof u->host){ st_err("host too long"); return -1; }
    memcpy(u->host, h, hl); u->host[hl] = 0;
    if(colon) u->port = atoi(colon + 1);
    snprintf(u->path, sizeof u->path, "%s", slash ? slash : "/");
    return 0;
}

// ---- DNS -------------------------------------------------------------------
// bionic's getaddrinfo() resolves nameservers from Android system properties,
// which do not exist under qemu-user in a plain Linux container — so it always
// fails here. Resolve A records ourselves with a direct UDP query to the
// nameserver in /etc/resolv.conf.

static int dns_nameserver(struct sockaddr_in *ns){
    FILE *f = fopen("/etc/resolv.conf", "r");
    if(!f) return -1;
    char line[256];
    int found = 0;
    while(fgets(line, sizeof line, f)){
        char ip[128];
        if(sscanf(line, " nameserver %127s", ip) == 1){
            memset(ns, 0, sizeof *ns);
            ns->sin_family = AF_INET;
            ns->sin_port = htons(53);
            if(inet_pton(AF_INET, ip, &ns->sin_addr) == 1){ found = 1; break; }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

// Skip a (possibly compression-pointer) encoded name; returns bytes consumed.
static int dns_skip_name(const unsigned char *m, size_t len, size_t off){
    size_t start = off;
    while(off < len){
        unsigned c = m[off];
        if((c & 0xC0) == 0xC0) return (int)(off + 2 - start);   // pointer ends the name
        if(c == 0) return (int)(off + 1 - start);
        off += c + 1;
    }
    return -1;
}

static int dns_query_a(const char *host, struct in_addr *out){
    struct sockaddr_in ns;
    if(dns_nameserver(&ns) != 0){ st_debug("no nameserver in /etc/resolv.conf"); return -1; }

    unsigned char q[512];
    size_t n = 0;
    unsigned short id = (unsigned short)(getpid() & 0xFFFF);
    q[n++] = (unsigned char)(id >> 8); q[n++] = (unsigned char)id;
    q[n++] = 0x01; q[n++] = 0x00;      // recursion desired
    q[n++] = 0; q[n++] = 1;            // qdcount = 1
    q[n++] = 0; q[n++] = 0;            // ancount
    q[n++] = 0; q[n++] = 0;            // nscount
    q[n++] = 0; q[n++] = 0;            // arcount
    // QNAME: length-prefixed labels
    const char *p = host;
    while(*p && n < sizeof q - 6){
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if(l == 0 || l > 63) return -1;
        q[n++] = (unsigned char)l;
        memcpy(q + n, p, l); n += l;
        if(!dot) break;
        p = dot + 1;
    }
    q[n++] = 0;
    q[n++] = 0; q[n++] = 1;            // QTYPE  = A
    q[n++] = 0; q[n++] = 1;            // QCLASS = IN

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd < 0) return -1;
    struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    if(sendto(fd, q, n, 0, (struct sockaddr*)&ns, sizeof ns) < 0){ close(fd); return -1; }

    unsigned char r[1024];
    ssize_t rn = recv(fd, r, sizeof r, 0);
    close(fd);
    if(rn < 12) return -1;

    unsigned qd = (unsigned)(r[4] << 8 | r[5]), an = (unsigned)(r[6] << 8 | r[7]);
    if(an == 0) return -1;
    size_t off = 12;
    for(unsigned i = 0; i < qd; i++){
        int s = dns_skip_name(r, (size_t)rn, off);
        if(s < 0) return -1;
        off += (size_t)s + 4;                       // + QTYPE/QCLASS
    }
    for(unsigned i = 0; i < an && off + 10 <= (size_t)rn; i++){
        int s = dns_skip_name(r, (size_t)rn, off);
        if(s < 0) return -1;
        off += (size_t)s;
        unsigned type = (unsigned)(r[off] << 8 | r[off+1]);
        unsigned rdlen = (unsigned)(r[off+8] << 8 | r[off+9]);
        off += 10;
        if(type == 1 && rdlen == 4 && off + 4 <= (size_t)rn){   // A record
            memcpy(&out->s_addr, r + off, 4);
            return 0;
        }
        off += rdlen;                                // CNAME etc: keep walking
    }
    return -1;
}

// ---- transport -------------------------------------------------------------
typedef struct { int fd; SSL_t *ssl; SSL_CTX_t *ctx; } Conn;

static int conn_open(Conn *c, const Url *u){
    memset(c, 0, sizeof *c); c->fd = -1;

    int fd = -1;
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", u->port);

    // Numeric host, or a resolver that happens to work: try getaddrinfo first.
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if(getaddrinfo(u->host, portstr, &hints, &res) == 0 && res){
        for(struct addrinfo *ai = res; ai; ai = ai->ai_next){
            fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if(fd < 0) continue;
            if(connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
            close(fd); fd = -1;
        }
        freeaddrinfo(res);
    }

    if(fd < 0){                                   // bionic resolver unusable
        struct in_addr addr;
        if(dns_query_a(u->host, &addr) != 0){
            st_err("dns lookup failed for %s", u->host);
            return -1;
        }
        char dotted[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &addr, dotted, sizeof dotted);
        st_debug("resolved %s -> %s (direct dns)", u->host, dotted);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET; sa.sin_port = htons((unsigned short)u->port); sa.sin_addr = addr;
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if(fd >= 0 && connect(fd, (struct sockaddr*)&sa, sizeof sa) != 0){ close(fd); fd = -1; }
    }

    if(fd < 0){ st_err("connect to %s:%d failed", u->host, u->port); return -1; }
    c->fd = fd;

    if(!u->tls) return 0;
    if(ssl_load() != 0) { close(fd); c->fd = -1; return -1; }

    c->ctx = S.SSL_CTX_new(S.TLS_client_method());
    if(!c->ctx){ st_err("SSL_CTX_new failed"); close(fd); c->fd = -1; return -1; }
    // Verify against a real CA bundle. This OpenSSL was built for Android, so
    // its compiled-in default path is an Android one that does not exist here;
    // set_default_verify_paths() still reports success, so load the container's
    // bundle explicitly (ca-certificates is installed in the Dockerfile) and
    // only fall back to the defaults if no known bundle is present.
    static const char *ca_files[] = {
        "/etc/ssl/certs/ca-certificates.crt",   // Debian/Ubuntu (our image)
        "/etc/pki/tls/certs/ca-bundle.crt",     // RHEL/Fedora
        "/etc/ssl/cert.pem",                    // Alpine/BSD
        NULL
    };
    const char *ca_env = getenv("OUTDOOR_CAM_CA_BUNDLE");
    int ca_ok = 0;
    if(ca_env && *ca_env)
        ca_ok = S.SSL_CTX_load_verify_locations(c->ctx, ca_env, NULL) == 1;
    for(int i = 0; !ca_ok && ca_files[i]; i++)
        if(S.SSL_CTX_load_verify_locations(c->ctx, ca_files[i], "/etc/ssl/certs") == 1){
            st_debug("CA bundle: %s", ca_files[i]); ca_ok = 1;
        }
    if(!ca_ok){
        S.SSL_CTX_set_default_verify_paths(c->ctx);
        st_debug("CA bundle: falling back to OpenSSL defaults");
    }
    S.SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);

    c->ssl = S.SSL_new(c->ctx);
    if(!c->ssl){ st_err("SSL_new failed"); return -1; }
    S.SSL_set_fd(c->ssl, fd);
    S.SSL_ctrl(c->ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void*)u->host); // SNI
    S.SSL_set1_host(c->ssl, u->host);                                                            // hostname check
    if(S.SSL_connect(c->ssl) != 1){
        st_err("TLS handshake with %s failed (verify=%ld)", u->host, S.SSL_get_verify_result(c->ssl));
        return -1;
    }
    return 0;
}

static void conn_close(Conn *c){
    if(c->ssl){ S.SSL_shutdown(c->ssl); S.SSL_free(c->ssl); c->ssl = NULL; }
    if(c->ctx){ S.SSL_CTX_free(c->ctx); c->ctx = NULL; }
    if(c->fd >= 0){ close(c->fd); c->fd = -1; }
}

static int conn_write(Conn *c, const char *buf, size_t n){
    size_t off = 0;
    while(off < n){
        int w = c->ssl ? S.SSL_write(c->ssl, buf + off, (int)(n - off))
                       : (int)write(c->fd, buf + off, n - off);
        if(w <= 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

// Returns >0 bytes read, 0 for "nothing available yet" (receive timeout / clean
// EOF), -1 for a real failure. Distinguishing the timeout case matters for the
// MQTT poll loop, which would otherwise treat every idle tick as a dropped link.
static int conn_read(Conn *c, char *buf, size_t cap){
    if(c->ssl){
        int r = S.SSL_read(c->ssl, buf, (int)cap);
        if(r > 0) return r;
        int err = S.SSL_get_error(c->ssl, r);
        if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return 0;
        if(err == SSL_ERROR_SYSCALL && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
        return r == 0 ? 0 : -1;      // 0 => peer closed cleanly
    }
    int r = (int)read(c->fd, buf, cap);
    if(r > 0) return r;
    if(r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    return r < 0 ? -1 : 0;
}

// ---- HTTP ------------------------------------------------------------------
void http_response_free(HttpResponse *r){
    if(!r) return; free(r->body); r->body = NULL; r->body_len = 0;
}

int http_request(const char *method, const char *url,
                 const char *const *headers, const char *body,
                 HttpResponse *out){
    memset(out, 0, sizeof *out);
    Url u;
    if(url_parse(url, &u) != 0) return -1;
    st_debug("%s %s", method, url);

    Conn c;
    if(conn_open(&c, &u) != 0){ conn_close(&c); return -1; }

    // Request. Connection: close keeps response framing simple (read to EOF).
    size_t blen = body ? strlen(body) : 0;
    char head[8192];
    int hn = snprintf(head, sizeof head,
        "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept: */*\r\n",
        method, u.path, u.host);
    for(const char *const *h = headers; h && *h && hn < (int)sizeof head; h++)
        hn += snprintf(head + hn, sizeof head - (size_t)hn, "%s\r\n", *h);
    if(body) hn += snprintf(head + hn, sizeof head - (size_t)hn, "Content-Length: %zu\r\n", blen);
    hn += snprintf(head + hn, sizeof head - (size_t)hn, "\r\n");
    if(hn <= 0 || hn >= (int)sizeof head){ st_err("request headers too large"); conn_close(&c); return -1; }

    if(conn_write(&c, head, (size_t)hn) != 0 || (body && conn_write(&c, body, blen) != 0)){
        st_err("sending request to %s failed", u.host); conn_close(&c); return -1;
    }

    // Response: accumulate everything, then split head/body.
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    if(!buf){ conn_close(&c); return -1; }
    for(;;){
        if(len + 8192 > cap){ cap *= 2; char *nb = realloc(buf, cap); if(!nb){ free(buf); conn_close(&c); return -1; } buf = nb; }
        int r = conn_read(&c, buf + len, cap - len - 1);
        if(r <= 0) break;
        len += (size_t)r;
    }
    buf[len] = 0;
    conn_close(&c);

    if(len == 0){ st_err("empty response from %s", u.host); free(buf); return -1; }

    if(sscanf(buf, "HTTP/%*d.%*d %d", &out->status) != 1){
        st_err("malformed response from %s", u.host); free(buf); return -1;
    }
    char *sep = strstr(buf, "\r\n\r\n");
    char *bodyp = sep ? sep + 4 : buf;

    // De-chunk if needed (servers honour Connection: close but may still chunk).
    int chunked = 0;
    if(sep){
        size_t headlen = (size_t)(sep - buf);
        for(char *p = buf; p < buf + headlen; p++)
            if((*p=='T'||*p=='t') && !strncasecmp(p, "Transfer-Encoding:", 18) &&
               strncasecmp(p, "Transfer-Encoding: identity", 27)) { chunked = 1; break; }
    }
    size_t blen_out = len - (size_t)(bodyp - buf);
    char *result;
    if(chunked){
        result = malloc(blen_out + 1); size_t o = 0; char *p = bodyp;
        while(p < buf + len){
            char *eol = strstr(p, "\r\n"); if(!eol) break;
            long sz = strtol(p, NULL, 16);
            if(sz <= 0) break;
            p = eol + 2;
            if(p + sz > buf + len) sz = (buf + len) - p;
            memcpy(result + o, p, (size_t)sz); o += (size_t)sz;
            p += sz + 2;
        }
        result[o] = 0; out->body_len = o;
    } else {
        result = malloc(blen_out + 1);
        memcpy(result, bodyp, blen_out); result[blen_out] = 0; out->body_len = blen_out;
    }
    out->body = result;
    free(buf);
    st_debug("-> %d (%zu bytes)", out->status, out->body_len);
    return 0;
}

// ---- raw socket API (shared with the MQTT client) --------------------------
// Thin public wrapper over the same Conn/TLS machinery the HTTP client uses, so
// MQTT gets the OpenSSL bindings and the DNS workaround for free.
struct NetConn { Conn c; };

NetConn *net_connect(const char *host, int port, int use_tls){
    if(!host || !*host) return NULL;
    Url u;
    memset(&u, 0, sizeof u);
    snprintf(u.host, sizeof u.host, "%s", host);
    snprintf(u.path, sizeof u.path, "/");
    snprintf(u.scheme, sizeof u.scheme, "%s", use_tls ? "https" : "http");
    u.port = port;
    u.tls  = use_tls ? 1 : 0;

    NetConn *n = calloc(1, sizeof *n);
    if(!n) return NULL;
    if(conn_open(&n->c, &u) != 0){ conn_close(&n->c); free(n); return NULL; }
    return n;
}

int net_write(NetConn *c, const void *buf, size_t n){
    if(!c) return -1;
    return conn_write(&c->c, (const char*)buf, n);
}

int net_read(NetConn *c, void *buf, size_t n, int timeout_ms){
    if(!c) return -1;
    if(timeout_ms > 0){
        struct timeval tv = { .tv_sec = timeout_ms / 1000, .tv_usec = (timeout_ms % 1000) * 1000 };
        setsockopt(c->c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    } else {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
        setsockopt(c->c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    }
    return conn_read(&c->c, (char*)buf, n);
}

void net_close(NetConn *c){
    if(!c) return;
    conn_close(&c->c);
    free(c);
}

int net_fd(NetConn *c){ return c ? c->c.fd : -1; }
