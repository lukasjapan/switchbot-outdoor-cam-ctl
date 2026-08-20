// Minimal HTTPS client.
//
// TLS comes from the app's own libssl.1.1.so / libcrypto.1.1.so, resolved with
// dlsym at runtime: the NDK ships no OpenSSL headers, and those .so's are
// already staged in the sysroot for the camera stack, so we declare the handful
// of OpenSSL 1.1 prototypes we need rather than depending on headers.
#ifndef OUTDOOR_CAM_HTTP_H
#define OUTDOOR_CAM_HTTP_H

#include <stddef.h>

typedef struct {
    int   status;     // HTTP status code (0 on transport failure)
    char *body;       // NUL-terminated response body (caller frees)
    size_t body_len;
} HttpResponse;

// One header per string, "Name: value" (NULL-terminated array, may be NULL).
// `body` NULL => GET, otherwise POST with that body.
// Returns 0 on success (check r->status), non-zero on transport error.
int http_request(const char *method, const char *url,
                 const char *const *headers, const char *body,
                 HttpResponse *out);

void http_response_free(HttpResponse *r);

// ---- raw (optionally TLS) socket ------------------------------------------
// Exposed so the MQTT client can reuse this module's TLS plumbing and DNS
// workaround instead of duplicating the OpenSSL dlsym bindings.
typedef struct NetConn NetConn;

NetConn *net_connect(const char *host, int port, int use_tls);
int      net_write(NetConn *c, const void *buf, size_t n);       // 0 ok, -1 fail
// Reads up to `n` bytes; >0 bytes read, 0 on clean EOF, -1 on error.
// `timeout_ms` <= 0 blocks indefinitely.
int      net_read(NetConn *c, void *buf, size_t n, int timeout_ms);
void     net_close(NetConn *c);
int      net_fd(NetConn *c);

#endif
