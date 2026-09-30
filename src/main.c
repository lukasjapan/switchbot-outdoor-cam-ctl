// switchbot-outdoor-cam-ctl — list / download / live-view SwitchBot (ThingClips) camera video.
//
// Runs as an aarch64 Android binary under qemu-user (see run.sh) so it can
// drive the app's native .so's directly:
//   libThingCameraSDK.so  AV command protocol, decrypt, MP4 mux
//   libThingP2PSDK.so     P2P transport
//   libthing_security.so  Tuya request signing / response decryption
//
// Output convention: stdout = data only, stderr = human-readable status.
#include "camera.h"
#include "cloud.h"
#include "config.h"
#include "creds.h"
#include "http.h"
#include "jni_mock.h"
#include "json.h"
#include "native.h"
#include "rawmedia.h"
#include "security.h"
#include "signaling.h"
#include "status.h"
#include "stream.h"

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

int g_status_verbose = 0;

// ---- interruption ----------------------------------------------------------
// `live` runs until told to stop, so Ctrl-C has to be a request rather than a
// kill: the camera session must be closed through the normal path, otherwise it
// stays open server-side and the next command has to wait it out.
static volatile sig_atomic_t g_stop;
static void on_signal(int sig){ (void)sig; g_stop = 1; }

// NB: a consumer dying on the far end of `docker compose run … | player` cannot be
// detected from in here, and it is worth recording why so nobody retries it:
//   - it never arrives as EPIPE — the broken pipe is between the docker CLI and
//     that consumer, outside the container;
//   - the daemon goes on draining (and discarding) our stdout indefinitely, so
//     writes keep succeeding and frames keep flowing (measured: 60+ frames well
//     after the consumer exited), which rules out both write errors and stalls;
//   - stdin is no help either: under `docker compose run` it already polls
//     POLLHUP at startup, so it cannot distinguish a live client from a dead one.
// The orphan therefore has to be cleaned up host-side — see the `osc` wrapper,
// which force-removes the container once the CLI exits.
static void install_signal_handlers(void){
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    // Streaming into `head` or a player that exits must not kill us mid-frame;
    // stream.c notices the EPIPE and stops cleanly instead.
    signal(SIGPIPE, SIG_IGN);
}

// ---- argument parsing ------------------------------------------------------
typedef struct {
    const char *cmd;
    const char *dev_id;
    const char *out;
    const char *format;
    const char *email, *password, *session_token;
    const char *from, *to;
    int year, month;
    int duration;
    const char *start_s, *stop_s;
    int json, show_secrets;
    int raw;              // live: decoded Y4M via the SDK instead of the camera's own stream
} Opts;

static void usage(FILE *f){
    fputs(
"switchbot-outdoor-cam-ctl — SwitchBot/ThingClips camera CLI (SD-card video over LAN)\n"
"\n"
"USAGE\n"
"  switchbot-outdoor-cam-ctl <command> [options]\n"
"\n"
"COMMANDS\n"
"  login      [--email <e> --password <p>] [--session-token <jwt>]\n"
"             One-time login. Fetches the Tuya shadow account (permanent) and\n"
"             caches it in ~/.switchbot-outdoor-cam-ctl/creds.json, so later\n"
"             commands need no auth.\n"
"             --session-token is the app's JWT (starts with \"eyJ\"), NOT the\n"
"             Open API token+secret — that is a different API and cannot reach\n"
"             the Tuya account. Give both and the token is tried first.\n"
"  list       [--dev-id <id>] [--year N --month M] [--from YYYY-MM --to YYYY-MM]\n"
"             [--json]                 Recordings on the SD card (current month\n"
"             by default; the device has no bulk index, so listing iterates).\n"
"  download   --dev-id <id> --start <time> [--stop <time> | --duration <sec>]\n"
"             [--out <file|->]\n"
"             Download a recording to mp4. Recordings are addressed by time\n"
"             range (the firmware reports no ids). <time> is either unix epoch\n"
"             seconds, as `list` prints, or local wall-clock:\n"
"               --start 1785568473\n"
"               --start \"2026-08-01 16:14:33\"   --start 2026-08-01T16:14:33\n"
"  record     --dev-id <id> [--format hd|sd] [--duration <sec>]\n"
"             [--out <file|->]         Record to mp4. hd = 1080p HEVC (default),\n"
"                                      sd = 640x360 H.264.\n"
"  live       --dev-id <id> [--format hd|sd] [--duration <sec>] [--raw]\n"
"             [--out <file|->]         Stream until Ctrl-C: the camera's own video\n"
"                                      as Annex-B, H.265 at hd, H.264 at sd:\n"
"                                        live --format sd | ffplay -f h264 -framerate 15 -\n"
"                                        live | ffplay -f hevc -framerate 15 -\n"
"                                      --raw: decoded by the SDK, as Y4M (costly;\n"
"                                        live --raw | ffplay -i pipe:0)\n"
"  snapshot   --dev-id <id> [--out <file|->]     Single JPEG.\n"
"  info       --dev-id <id>                      Camera capability JSON.\n"
"  selftest   Load the native stack and initialise the engine (bring-up check).\n"
"\n"
"GLOBAL\n"
"  -v, --verbose    Verbose status on stderr.\n"
"  --show-secrets   Print device secrets (localKey) instead of masking them.\n"
"  -h, --help       This help.\n"
"\n"
"ENVIRONMENT\n"
"  OUTDOOR_CAM_DEV_ID   Default for --dev-id, so you need not repeat it. The\n"
"                       flag takes precedence. Set it empty to ignore it.\n"
"\n"
"Use \"--out -\" to stream to stdout. stdout carries data only; all status and\n"
"progress goes to stderr.\n", f);
}

static int need_arg(int i, int argc, const char *flag){
    if(i + 1 >= argc){ st_err("%s requires a value", flag); return 0; }
    return 1;
}

static int parse_args(int argc, char **argv, Opts *o){
    memset(o, 0, sizeof *o);
    o->format = "hd";
    for(int i = 1; i < argc; i++){
        const char *a = argv[i];
        if(a[0] != '-'){
            if(!o->cmd){ o->cmd = a; continue; }
            st_err("unexpected argument '%s'", a); return -1;
        }
        #define OPT_STR(flag, field) \
            if(!strcmp(a, flag)){ if(!need_arg(i, argc, flag)) return -1; o->field = argv[++i]; continue; }
        #define OPT_INT(flag, field) \
            if(!strcmp(a, flag)){ if(!need_arg(i, argc, flag)) return -1; o->field = atoi(argv[++i]); continue; }
        #define OPT_LONG(flag, field) \
            if(!strcmp(a, flag)){ if(!need_arg(i, argc, flag)) return -1; o->field = strtol(argv[++i], NULL, 10); continue; }
        OPT_STR ("--dev-id",           dev_id)
        OPT_STR ("--out",              out)
        OPT_STR ("--format",           format)
        OPT_STR ("--email",            email)
        OPT_STR ("--password",         password)
        // "session token" = the app's JWT (authorization header). NOT the Open
        // API "switchbot token" (hex + secret), which is a different API and
        // cannot reach the Tuya shadow account.
        OPT_STR ("--session-token",    session_token)
        OPT_STR ("--from",             from)
        OPT_STR ("--to",               to)
        OPT_INT ("--year",             year)
        OPT_INT ("--month",            month)
        OPT_INT ("--duration",         duration)
        OPT_STR ("--start",            start_s)
        OPT_STR ("--stop",             stop_s)
        #undef OPT_STR
        #undef OPT_INT
        #undef OPT_LONG
        if(!strcmp(a, "--json")){ o->json = 1; continue; }
        if(!strcmp(a, "--show-secrets")){ o->show_secrets = 1; continue; }
        if(!strcmp(a, "--raw")){ o->raw = 1; continue; }
        if(!strcmp(a, "-v") || !strcmp(a, "--verbose")){ g_status_verbose = 1; g_verbose = 1; continue; }
        if(!strcmp(a, "-h") || !strcmp(a, "--help")){ usage(stdout); exit(0); }
        st_err("unknown option '%s'", a);
        return -1;
    }
    return 0;
}

// ---- commands --------------------------------------------------------------

// Bring-up check: load the whole native chain and initialise the engine. This
// proves the FFmpeg/OpenSSL/codec dependency graph resolves under qemu and that
// the JNIEnv mock survives JNI_OnLoad, before any cloud or P2P work.
// Defined below, next to the other session helpers.
static int ensure_session(Creds *c, TuyaSession *s);

// Split a user-supplied --out into the directory + file name the SDK wants.
// Relative paths resolve under OUTDOOR_CAM_OUT_DIR (run.sh mounts your cwd there);
// "-" means stdout, so the file is staged in a scratch dir and streamed after.
#define OUT_SCRATCH "/tmp/switchbot-outdoor-cam-ctl"
static void resolve_out(const char *out, const char *fallback_name,
                        char *dir, size_t dir_sz, char *name, size_t name_sz,
                        int *to_stdout){
    *to_stdout = (out && !strcmp(out, "-"));
    if(*to_stdout || !out || !*out){
        snprintf(dir, dir_sz, "%s", OUT_SCRATCH);
        snprintf(name, name_sz, "%s", fallback_name);
        if(!*to_stdout){
            // No --out given: still land it somewhere the user can reach.
            const char *base = getenv("OUTDOOR_CAM_OUT_DIR");
            if(base && *base) snprintf(dir, dir_sz, "%s", base);
        }
        return;
    }
    const char *slash = strrchr(out, '/');
    if(out[0] == '/'){                       // absolute
        if(slash == out) snprintf(dir, dir_sz, "/");
        else { size_t n = (size_t)(slash - out); if(n >= dir_sz) n = dir_sz - 1; memcpy(dir, out, n); dir[n] = 0; }
        snprintf(name, name_sz, "%s", slash + 1);
        return;
    }
    const char *base = getenv("OUTDOOR_CAM_OUT_DIR");
    if(!base || !*base) base = ".";
    if(slash){
        size_t n = (size_t)(slash - out);
        snprintf(dir, dir_sz, "%s/%.*s", base, (int)n, out);
        snprintf(name, name_sz, "%s", slash + 1);
    } else {
        snprintf(dir, dir_sz, "%s", base);
        snprintf(name, name_sz, "%s", out);
    }
}

// Copy a produced file to stdout, then remove it (used for --out -).
static int stream_to_stdout(const char *path){
    FILE *f = fopen(path, "rb");
    if(!f){ st_err("cannot read %s", path); return -1; }
    char buf[65536];
    size_t n;
    while((n = fread(buf, 1, sizeof buf, f)) > 0)
        if(fwrite(buf, 1, n, stdout) != n){ fclose(f); st_err("short write to stdout"); return -1; }
    fclose(f);
    fflush(stdout);
    unlink(path);
    return 0;
}

// Report a finished file on stderr (stdout stays data-only).
static void report_file(const char *path){
    // Show the name the user asked for, not the container-internal mount point.
    const char *base = getenv("OUTDOOR_CAM_OUT_DIR");
    const char *shown = path;
    if(base && *base){
        size_t bl = strlen(base);
        if(!strncmp(path, base, bl) && path[bl] == '/') shown = path + bl + 1;
    }
    FILE *f = fopen(path, "rb");
    if(!f){ st_warn("expected output at %s but it is not there", path); return; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fclose(f);
    if(sz <= 0){ st_warn("wrote %s but it is empty", path); return; }
    st_info("wrote %s (%.1f MB)", shown, (double)sz / (1024.0 * 1024.0));
}

// Optional extra leg of the bring-up check: bring up the signaling transport for
// a device (MQTT connect + subscribe). This validates the credential derivation
// — broker, username, native op-2 password, topics — before any P2P work.
static int selftest_signaling(const Opts *o){
    Creds c; TuyaSession s;
    if(ensure_session(&c, &s) != 0){ creds_free(&c); return 1; }
    int rc = cloud_device_detail(&c, &s, o->dev_id);
    if(rc == 0) rc = cloud_rtc_config(&c, &s, o->dev_id, 0);
    if(rc != 0){ tuya_session_free(&s); creds_free(&c); return 1; }
    creds_save(&c);

    CredDevice *dev = creds_device(&c, o->dev_id);
    st_info("bringing up signaling transport…");
    Signaling *sg = signaling_start(&s, dev, c.tyCountryCode);
    if(!sg){
        st_err("signaling transport failed");
        tuya_session_free(&s); creds_free(&c);
        return 1;
    }
    st_info("signaling transport up — broker accepted our credentials");
    // Pump briefly so any unsolicited inbound frame is exercised too.
    for(int i = 0; i < 4; i++)
        if(signaling_poll(sg, 250, NULL, NULL) != 0){ st_warn("signaling link dropped"); break; }
    signaling_stop(sg);
    tuya_session_free(&s);
    creds_free(&c);
    printf("signaling ok\n");
    return 0;
}

static int cmd_selftest(void){
    st_info("loading native stack…");
    if(native_load() != 0){ st_err("native stack failed to load"); return 1; }
    st_info("native stack loaded");

    const char *ver = native_engine_version();
    if(ver) st_info("camera SDK version: %s", ver);

    st_info("initialising camera engine…");
    int r = native_engine_initialize();
    if(r < 0){ st_err("engine initialize() failed (%d)", r); return 1; }
    st_info("engine initialised (rc=%d)", r);

    // libthing_security supplies the Tuya ATOP signing / response-decryption
    // primitives, so prove it initialises and that a couple of them return data.
    st_info("initialising libthing_security…");
    if(security_init() != 0) return 1;
    char *chkey = security_get_ch_key(NULL);
    st_info("getChKey -> %s", chkey ? chkey : "(null)");
    char *digest = security_compute_digest(NULL, "a=1&b=2");
    st_info("computeDigest -> %s", digest ? digest : "(null)");
    int sec_ok = (chkey && *chkey) || (digest && *digest);
    free(chkey); free(digest);
    if(!sec_ok){ st_err("libthing_security returned no usable output"); return 1; }

    // HTTPS reachability: DNS + TLS through the app's OpenSSL 1.1, which the
    // cloud provisioning layer depends on. Uses a cheap unauthenticated probe.
    st_info("checking HTTPS (TLS via libssl.1.1)…");
    const SbConfig *cfg = sb_config();
    if(!cfg) return 1;
    HttpResponse hr;
    const char *hdrs[] = { "Content-Type: application/json", NULL };
    char exist_url[256];
    snprintf(exist_url, sizeof exist_url, "%s/account/api/v2/user/exist", cfg->accountBase);
    if(http_request("POST", exist_url, hdrs, "{}", &hr) != 0){
        st_err("HTTPS check failed");
        return 1;
    }
    st_info("HTTPS ok (status %d, %zu bytes)", hr.status, hr.body_len);
    JDoc *d = json_parse(hr.body);
    if(d){ st_debug("json parse ok"); json_free(d); }
    else   st_warn("response was not JSON (non-fatal for the transport check)");
    http_response_free(&hr);

    printf("ok\n");
    return 0;
}

// Log in once and cache the durable credentials. Everything downstream (access
// tokens, Tuya session, per-device data) regenerates from the cache without
// ever prompting again.
static int cmd_login(const Opts *o){
    Creds c;
    creds_load(&c);   // may be absent on first run; that's fine

    int have_token = o->session_token && *o->session_token;
    int have_pw    = o->email && o->password;
    if(!have_token && !have_pw){
        st_err("login needs --email and --password, and/or --switchbot-token");
        creds_free(&c);
        return 2;
    }

    // Try the supplied token first (cheapest), then fall back to email/password.
    // Supplying both is useful for checking each path independently.
    int ok = 0;
    if(have_token){
        if(cloud_switchbot_use_token(&c, o->session_token) == 0 &&
           cloud_fetch_tuya_account(&c) == 0){
            ok = 1;
        } else if(have_pw){
            st_warn("token path failed — falling back to email/password");
        }
    }
    if(!ok && have_pw){
        if(cloud_switchbot_login(&c, o->email, o->password) == 0 &&
           cloud_fetch_tuya_account(&c) == 0){
            ok = 1;
        }
    }
    if(!ok){ creds_free(&c); return 1; }

    if(creds_save(&c) != 0) st_warn("could not persist the credential cache");
    else st_info("credentials cached in %s", creds_path());

    printf("logged in\n");
    creds_free(&c);
    return 0;
}

// Get a usable Tuya session, reusing the cached one while it is still valid so
// repeated commands do not re-login. Loads creds as a side effect.
static int ensure_session(Creds *c, TuyaSession *s){
    memset(s, 0, sizeof *s);
    if(creds_load(c) != 0 || !c->tyUid){
        st_err("not logged in — run: switchbot-outdoor-cam-ctl login --email <e> --password <p>");
        return -1;
    }
    // The native security lib is needed for EVERY signed request (it supplies the
    // body key and the signature), not just for logging in — so load and
    // initialise it before either path below.
    if(native_load() != 0) return -1;
    if(security_init() != 0) return -1;

    // Reuse the cached session only if it is complete — a cache written before
    // partnerIdentity was persisted would break MQTT signaling, so re-login.
    if(c->tySid && *c->tySid && creds_valid(c->tyExpiresAt, 120) &&
       c->tyPartnerIdentity && *c->tyPartnerIdentity &&
       c->tyLoginUid && *c->tyLoginUid){
        st_debug("reusing cached Tuya session (%llds left)", c->tyExpiresAt - (long long)time(NULL));
        s->sid   = strdup(c->tySid);
        s->ecode = strdup(c->tySecret ? c->tySecret : "");
        // The login uid, NOT the shadow-account uid — the MQTT topic depends on it.
        s->uid   = strdup(c->tyLoginUid);
        s->partnerIdentity = strdup(c->tyPartnerIdentity);
        return 0;
    }
    if(c->tySid && *c->tySid &&
       ((!c->tyPartnerIdentity || !*c->tyPartnerIdentity) || (!c->tyLoginUid || !*c->tyLoginUid)))
        st_debug("cached session is missing signaling fields — logging in again");
    if(cloud_tuya_login(c, s) != 0) return -1;
    creds_save(c);
    return 0;
}


// Resolve a device's static secrets (localKey/pv) — proves the signed ATOP path
// end to end, and is a prerequisite for every media command.
static int cmd_info(const Opts *o){
    if(!o->dev_id){ st_err("info needs --dev-id <id>"); return 2; }
    Creds c; TuyaSession s;
    if(ensure_session(&c, &s) != 0){ creds_free(&c); return 1; }
    int rc = cloud_device_detail(&c, &s, o->dev_id);
    // Also resolve the session config, so `info` reports everything needed to
    // open a P2P session (and warms the cache for the media commands).
    if(rc == 0) rc = cloud_rtc_config(&c, &s, o->dev_id, 0);
    if(rc == 0){
        creds_save(&c);
        CredDevice *d = creds_device(&c, o->dev_id);
        if(d){
            // localKey is a device secret (it authenticates the P2P session), so
            // keep it out of terminal output unless explicitly asked for. It is
            // cached in creds.json either way.
            const char *hidden = "<hidden, use --show-secrets>";
            const char *lk = o->show_secrets ? d->localKey : hidden;
            char authpwd[33] = {0};
            int have_auth = cloud_auth_pwd(d, authpwd) == 0;
            if(o->json)
                printf("{\"devId\":\"%s\",\"name\":\"%s\",\"pv\":\"%s\",\"p2pType\":%d,"
                       "\"localKey\":\"%s\",\"p2pConfig\":%s,\"skill\":%s}\n",
                       d->devId, d->name, d->pv, d->p2pType, lk,
                       d->p2pConfig ? d->p2pConfig : "null",
                       d->skill ? d->skill : "null");
            else {
                printf("devId      %s\nname       %s\npv         %s\np2pType    %d\n",
                       d->devId, d->name[0] ? d->name : "(unnamed)", d->pv, d->p2pType);
                printf("localKey   %s\n", lk);
                printf("password   %s\n", o->show_secrets ? d->password : hidden);
                printf("authPwd    %s\n", have_auth ? (o->show_secrets ? authpwd : hidden) : "(unavailable)");
                printf("p2pConfig  %s\n", d->p2pConfig ? "present" : "missing");
                printf("skill      %s\n", d->skill ? "present" : "missing");
            }
        }
    }
    tuya_session_free(&s);
    creds_free(&c);
    return rc == 0 ? 0 : 1;
}

// Open a live session. Frame capture / mp4 muxing is not wired yet, so this
// currently proves the P2P path: credentials -> signaling -> connect -> preview.
// ---- shared camera session -------------------------------------------------
// Opening a media session is the same dance for every command, and the P2P
// connect is intermittently flaky (state=4 error=-3, a timeout), so it lives
// here with bounded retries.
//
// A retry cannot reuse the previous p2pConfig: session.init mints per-connection
// values, and a second connect with the same sessionId is refused. So each
// attempt re-fetches the config and rebuilds signaling + camera from scratch.
typedef struct {
    Creds        c;
    TuyaSession  ts;
    Signaling   *sg;
    Camera      *cam;
    CredDevice  *dev;
    char         auth_pwd[33];
    int          have_creds;
} CamSession;

static void session_close(CamSession *s){
    if(s->cam){ camera_close(s->cam); s->cam = NULL; }
    if(s->sg){ signaling_stop(s->sg); s->sg = NULL; }
    tuya_session_free(&s->ts);
    if(s->have_creds){ creds_free(&s->c); s->have_creds = 0; }
}

// Tear down just the per-attempt parts, keeping the cloud credentials.
static void session_drop_attempt(CamSession *s){
    if(s->cam){ camera_close(s->cam); s->cam = NULL; }
    if(s->sg){ signaling_stop(s->sg); s->sg = NULL; }
}

static int session_open(CamSession *s, const char *dev_id, int attempts){
    memset(s, 0, sizeof *s);
    if(ensure_session(&s->c, &s->ts) != 0){ creds_free(&s->c); return -1; }
    s->have_creds = 1;

    if(cloud_device_detail(&s->c, &s->ts, dev_id) != 0){ session_close(s); return -1; }

    if(attempts < 1) attempts = 1;
    for(int attempt = 1; attempt <= attempts; attempt++){
        if(attempt > 1) st_info("retrying (attempt %d of %d)…", attempt, attempts);

        // Fresh session config every attempt — the previous one is spent.
        if(cloud_rtc_config(&s->c, &s->ts, dev_id, 1) != 0){ session_drop_attempt(s); continue; }
        creds_save(&s->c);

        s->dev = creds_device(&s->c, dev_id);
        if(!s->dev || cloud_auth_pwd(s->dev, s->auth_pwd) != 0){ session_drop_attempt(s); continue; }

        s->sg = signaling_start(&s->ts, s->dev, s->c.tyCountryCode);
        if(!s->sg){ session_drop_attempt(s); goto backoff; }
        signaling_wake(s->sg);          // low-power cameras sleep until poked

        s->cam = camera_open(s->dev, s->sg, s->ts.uid);
        if(!s->cam){ session_drop_attempt(s); goto backoff; }

        // Signaling rides the cloud broker, so the session opens in relay mode.
        if(camera_connect(s->cam, s->auth_pwd, 0, 20000) == 0) return 0;
        session_drop_attempt(s);

    backoff:
        if(attempt < attempts){
            // Give the camera time to retire the half-open session before the
            // next try; back off a little further each round.
            int pause_ms = 3000 * attempt;
            st_info("waiting %.1fs before retrying…", pause_ms / 1000.0);
            usleep((useconds_t)pause_ms * 1000);
        }
    }
    st_err("could not open a camera session after %d attempt(s)", attempts);
    session_close(s);
    return -1;
}

// How many times to try opening a session (OUTDOOR_CAM_ATTEMPTS overrides).
static int session_attempts(void){
    const char *e = getenv("OUTDOOR_CAM_ATTEMPTS");
    int n = e && *e ? atoi(e) : 3;
    return n > 0 ? n : 1;
}

// ---- record ----------------------------------------------------------------
// Fixed-duration mp4. Writes straight to the destination path as the frames
// arrive; only "--out -" has to stage, because the SDK's muxer patches the mdat
// size when it finalises and a pipe cannot be seeked back.
static int cmd_record(const Opts *o){
    if(!o->dev_id){ st_err("record needs --dev-id <id>"); return 2; }

    CamSession S;
    if(session_open(&S, o->dev_id, session_attempts()) != 0) return 1;
    Camera *cam = S.cam;
    int status = 1;
    {
        {
            int clarity = camera_clarity_from_format(o->format);
            st_info("[step] starting preview…");
            if(camera_start_preview(cam, clarity) == 0){
                st_info("[step] preview started");
                char dir[512], name[256];
                int to_stdout = 0;
                resolve_out(o->out, "record.mp4", dir, sizeof dir, name, sizeof name, &to_stdout);
                st_debug("destination dir=%s name=%s", dir, name);

                // NB: recordings have no audio track because camera audio is
                // muted by default, but camera_set_mute(cam, 0) here segfaults
                // inside the SDK (null deref). Not an ordering problem at the
                // Java layer — IPCThingP2PCamera.audioOpen() is an empty method,
                // so there is no prerequisite call we are skipping. Left alone
                // until the native side is understood; see camera_set_mute().
                //
                // Let the stream settle and produce a keyframe before recording,
                // otherwise the mp4 can start with an undecodable gap.
                usleep(1500000);
                // Write straight to the destination. Only "--out -" needs staging,
                // since the SDK writes to a path and stdout is not one.
                if(camera_start_record(cam, dir, name) == 0){
                    int secs = o->duration > 0 ? o->duration : 10;
                    st_info("recording %ds (clarity=%d)…", secs, clarity);
                    for(int i = 0; i < secs * 4; i++) usleep(250000);
                    camera_stop_record(cam);
                    // The SDK finalises the container asynchronously.
                    usleep(1000000);
                    const char *path = camera_record_path(cam);
                    if(path){
                        if(to_stdout) status = stream_to_stdout(path) == 0 ? 0 : 1;
                        else { report_file(path); status = 0; }
                    }
                } else st_err("recorder failed to start");
                st_info("[step] stopping preview…");
                camera_stop_preview(cam);
                st_info("[step] preview stopped");
            } else st_err("[step] preview failed to start");
        }
    }
    session_close(&S);
    return status;
}

// ---- live ------------------------------------------------------------------
// Continuous stream until Ctrl-C, in one of two shapes:
//
//   default  The camera's own encoded video (Annex-B H.264 at sd, H.265 at hd),
//            read off the P2P session by rawmedia.c. The SDK's preview is never
//            started, so nothing is decoded — the whole point, since that decode
//            runs in software under emulation.
//   --raw    The SDK's preview: its listener only offers *decoded* frames (three
//            I420 planes — see the frame sink in camera.h), written as Y4M.

// Runs until interrupted, --duration, the destination goes away, or output dries
// up. The stall check is what catches a dead consumer. When the far end of a
// `docker compose run` pipe exits, we never see EPIPE — the break is between the
// docker CLI and that consumer, outside the container — and output simply stops
// moving. Without this the container sits there holding the camera session until
// --duration elapses, or forever. Only armed once output has actually started,
// because HD can take tens of seconds to produce its first frame.
//
// Before that, a separate, longer limit. Output that never starts is also how a
// closed player looks, since we only learn the consumer is gone by writing to it:
// on a poor link `live --raw | ffplay` was seen still holding the session a minute
// after the window was closed, because the camera had not sent a single frame.
static void live_wait(const Opts *o){
    const long long STALL_TICKS = 40;            // 10 s at 250 ms/tick
    const long long START_TICKS = 240;           // 60 s for the first output
    long long ticks = 0, cap = o->duration > 0 ? (long long)o->duration * 4 : -1;
    long long last_change = 0;
    long seen = 0, reported = -1;
    int stalled = 0;
    while(!g_stop && !stream_broken() && (cap < 0 || ticks < cap)){
        usleep(250000);
        ticks++;
        long n = stream_frame_count();
        if(n != seen){ seen = n; last_change = ticks; }
        else if(seen > 0 && ticks - last_change >= STALL_TICKS){ stalled = 1; break; }
        else if(seen == 0 && ticks >= START_TICKS){ stalled = 2; break; }
        if((ticks % 8) == 0 && n != reported){ st_debug("%ld units", n); reported = n; }
    }
    if(g_stop)       st_info("interrupted");
    else if(stalled == 1) st_err("no new output for %llds — stream stalled; stopping",
                                 STALL_TICKS / 4);
    else if(stalled == 2) st_err("nothing arrived within %llds — giving up", START_TICKS / 4);
}

static int live_decoded(const Opts *o, Camera *cam, int clarity){
    int w = 0, h = 0, fps = 0, status = 1;
    camera_format_geometry(o->format, &w, &h, &fps);
    if(stream_open(o->out, w, h, fps) != 0) return 1;

    st_info("[step] starting preview…");
    if(camera_start_preview(cam, clarity) == 0){
        st_info("[step] preview started");
        camera_set_frame_sink(stream_write_frame);
        live_wait(o);

        // Detach before tearing down, so a frame in flight cannot land on a
        // closed destination.
        camera_set_frame_sink(NULL);
        st_info("[step] stopping preview…");
        camera_stop_preview(cam);
        st_info("[step] preview stopped");

        long n = stream_frame_count();
        if(n > 0){ st_info("%ld frames streamed", n); status = 0; }
        else st_err("no frames arrived — the SDK decoded nothing at this clarity");
    } else st_err("[step] preview failed to start");

    stream_close();
    return status;
}

static int live_encoded(const Opts *o, Camera *cam, int clarity){
    int status = 1;
    if(stream_open_bytes(o->out) != 0) return 1;

    st_info("[step] starting video…");
    if(rawmedia_start(camera_p2p_session(cam), clarity) == 0){
        st_info("[step] video started");
        live_wait(o);
        st_info("[step] stopping video…");
        rawmedia_stop();
        st_info("[step] video stopped");

        long n = stream_frame_count();
        const char *codec = rawmedia_codec();
        if(n > 0){
            st_info("%ld NAL units streamed (%s) — play with: ffplay -f %s -framerate 15 -", n,
                    codec ? codec : "?", codec && !strcmp(codec, "h265") ? "hevc" : "h264");
            status = 0;
        } else st_err("no video arrived on the media channel");
    } else {
        rawmedia_stop();
        st_err("[step] video failed to start");
    }

    stream_close();
    return status;
}

static int cmd_live(const Opts *o){
    if(!o->dev_id){ st_err("live needs --dev-id <id>"); return 2; }
    int clarity = camera_clarity_from_format(o->format);

    CamSession S;
    if(session_open(&S, o->dev_id, session_attempts()) != 0) return 1;
    int status = o->raw ? live_decoded(o, S.cam, clarity) : live_encoded(o, S.cam, clarity);
    session_close(&S);
    return status;
}

// ---- list ------------------------------------------------------------------
// The device has no bulk index, so listing walks months -> days -> fragments.
// (getRecordDaysByMonth tells us which days hold data; only those are queried.)
static void fmt_ts(long long t, char *out, size_t n){
    time_t tt = (time_t)t;
    struct tm tmv;
    if(localtime_r(&tt, &tmv)) strftime(out, n, "%Y-%m-%d %H:%M:%S", &tmv);
    else snprintf(out, n, "%lld", t);
}

// The zone abbreviation in force, so printed times are never ambiguous. (Without
// tzdata in the container bionic reports UTC; run.sh passes the host TZ in.)
static const char *tz_label(void){
    static char buf[16];
    time_t now = time(NULL);
    struct tm tmv;
    if(localtime_r(&now, &tmv) && strftime(buf, sizeof buf, "%Z", &tmv) > 0) return buf;
    return "UTC";
}

// Accept either unix epoch seconds (all digits, as `list` prints) or a local
// wall-clock time. The SDK only takes int32 epoch seconds, so everything is
// normalised to that. Returns -1 if unparseable.
static long long parse_time_arg(const char *s){
    if(!s || !*s) return -1;
    int all_digits = 1;
    for(const char *p = s; *p; p++) if(*p < '0' || *p > '9'){ all_digits = 0; break; }
    if(all_digits) return strtoll(s, NULL, 10);

    // Local time, in a few shapes: "YYYY-MM-DD HH:MM:SS", the same with 'T',
    // and without seconds.
    struct tm tmv;
    memset(&tmv, 0, sizeof tmv);
    tmv.tm_isdst = -1;                 // let mktime work out DST
    int y, mo, d, h = 0, mi = 0, se = 0;
    int n = sscanf(s, "%d-%d-%d%*[ T]%d:%d:%d", &y, &mo, &d, &h, &mi, &se);
    if(n < 3) return -1;
    tmv.tm_year = y - 1900; tmv.tm_mon = mo - 1; tmv.tm_mday = d;
    tmv.tm_hour = h; tmv.tm_min = mi; tmv.tm_sec = se;
    time_t t = mktime(&tmv);
    return t == (time_t)-1 ? -1 : (long long)t;
}

// One day's fragments -> stdout. Returns how many were printed.
static int print_day(Camera *cam, int y, int m, int d, const Opts *o, int *first_json){
    char *json = NULL;
    if(camera_query_fragments(cam, y, m, d, 0, 0, &json, 15000) != 0) return 0;
    // The raw record is useful while developing: it shows exactly which fields
    // the firmware reports (uuid, encrypt, type, prefix, …).
    if(g_status_verbose && json) st_debug("raw %04d-%02d-%02d: %.600s", y, m, d, json);
    JDoc *doc = json ? json_parse(json) : NULL;
    if(!doc){ st_warn("%04d-%02d-%02d: unparseable fragment list", y, m, d); free(json); return 0; }

    JNode *items = json_get(json_root(doc), "items");
    int n = 0;
    for(JNode *it = items ? items->child : NULL; it; it = it->next){
        long long start = (long long)json_getn(it, "startTime", 0);
        long long stop  = (long long)json_getn(it, "endTime", 0);
        if(start <= 0) continue;
        // This firmware reports only {type,startTime,endTime}; `encrypt` shows up
        // on the cloud-storage path, so treat it as absent-means-no.
        int rtype = (int)json_getn(it, "type", 0);
        int encrypted = (int)json_getn(it, "encrypt", 0);
        if(o->json){
            if(!*first_json) printf(",\n"); else *first_json = 0;
            printf("  {\"start\":%lld,\"stop\":%lld,\"duration\":%lld,\"type\":%d,\"encrypted\":%s}",
                   start, stop, stop - start, rtype, encrypted ? "true" : "false");
        } else {
            char sbuf[32], ebuf[32];
            fmt_ts(start, sbuf, sizeof sbuf);
            fmt_ts(stop, ebuf, sizeof ebuf);
            printf("%-19s  %-8s  %6llds  %-11lld %-11lld %d%s\n",
                   sbuf, ebuf + 11, stop - start, start, stop,
                   rtype, encrypted ? " (encrypted)" : "");
        }
        n++;
    }
    json_free(doc);
    free(json);
    return n;
}

static int list_month(Camera *cam, int y, int m, const Opts *o, int *first_json){
    // The record-index queries are unreliable right after a session opens: they
    // sometimes answer with an empty set for a month that does have footage.
    // Reporting that as "no recordings" would look like an empty card, so retry
    // a few times before believing it. A genuinely empty month costs a couple of
    // extra seconds.
    char *json = NULL;
    JDoc *doc = NULL;
    JNode *days = NULL;
    for(int attempt = 1; attempt <= 3; attempt++){
        free(json); json = NULL;
        if(doc){ json_free(doc); doc = NULL; }
        if(camera_query_days(cam, y, m, &json, 15000) != 0){ usleep(700000); continue; }
        doc = json ? json_parse(json) : NULL;
        if(!doc){ st_warn("%04d-%02d: unparseable day list", y, m); usleep(700000); continue; }
        days = json_get(json_root(doc), "DataDays");
        if(days && days->child) break;         // got a non-empty set
        st_debug("%04d-%02d: empty day list (try %d)", y, m, attempt);
        usleep(700000);
    }
    if(!doc){ free(json); return 0; }
    int total = 0, ndays = 0;
    for(JNode *d = days ? days->child : NULL; d; d = d->next){
        const char *ds = json_str(d, NULL);
        int day = ds ? atoi(ds) : (int)json_num(d, 0);
        if(day < 1 || day > 31) continue;
        ndays++;
        total += print_day(cam, y, m, day, o, first_json);
    }
    st_info("%04d-%02d: %d day(s) with recordings, %d fragment(s)", y, m, ndays, total);
    json_free(doc);
    free(json);
    return total;
}

static int cmd_list(const Opts *o){
    if(!o->dev_id){ st_err("list needs --dev-id <id>"); return 2; }

    // Listing only needs the P2P session; no preview, so no decoding either.
    CamSession S;
    if(session_open(&S, o->dev_id, session_attempts()) != 0) return 1;
    Camera *cam = S.cam;
    int status = 1;
    {
        {
            // Month range: --from/--to, else --year/--month, else current month.
            time_t now = time(NULL);
            struct tm tmv;
            localtime_r(&now, &tmv);
            int y0 = tmv.tm_year + 1900, m0 = tmv.tm_mon + 1;
            int y1 = y0, m1 = m0;
            if(o->from && sscanf(o->from, "%d-%d", &y0, &m0) == 2){
                y1 = y0; m1 = m0;
                if(o->to && sscanf(o->to, "%d-%d", &y1, &m1) != 2){ y1 = y0; m1 = m0; }
            } else if(o->year > 0 && o->month > 0){
                y0 = y1 = o->year; m0 = m1 = o->month;
            }

            int first_json = 1;
            if(o->json) printf("[\n");
            else printf("%-19s  %-8s  %7s  %-11s %-11s %s\n",
                        "START", "STOP", "DUR", "START_TS", "STOP_TS", "TYPE");
            int total = 0;
            for(int y = y0, m = m0; (y < y1) || (y == y1 && m <= m1); ){
                total += list_month(cam, y, m, o, &first_json);
                if(++m > 12){ m = 1; y++; }
            }
            if(o->json) printf("\n]\n");
            if(total == 0) st_warn("no recordings found in the requested range");
            status = 0;
        }
    }
    session_close(&S);
    return status;
}

// ---- download --------------------------------------------------------------
// Recordings are addressed by time range (the firmware reports no ids), so the
// span from `list` is the identifier.
static int cmd_download(const Opts *o){
    if(!o->dev_id){ st_err("download needs --dev-id <id>"); return 2; }
    if(!o->start_s){ st_err("download needs --start <time> (see `switchbot-outdoor-cam-ctl list`)"); return 2; }

    long long start = parse_time_arg(o->start_s);
    if(start <= 0){ st_err("cannot parse --start '%s'", o->start_s); return 2; }
    long long stop;
    if(o->stop_s){
        stop = parse_time_arg(o->stop_s);
        if(stop <= 0){ st_err("cannot parse --stop '%s'", o->stop_s); return 2; }
    } else if(o->duration > 0){
        stop = start + o->duration;
    } else {
        st_err("download needs --stop <time> or --duration <sec>");
        return 2;
    }
    if(stop <= start){ st_err("--stop must be after --start"); return 2; }

    char sbuf[32], ebuf[32];
    fmt_ts(start, sbuf, sizeof sbuf);
    fmt_ts(stop, ebuf, sizeof ebuf);
    st_info("requesting %s .. %s %s (%llds)", sbuf, ebuf, tz_label(), stop - start);

    CamSession S;
    if(session_open(&S, o->dev_id, session_attempts()) != 0) return 1;
    Camera *cam = S.cam;
    int status = 1;
    {
        {
            char dir[512], name[256];
            int to_stdout = 0;
            char fallback[64];
            snprintf(fallback, sizeof fallback, "%lld.mp4", start);
            resolve_out(o->out, fallback, dir, sizeof dir, name, sizeof name, &to_stdout);

            // Follow the app's order (CamPlayBackActivity): load the day's
            // fragment list, open playback on the span, then download. Going
            // straight to the download is rejected with -20002 (ParamsInvalid).
            time_t st_t = (time_t)start;
            struct tm stm;
            if(localtime_r(&st_t, &stm)){
                // The SDK refuses the download unless the day's fragment list
                // has been loaded ("need query fragment data first"), so this
                // query is mandatory. The month query is NOT — the day query
                // answers on its own in the happy path — so it is only used as a
                // fallback when the day query comes back empty or unanswered
                // (the app runs both because its UI needs the month view).
                int y = stm.tm_year + 1900, mo = stm.tm_mon + 1, dy = stm.tm_mday;
                int have_ctx = 0;
                for(int attempt = 1; attempt <= 4 && !have_ctx; attempt++){
                    char *frag = NULL;
                    if(camera_query_fragments(cam, y, mo, dy, 0, 0, &frag, 20000) == 0){
                        have_ctx = frag && strstr(frag, "startTime") != NULL;
                        st_debug("day context (try %d): %s", attempt, frag ? frag : "(null)");
                        free(frag);
                    }
                    if(have_ctx) break;
                    // Prime it the way the app does, then try the day again.
                    char *days = NULL;
                    if(camera_query_days(cam, y, mo, &days, 20000) == 0){
                        st_debug("month context: %s", days ? days : "(null)");
                        free(days);
                    }
                    usleep(500000);
                }
                if(!have_ctx) st_warn("could not load the day's fragment list; download may be refused");
            }
            // playTime is a seek position inside the span, not an offset from
            // zero — the app passes a timestamp within [start, stop], and 0 is
            // rejected as out of range.
            if(camera_start_playback(cam, start, stop, (int)start) != 0)
                st_warn("could not open playback; attempting the download anyway");
            else
                usleep(2000000);   // let the playback stream establish

            // Allow generous time: the camera streams the span over P2P.
            int budget = (int)((stop - start) * 4000) + 60000;
            int pct = 0;
            if(camera_download(cam, start, stop, dir, name, budget, &pct) == 0){
                const char *path = camera_record_path(cam);
                if(path){
                    if(to_stdout) status = stream_to_stdout(path) == 0 ? 0 : 1;
                    else { report_file(path); status = 0; }
                }
            }
        }
    }
    session_close(&S);
    return status;
}

// ---- snapshot --------------------------------------------------------------
// A still needs a running stream, so this opens preview briefly and grabs one
// frame. The SDK encodes the JPEG itself.
static int cmd_snapshot(const Opts *o){
    if(!o->dev_id){ st_err("snapshot needs --dev-id <id>"); return 2; }

    CamSession S;
    if(session_open(&S, o->dev_id, session_attempts()) != 0) return 1;
    Camera *cam = S.cam;
    int status = 1;

    int clarity = camera_clarity_from_format(o->format);
    if(camera_start_preview(cam, clarity) == 0){
        char dir[512], name[256];
        int to_stdout = 0;
        resolve_out(o->out, "snapshot.jpg", dir, sizeof dir, name, sizeof name, &to_stdout);
        char path[768];
        snprintf(path, sizeof path, "%s/%s", dir, name);

        // Wait for a decoded frame to exist before asking for a still.
        usleep(2500000);
        if(camera_snapshot(cam, path) == 0){
            // The SDK writes the file asynchronously.
            usleep(1000000);
            if(to_stdout) status = stream_to_stdout(path) == 0 ? 0 : 1;
            else { report_file(path); status = 0; }
        } else st_err("snapshot failed");
        camera_stop_preview(cam);
    } else st_err("could not start preview for the snapshot");

    session_close(&S);
    return status;
}

int main(int argc, char **argv){
    setvbuf(stderr, NULL, _IOLBF, 0);
    install_signal_handlers();
    if(getenv("VERBOSE") && *getenv("VERBOSE")){ g_status_verbose = 1; g_verbose = 1; }

    Opts o;
    if(parse_args(argc, argv, &o) != 0) return 2;
    if(!o.cmd){ usage(stderr); return 2; }

    // Every camera command needs --dev-id, and it never changes for a given
    // camera, so fall back to the environment. Done once here rather than at the
    // six call sites, so the flag always wins and nothing else has to care.
    if(!o.dev_id){
        const char *env = getenv("OUTDOOR_CAM_DEV_ID");
        if(env && *env){
            o.dev_id = env;
            st_debug("dev-id from OUTDOOR_CAM_DEV_ID: %s", o.dev_id);
        }
    }

    jni_mock_init();

    // Fail fast if the bundled app config (switchbot_config.json) is missing or
    // unreadable — every command below needs the Tuya keys / SwitchBot endpoints
    // it carries. sb_config() caches, so this just front-loads the check.
    if(!sb_config()){
        st_err("cannot load switchbot_config.json — is the APK asset mounted? "
               "(set SWITCHBOT_CONFIG or ASSETS_DIR)");
        return 1;
    }

    // With --dev-id, selftest also brings up the signaling transport.
    if(!strcmp(o.cmd, "selftest")) return o.dev_id ? selftest_signaling(&o) : cmd_selftest();
    if(!strcmp(o.cmd, "login"))    return cmd_login(&o);
    if(!strcmp(o.cmd, "list"))     return cmd_list(&o);
    if(!strcmp(o.cmd, "download")) return cmd_download(&o);
    if(!strcmp(o.cmd, "record"))   return cmd_record(&o);
    if(!strcmp(o.cmd, "live"))     return cmd_live(&o);
    if(!strcmp(o.cmd, "snapshot")) return cmd_snapshot(&o);
    if(!strcmp(o.cmd, "info"))     return cmd_info(&o);

    st_err("unknown command '%s'", o.cmd);
    usage(stderr);
    return 2;
}
