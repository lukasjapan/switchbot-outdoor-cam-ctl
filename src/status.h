// Status/progress reporting.
//
// Output convention (per the plan):
//   stdout = DATA ONLY (JSON/table, or raw media bytes when --out -)
//   stderr = human-readable status/progress
// so `switchbot-outdoor-cam-ctl list --json | jq` and `switchbot-outdoor-cam-ctl download --out - > f.mp4` stay clean.
#ifndef OUTDOOR_CAM_STATUS_H
#define OUTDOOR_CAM_STATUS_H

#include <stdio.h>

extern int g_status_verbose;   // -v/--verbose: adds tracing detail

// Always-printed milestone (e.g. "connecting P2P (LAN)…").
#define st_info(...)  do{ fputs("• ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }while(0)
// Only with -v (signaling trace, per-frame detail, JNI chatter).
#define st_debug(...) do{ if(g_status_verbose){ fputs("  ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); } }while(0)
// Non-fatal warning.
#define st_warn(...)  do{ fputs("! ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }while(0)
// Fatal one-liner; caller returns non-zero.
#define st_err(...)   do{ fputs("error: ", stderr); fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); }while(0)

#endif
