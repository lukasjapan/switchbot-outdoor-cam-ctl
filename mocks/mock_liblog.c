// Mock Android liblog: route __android_log_* to stderr so the SDK's internal
// logs are visible under qemu (real bionic liblog writes to /dev/log, absent
// here). Gated by VERBOSE, matching main.c, so it stays quiet by default.
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

// Set *and* non-empty, as in main.c — an exported-but-empty VERBOSE means off.
static int enabled(void){
    static int e = -1;
    if(e < 0){ const char *v = getenv("VERBOSE"); e = (v && *v) ? 1 : 0; }
    return e;
}

int __android_log_print(int prio, const char *tag, const char *fmt, ...){
    (void)prio; if(!enabled()) return 0;
    va_list ap; va_start(ap,fmt);
    fprintf(stderr,"[%s] ", tag?tag:"?"); vfprintf(stderr,fmt,ap); fputc('\n',stderr);
    va_end(ap); return 0;
}
int __android_log_write(int prio, const char *tag, const char *text){
    (void)prio; if(!enabled()) return 0;
    fprintf(stderr,"[%s] %s\n", tag?tag:"?", text?text:""); return 0;
}
int __android_log_vprint(int prio, const char *tag, const char *fmt, va_list ap){
    (void)prio; if(!enabled()) return 0;
    fprintf(stderr,"[%s] ", tag?tag:"?"); vfprintf(stderr,fmt,ap); fputc('\n',stderr); return 0;
}
void __android_log_assert(const char*c,const char*t,const char*fmt,...){ (void)c;(void)t;(void)fmt; }
int __android_log_buf_write(int b,int p,const char*t,const char*txt){ (void)b; return __android_log_write(p,t,txt); }
