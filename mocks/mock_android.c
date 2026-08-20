// Mock libandroid.so — replaces the NDK link-stub so libthing_security's
// asset reads actually return the bundled Tuya key files. The library calls:
//   AAssetManager_fromJava(env, assetManager) -> AAssetManager*
//   AAssetManager_open(mgr, "t_s.bmp", mode)  -> AAsset*
//   AAsset_getLength / getLength64 / read / seek / close
// We ignore the (mock) Java AssetManager object and serve files from the
// directory named by the ASSETS_DIR env var (defaults to "./assets").
//
// Built as a shared lib with soname "libandroid.so" so the bionic linker
// resolves the NEEDED libandroid.so to this at runtime.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { char dir[1024]; } MockAssetManager;
typedef struct { uint8_t *data; long len; long pos; } MockAsset;

static MockAssetManager g_mgr;

// Tracing gated on VERBOSE, same rule as main.c and the liblog shim: set and
// non-empty. Quiet by default so normal runs carry only the CLI's own output.
static int trace(void){
    static int e = -1;
    if(e < 0){ const char *v = getenv("VERBOSE"); e = (v && *v) ? 1 : 0; }
    return e;
}

// AAssetManager* AAssetManager_fromJava(JNIEnv*, jobject)
void *AAssetManager_fromJava(void *env, void *assetManager) {
    (void)env; (void)assetManager;
    const char *dir = getenv("ASSETS_DIR");
    snprintf(g_mgr.dir, sizeof g_mgr.dir, "%s", dir ? dir : "./assets");
    if(trace()) fprintf(stderr, "[android] AAssetManager_fromJava -> dir=%s\n", g_mgr.dir);
    return &g_mgr;
}

// AAsset* AAssetManager_open(AAssetManager*, const char* filename, int mode)
void *AAssetManager_open(void *mgr, const char *filename, int mode) {
    (void)mode;
    MockAssetManager *m = mgr ? (MockAssetManager *)mgr : &g_mgr;
    char path[2048];
    snprintf(path, sizeof path, "%s/%s", m->dir[0] ? m->dir : ".", filename);
    FILE *f = fopen(path, "rb");
    if (!f) { if(trace()) fprintf(stderr, "[android] AAssetManager_open MISS %s\n", path); return NULL; }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    MockAsset *a = (MockAsset *)calloc(1, sizeof(MockAsset));
    a->data = (uint8_t *)malloc(n > 0 ? n : 1); a->len = n; a->pos = 0;
    if (n > 0 && fread(a->data, 1, n, f) != (size_t)n) { n = a->len = 0; }
    fclose(f);
    if(trace()) fprintf(stderr, "[android] AAssetManager_open %s (%ld bytes)\n", path, a->len);
    return a;
}

// int AAsset_read(AAsset*, void* buf, size_t count)
int AAsset_read(void *asset, void *buf, size_t count) {
    MockAsset *a = (MockAsset *)asset;
    if (!a) return -1;
    long remain = a->len - a->pos;
    if (remain <= 0) return 0;
    size_t n = count < (size_t)remain ? count : (size_t)remain;
    memcpy(buf, a->data + a->pos, n); a->pos += (long)n;
    return (int)n;
}

// off_t AAsset_seek(AAsset*, off_t off, int whence)
long AAsset_seek(void *asset, long off, int whence) {
    MockAsset *a = (MockAsset *)asset;
    if (!a) return -1;
    if (whence == 0) a->pos = off;            // SEEK_SET
    else if (whence == 1) a->pos += off;      // SEEK_CUR
    else if (whence == 2) a->pos = a->len + off; // SEEK_END
    return a->pos;
}
long AAsset_seek64(void *asset, long off, int whence) { return AAsset_seek(asset, off, whence); }

long AAsset_getLength(void *asset)   { MockAsset *a=(MockAsset*)asset; return a?a->len:0; }
long AAsset_getLength64(void *asset) { return AAsset_getLength(asset); }
long AAsset_getRemainingLength(void *asset)   { MockAsset *a=(MockAsset*)asset; return a?(a->len-a->pos):0; }
long AAsset_getRemainingLength64(void *asset) { return AAsset_getRemainingLength(asset); }

const void *AAsset_getBuffer(void *asset) { MockAsset *a=(MockAsset*)asset; return a?a->data:NULL; }

void AAsset_close(void *asset) {
    MockAsset *a = (MockAsset *)asset;
    if (a) { free(a->data); free(a); }
}

// Rarely used by this lib but present in the header; provide benign stubs.
void *AAssetManager_openDir(void *mgr, const char *dirName) { (void)mgr; (void)dirName; return NULL; }
const char *AAssetDir_getNextFileName(void *dir) { (void)dir; return NULL; }
void AAssetDir_close(void *dir) { (void)dir; }
int AAsset_openFileDescriptor(void *asset, long *start, long *length) { (void)asset; (void)start; (void)length; return -1; }
int AAsset_isAllocated(void *asset) { (void)asset; return 0; }
