// Minimal JSON parser / writer.
//
// Just enough for the SwitchBot + Tuya cloud payloads and the SD-card listing
// JSON the camera SDK hands back. Parses into a flat node arena; values are
// borrowed slices of a mutable copy of the input (unescaped in place).
#ifndef OUTDOOR_CAM_JSON_H
#define OUTDOOR_CAM_JSON_H

#include <stddef.h>

typedef enum { J_NULL, J_BOOL, J_NUM, J_STR, J_ARR, J_OBJ } JType;

typedef struct JNode {
    JType type;
    const char *str;      // J_STR value / J_OBJ member key storage
    double num;           // J_NUM value, J_BOOL as 0/1
    struct JNode *child;  // first child (J_ARR/J_OBJ)
    struct JNode *next;   // next sibling
    const char *key;      // member name when the parent is J_OBJ
} JNode;

typedef struct JDoc JDoc;

// Parse `text` (copied internally). Returns NULL on syntax error.
JDoc  *json_parse(const char *text);
JNode *json_root(JDoc *d);
void   json_free(JDoc *d);

// Lookups (all NULL-safe).
JNode      *json_get(const JNode *obj, const char *key);   // object member
JNode      *json_at(const JNode *arr, int index);          // array element
int         json_len(const JNode *node);                   // array/object size
const char *json_str(const JNode *node, const char *fallback);
double      json_num(const JNode *node, double fallback);
int         json_bool(const JNode *node, int fallback);
// Convenience: obj.key as string/number.
const char *json_gets(const JNode *obj, const char *key, const char *fallback);
double      json_getn(const JNode *obj, const char *key, double fallback);

// Re-serialise a node (caller frees). Used to pass sub-objects through as
// opaque JSON (e.g. the p2pConfig blob handed to the native SDK).
char *json_dump(const JNode *node);

// ---- writer ---------------------------------------------------------------
// Small append buffer for building request bodies.
typedef struct { char *buf; size_t len, cap; } JBuf;
void  jbuf_init(JBuf *b);
void  jbuf_free(JBuf *b);
void  jbuf_raw(JBuf *b, const char *s);            // append verbatim
void  jbuf_escaped(JBuf *b, const char *s);        // append JSON-escaped string
void  jbuf_kv(JBuf *b, const char *k, const char *v, int *first); // "k":"v"
void  jbuf_kv_raw(JBuf *b, const char *k, const char *raw, int *first);
void  jbuf_printf(JBuf *b, const char *fmt, ...);

#endif
