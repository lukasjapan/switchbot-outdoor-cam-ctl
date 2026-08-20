#include "json.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct JDoc {
    char  *text;     // mutable copy; string values point into it
    JNode *nodes;    // arena
    size_t used, cap;
    JNode *root;
};

static JNode *node_new(JDoc *d, JType t){
    if(d->used == d->cap){
        size_t nc = d->cap ? d->cap * 2 : 64;
        JNode *nn = realloc(d->nodes, nc * sizeof *nn);
        if(!nn) return NULL;
        d->nodes = nn; d->cap = nc;
    }
    JNode *n = &d->nodes[d->used++];
    memset(n, 0, sizeof *n);
    n->type = t;
    return n;
}

// The arena may move on growth, so children are linked by index during parse
// and fixed up afterwards. Simpler: parse recursively but store indices.
typedef struct { JDoc *d; char *p; int ok; } P;

static void skip_ws(P *s){ while(*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r') s->p++; }

static int hex4(const char *p){
    int v = 0;
    for(int i = 0; i < 4; i++){
        char c = p[i]; v <<= 4;
        if(c >= '0' && c <= '9') v |= c - '0';
        else if(c >= 'a' && c <= 'f') v |= c - 'a' + 10;
        else if(c >= 'A' && c <= 'F') v |= c - 'A' + 10;
        else return -1;
    }
    return v;
}

// Parse a string in place: returns pointer to the unescaped, NUL-terminated
// value and advances s->p past the closing quote.
static const char *parse_string(P *s){
    if(*s->p != '"'){ s->ok = 0; return ""; }
    s->p++;
    char *out = s->p, *w = s->p;
    while(*s->p && *s->p != '"'){
        if(*s->p == '\\'){
            s->p++;
            switch(*s->p){
                case 'n': *w++ = '\n'; s->p++; break;
                case 't': *w++ = '\t'; s->p++; break;
                case 'r': *w++ = '\r'; s->p++; break;
                case 'b': *w++ = '\b'; s->p++; break;
                case 'f': *w++ = '\f'; s->p++; break;
                case 'u': {
                    int cp = hex4(s->p + 1);
                    if(cp < 0){ s->ok = 0; return ""; }
                    s->p += 5;
                    // Minimal UTF-8 encode (surrogate pairs collapse to U+FFFD).
                    if(cp < 0x80) *w++ = (char)cp;
                    else if(cp < 0x800){ *w++ = (char)(0xC0|(cp>>6)); *w++ = (char)(0x80|(cp&0x3F)); }
                    else if(cp >= 0xD800 && cp <= 0xDFFF){ *w++ = (char)0xEF; *w++ = (char)0xBF; *w++ = (char)0xBD; }
                    else { *w++ = (char)(0xE0|(cp>>12)); *w++ = (char)(0x80|((cp>>6)&0x3F)); *w++ = (char)(0x80|(cp&0x3F)); }
                    break;
                }
                default: *w++ = *s->p ? *s->p++ : '\0'; break;
            }
        } else *w++ = *s->p++;
    }
    if(*s->p != '"'){ s->ok = 0; return ""; }
    s->p++;      // past closing quote
    *w = '\0';   // terminate (safe: w <= original closing-quote position)
    return out;
}

static JNode *parse_value(P *s);

static JNode *parse_container(P *s, int is_obj){
    JDoc *d = s->d;
    size_t self = d->used;
    if(!node_new(d, is_obj ? J_OBJ : J_ARR)){ s->ok = 0; return NULL; }
    s->p++;  // past { or [
    skip_ws(s);
    char close = is_obj ? '}' : ']';
    size_t last = (size_t)-1;
    if(*s->p == close){ s->p++; return &d->nodes[self]; }
    for(;;){
        const char *key = NULL;
        if(is_obj){
            skip_ws(s);
            key = parse_string(s);
            if(!s->ok) return NULL;
            skip_ws(s);
            if(*s->p != ':'){ s->ok = 0; return NULL; }
            s->p++;
        }
        skip_ws(s);
        size_t childidx = d->used;
        JNode *child = parse_value(s);
        if(!s->ok || !child) return NULL;
        d->nodes[childidx].key = key;
        if(last == (size_t)-1) d->nodes[self].child = (JNode*)(uintptr_t)(childidx + 1);
        else                   d->nodes[last].next  = (JNode*)(uintptr_t)(childidx + 1);
        last = childidx;
        skip_ws(s);
        if(*s->p == ','){ s->p++; continue; }
        if(*s->p == close){ s->p++; break; }
        s->ok = 0; return NULL;
    }
    return &d->nodes[self];
}

static JNode *parse_value(P *s){
    JDoc *d = s->d;
    skip_ws(s);
    switch(*s->p){
        case '{': return parse_container(s, 1);
        case '[': return parse_container(s, 0);
        case '"': {
            size_t i = d->used;
            if(!node_new(d, J_STR)){ s->ok = 0; return NULL; }
            const char *v = parse_string(s);
            d->nodes[i].str = v;
            return &d->nodes[i];
        }
        case 't': if(!strncmp(s->p,"true",4)){ s->p += 4; JNode*n=node_new(d,J_BOOL); if(n) n->num=1; return n; } s->ok=0; return NULL;
        case 'f': if(!strncmp(s->p,"false",5)){ s->p += 5; JNode*n=node_new(d,J_BOOL); if(n) n->num=0; return n; } s->ok=0; return NULL;
        case 'n': if(!strncmp(s->p,"null",4)){ s->p += 4; return node_new(d,J_NULL); } s->ok=0; return NULL;
        default: {
            char *end = NULL;
            double v = strtod(s->p, &end);
            if(end == s->p){ s->ok = 0; return NULL; }
            s->p = end;
            JNode *n = node_new(d, J_NUM);
            if(n) n->num = v;
            return n;
        }
    }
}

JDoc *json_parse(const char *text){
    if(!text) return NULL;
    JDoc *d = calloc(1, sizeof *d);
    if(!d) return NULL;
    d->text = strdup(text);
    if(!d->text){ free(d); return NULL; }
    P s = { d, d->text, 1 };
    size_t rootidx = d->used;
    JNode *r = parse_value(&s);
    if(!s.ok || !r){ json_free(d); return NULL; }
    // Fix up index-encoded links into real pointers now the arena is stable.
    for(size_t i = 0; i < d->used; i++){
        uintptr_t c = (uintptr_t)d->nodes[i].child, n = (uintptr_t)d->nodes[i].next;
        d->nodes[i].child = c ? &d->nodes[c - 1] : NULL;
        d->nodes[i].next  = n ? &d->nodes[n - 1] : NULL;
    }
    d->root = &d->nodes[rootidx];
    return d;
}

JNode *json_root(JDoc *d){ return d ? d->root : NULL; }

void json_free(JDoc *d){
    if(!d) return;
    free(d->nodes); free(d->text); free(d);
}

JNode *json_get(const JNode *obj, const char *key){
    if(!obj || obj->type != J_OBJ || !key) return NULL;
    for(JNode *c = obj->child; c; c = c->next)
        if(c->key && !strcmp(c->key, key)) return c;
    return NULL;
}
JNode *json_at(const JNode *arr, int index){
    if(!arr || index < 0) return NULL;
    int i = 0;
    for(JNode *c = arr->child; c; c = c->next, i++) if(i == index) return c;
    return NULL;
}
int json_len(const JNode *node){
    if(!node) return 0;
    int n = 0;
    for(JNode *c = node->child; c; c = c->next) n++;
    return n;
}
const char *json_str(const JNode *n, const char *fb){ return (n && n->type == J_STR && n->str) ? n->str : fb; }
double json_num(const JNode *n, double fb){ return (n && (n->type == J_NUM || n->type == J_BOOL)) ? n->num : fb; }
int json_bool(const JNode *n, int fb){ return (n && n->type == J_BOOL) ? (n->num != 0) : fb; }
const char *json_gets(const JNode *o, const char *k, const char *fb){ return json_str(json_get(o, k), fb); }
double json_getn(const JNode *o, const char *k, double fb){ return json_num(json_get(o, k), fb); }

// ---- writer ---------------------------------------------------------------
void jbuf_init(JBuf *b){ b->cap = 256; b->len = 0; b->buf = malloc(b->cap); if(b->buf) b->buf[0] = 0; }
void jbuf_free(JBuf *b){ free(b->buf); b->buf = NULL; b->len = b->cap = 0; }
static void jbuf_need(JBuf *b, size_t extra){
    if(!b->buf) jbuf_init(b);
    if(b->len + extra + 1 <= b->cap) return;
    while(b->len + extra + 1 > b->cap) b->cap *= 2;
    b->buf = realloc(b->buf, b->cap);
}
void jbuf_raw(JBuf *b, const char *s){
    if(!s) return; size_t n = strlen(s);
    jbuf_need(b, n); if(!b->buf) return;
    memcpy(b->buf + b->len, s, n); b->len += n; b->buf[b->len] = 0;
}
void jbuf_escaped(JBuf *b, const char *s){
    jbuf_raw(b, "\"");
    for(const unsigned char *p = (const unsigned char*)(s ? s : ""); *p; p++){
        char tmp[8];
        switch(*p){
            case '"':  jbuf_raw(b, "\\\""); break;
            case '\\': jbuf_raw(b, "\\\\"); break;
            case '\n': jbuf_raw(b, "\\n");  break;
            case '\r': jbuf_raw(b, "\\r");  break;
            case '\t': jbuf_raw(b, "\\t");  break;
            default:
                if(*p < 0x20){ snprintf(tmp, sizeof tmp, "\\u%04x", *p); jbuf_raw(b, tmp); }
                else { jbuf_need(b, 1); if(b->buf){ b->buf[b->len++] = (char)*p; b->buf[b->len] = 0; } }
        }
    }
    jbuf_raw(b, "\"");
}
void jbuf_kv(JBuf *b, const char *k, const char *v, int *first){
    if(!*first) jbuf_raw(b, ","); *first = 0;
    jbuf_escaped(b, k); jbuf_raw(b, ":"); jbuf_escaped(b, v);
}
void jbuf_kv_raw(JBuf *b, const char *k, const char *raw, int *first){
    if(!*first) jbuf_raw(b, ","); *first = 0;
    jbuf_escaped(b, k); jbuf_raw(b, ":"); jbuf_raw(b, raw);
}
void jbuf_printf(JBuf *b, const char *fmt, ...){
    char tmp[1024]; va_list ap; va_start(ap, fmt);
    vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap);
    jbuf_raw(b, tmp);
}

// ---- dump -----------------------------------------------------------------
static void dump_node(const JNode *n, JBuf *b){
    if(!n){ jbuf_raw(b, "null"); return; }
    switch(n->type){
        case J_NULL: jbuf_raw(b, "null"); break;
        case J_BOOL: jbuf_raw(b, n->num ? "true" : "false"); break;
        case J_NUM: {
            if(n->num == (double)(long long)n->num) jbuf_printf(b, "%lld", (long long)n->num);
            else jbuf_printf(b, "%g", n->num);
            break;
        }
        case J_STR: jbuf_escaped(b, n->str); break;
        case J_ARR:
            jbuf_raw(b, "[");
            for(JNode *c = n->child; c; c = c->next){ if(c != n->child) jbuf_raw(b, ","); dump_node(c, b); }
            jbuf_raw(b, "]");
            break;
        case J_OBJ:
            jbuf_raw(b, "{");
            for(JNode *c = n->child; c; c = c->next){
                if(c != n->child) jbuf_raw(b, ",");
                jbuf_escaped(b, c->key ? c->key : ""); jbuf_raw(b, ":"); dump_node(c, b);
            }
            jbuf_raw(b, "}");
            break;
    }
}
char *json_dump(const JNode *node){
    JBuf b; jbuf_init(&b);
    dump_node(node, &b);
    return b.buf;   // caller frees
}
