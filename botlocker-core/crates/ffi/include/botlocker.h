/*
 * C interface to the Botlocker detection core.
 *
 * Ownership and threading:
 *   - bl_engine_new() returns an engine that must be released with bl_engine_free().
 *   - Every char* returned by this API must be released with bl_string_free().
 *   - All functions taking a pointer+length read exactly that many bytes. The
 *     pointer may be NULL only when its length is 0.
 *   - An engine is not thread-safe for concurrent bl_classify() calls with
 *     different state, but it is internally synchronized, so sharing one engine
 *     across threads is safe. nginx uses one engine per worker process.
 */
#ifndef BOTLOCKER_H
#define BOTLOCKER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct bl_engine bl_engine;

typedef enum {
    BL_ACTION_PROXY = 0,
    BL_ACTION_CHALLENGE = 1,
    BL_ACTION_TRAP = 2
} bl_action;

typedef struct {
    const char *name;   /* header name; lowercased on the Rust side */
    size_t name_len;
    const char *value;
    size_t value_len;
} bl_header;

typedef struct {
    const char *method;
    size_t method_len;
    const char *path;        /* decoded request path, without query */
    size_t path_len;
    const char *query;       /* raw query string, may be empty */
    size_t query_len;
    const char *client_ip;   /* textual IPv4 or IPv6 address */
    size_t client_ip_len;
    const bl_header *headers;
    size_t header_count;
} bl_request;

/*
 * Creates an engine from a TOML config file and a signing secret (>= 32 bytes).
 * On failure returns NULL and writes a NUL-terminated message into err.
 */
bl_engine *bl_engine_new(const char *config_path,
                         const char *secret, size_t secret_len,
                         char *err, size_t err_len);

void bl_engine_free(bl_engine *engine);

/*
 * Classifies one request. `now` is Unix seconds. Fails open: a malformed
 * request (for example an unparseable client IP) returns BL_ACTION_PROXY.
 */
bl_action bl_classify(bl_engine *engine, const bl_request *req, uint64_t now);

/* A decision plus why it was made. Free with bl_decision_free(). */
typedef struct {
    bl_action action;
    double score;
    char *reason;    /* e.g. "honeypot", "automated", "scored"; may be NULL */
    char *evidence;  /* lines separated by "\n"; may be NULL */
} bl_decision;

/* Like bl_classify(), but also returns the reason and evidence. Fails open. */
bl_decision bl_classify_detail(bl_engine *engine, const bl_request *req, uint64_t now);

void bl_decision_free(bl_decision d);

/* Trap page for `path`. Returns NULL on failure. */
char *bl_maze_html(bl_engine *engine, const char *path, size_t path_len);

/* Challenge page for a gray-zone visitor. `next` is the original path and query. */
char *bl_challenge_html(bl_engine *engine,
                        const char *client_ip, size_t client_ip_len,
                        uint64_t now,
                        const char *next, size_t next_len);

/* Challenge page for the /.bl/challenge endpoint. Reads `next` from the query string. */
char *bl_challenge_endpoint_html(bl_engine *engine,
                                 const char *client_ip, size_t client_ip_len,
                                 uint64_t now,
                                 const char *query, size_t query_len);

/*
 * Handles a browser report (`GET /.bl/report`). `query` is the raw query string.
 * Returns a JSON object: {"ok":true,"token":"..."} or {"ok":false}. Free with bl_string_free().
 */
char *bl_report(bl_engine *engine,
                const char *client_ip, size_t client_ip_len,
                uint64_t now,
                const char *query, size_t query_len);

/* Hidden honeypot link to inject into HTML pages. */
char *bl_honeypot_link(bl_engine *engine);

void bl_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* BOTLOCKER_H */
