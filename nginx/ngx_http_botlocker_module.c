/*
 * ngx_http_botlocker_module
 *
 * Runs Botlocker's detector in nginx's access phase. Each request is either
 * passed on (DECLINED), answered with the challenge page, or answered with a
 * maze page. Detection itself lives in the Rust core, reached through
 * botlocker.h.
 *
 * Directives:
 *   botlocker on|off;               per server/location
 *   botlocker_config PATH;          http block, TOML config (see botlocker.example.toml)
 *   botlocker_secret_file PATH;     http block, file holding the signing secret (>= 32 bytes)
 *
 * Variables:
 *   $botlocker_action     proxied | challenged | trapped | "" (module not run)
 *   $botlocker_honeypot   hidden maze link, for use with sub_filter
 *
 * Limitations:
 *   - Behavior counters (rate, missing assets) are per nginx worker process.
 *   - Honeypot links are added with sub_filter, so they go into every HTML
 *     response from the location, including ones for passing visitors.
 *   - ASN and TLS fingerprint signals are not available in this module.
 *   - The dashboard is not provided here. Use $botlocker_action in the access log.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "botlocker.h"

typedef struct {
    ngx_str_t   config_path;
    ngx_str_t   secret_file;
    bl_engine  *engine;          /* created in postconfiguration, inherited by workers */
} ngx_http_botlocker_main_conf_t;

typedef struct {
    ngx_flag_t  enabled;
} ngx_http_botlocker_loc_conf_t;

typedef struct {
    ngx_uint_t  action;          /* bl_action from this request's decision */
    ngx_str_t   reason;          /* why, e.g. "honeypot"; empty when the module did not run */
    ngx_str_t   evidence;        /* evidence lines, "\n" separated; copied out of the Rust side */
} ngx_http_botlocker_ctx_t;

static ngx_str_t  bl_challenge_uri = ngx_string("/.bl/challenge");
static ngx_str_t  bl_report_uri = ngx_string("/.bl/report");

static ngx_int_t ngx_http_botlocker_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_botlocker_postconfiguration(ngx_conf_t *cf);
static void *ngx_http_botlocker_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_botlocker_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_botlocker_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_botlocker_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_botlocker_action_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_botlocker_honeypot_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_botlocker_reason_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_botlocker_evidence_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_botlocker_commands[] = {
    { ngx_string("botlocker"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_botlocker_loc_conf_t, enabled),
      NULL },

    { ngx_string("botlocker_config"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_botlocker_main_conf_t, config_path),
      NULL },

    { ngx_string("botlocker_secret_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_botlocker_main_conf_t, secret_file),
      NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_botlocker_module_ctx = {
    ngx_http_botlocker_preconfiguration,   /* preconfiguration */
    ngx_http_botlocker_postconfiguration,  /* postconfiguration */
    ngx_http_botlocker_create_main_conf,   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_botlocker_create_loc_conf,    /* create location configuration */
    ngx_http_botlocker_merge_loc_conf      /* merge location configuration */
};

ngx_module_t ngx_http_botlocker_module = {
    NGX_MODULE_V1,
    &ngx_http_botlocker_module_ctx,        /* module context */
    ngx_http_botlocker_commands,           /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};

/* ---------- configuration ---------- */

static ngx_int_t
ngx_http_botlocker_preconfiguration(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;
    ngx_str_t             action = ngx_string("botlocker_action");
    ngx_str_t             honeypot = ngx_string("botlocker_honeypot");
    ngx_str_t             reason = ngx_string("botlocker_reason");
    ngx_str_t             evidence = ngx_string("botlocker_evidence");

    var = ngx_http_add_variable(cf, &action, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_botlocker_action_variable;

    var = ngx_http_add_variable(cf, &honeypot, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_botlocker_honeypot_variable;

    var = ngx_http_add_variable(cf, &reason, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_botlocker_reason_variable;

    var = ngx_http_add_variable(cf, &evidence, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_botlocker_evidence_variable;

    return NGX_OK;
}

static char *
to_cstr(ngx_pool_t *pool, ngx_str_t s)
{
    u_char  *p = ngx_pnalloc(pool, s.len + 1);

    if (p == NULL) {
        return NULL;
    }
    ngx_memcpy(p, s.data, s.len);
    p[s.len] = '\0';
    return (char *) p;
}

static ngx_int_t
read_secret(ngx_conf_t *cf, ngx_str_t file, u_char **out, size_t *out_len)
{
    char    *path = to_cstr(cf->pool, file);
    FILE    *fp;
    u_char  *buf;
    size_t   n;

    if (path == NULL) {
        return NGX_ERROR;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "botlocker: cannot open botlocker_secret_file \"%s\"", path);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(cf->pool, 4096);
    if (buf == NULL) {
        fclose(fp);
        return NGX_ERROR;
    }
    n = fread(buf, 1, 4095, fp);
    fclose(fp);

    /* Trim the trailing newline that `openssl rand -hex 32 > file` leaves behind. */
    while (n > 0 && isspace(buf[n - 1])) {
        n--;
    }
    buf[n] = '\0';

    *out = buf;
    *out_len = n;
    return NGX_OK;
}

static ngx_int_t
ngx_http_botlocker_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t        *cmcf;
    ngx_http_handler_pt              *h;
    ngx_http_botlocker_main_conf_t  *mcf;
    u_char                           *secret;
    size_t                            secret_len;
    char                              err[256] = {0};
    char                             *config_path;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_botlocker_handler;

    mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_botlocker_module);
    if (mcf->config_path.len == 0) {
        /* No config in this http block: the module stays inert here. */
        return NGX_OK;
    }

    /* Build the engine here, in the master process. Startup fails loudly on bad
     * config, and each forked worker inherits the ready engine. */
    if (mcf->secret_file.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "botlocker: botlocker_secret_file is required with botlocker_config");
        return NGX_ERROR;
    }
    if (read_secret(cf, mcf->secret_file, &secret, &secret_len) != NGX_OK) {
        return NGX_ERROR;
    }

    config_path = to_cstr(cf->pool, mcf->config_path);
    if (config_path == NULL) {
        return NGX_ERROR;
    }

    mcf->engine = bl_engine_new(config_path, (const char *) secret, secret_len,
                                err, sizeof(err));
    if (mcf->engine == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "botlocker: %s", err);
        return NGX_ERROR;
    }

    return NGX_OK;
}

static void *
ngx_http_botlocker_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_botlocker_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_botlocker_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    return conf;
}

static void *
ngx_http_botlocker_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_botlocker_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_botlocker_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->enabled = NGX_CONF_UNSET;
    return conf;
}

static char *
ngx_http_botlocker_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_botlocker_loc_conf_t  *prev = parent;
    ngx_http_botlocker_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    return NGX_CONF_OK;
}

/* ---------- request handling ---------- */

/* Copies a string owned by the Rust side into the request pool. NULL becomes an empty string. */
static ngx_str_t
copy_to_pool(ngx_pool_t *pool, const char *s)
{
    ngx_str_t  out;
    size_t     len;

    out.len = 0;
    out.data = NULL;
    if (s == NULL) {
        return out;
    }

    len = strlen(s);
    out.data = ngx_pnalloc(pool, len + 1);
    if (out.data == NULL) {
        out.data = NULL;
        return out;
    }
    ngx_memcpy(out.data, s, len);
    out.data[len] = '\0';
    out.len = len;
    return out;
}

static ngx_int_t
add_header(ngx_http_request_t *r, const char *name, const char *value)
{
    ngx_table_elt_t  *h = ngx_list_push(&r->headers_out.headers);

    if (h == NULL) {
        return NGX_ERROR;
    }
    h->hash = 1;
    h->key.len = strlen(name);
    h->key.data = (u_char *) name;
    h->value.len = strlen(value);
    h->value.data = (u_char *) value;
    return NGX_OK;
}

/* Sends a body and frees `body`, which came from the Rust side. */
static ngx_int_t
send_body(ngx_http_request_t *r, char *body, const char *content_type)
{
    size_t             len = strlen(body);
    char              *html = body;
    u_char            *copy;
    ngx_buf_t         *b;
    ngx_chain_t        out;
    ngx_int_t          rc;

    copy = ngx_pnalloc(r->pool, len);
    if (copy == NULL) {
        bl_string_free(html);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(copy, html, len);
    bl_string_free(html);

    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = (off_t) len;
    r->headers_out.content_type.data = (u_char *) content_type;
    r->headers_out.content_type.len = strlen(content_type);
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    if (add_header(r, "X-Robots-Tag", "noindex, nofollow") != NGX_OK
        || add_header(r, "Cache-Control", "no-store") != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        ngx_http_finalize_request(r, rc);
        return NGX_DONE;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_DONE;
    }
    b->pos = copy;
    b->last = copy + len;
    b->memory = 1;
    b->last_buf = 1;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    /* We are in the access phase. Returning NGX_OK would let the content
     * phase proxy the request to the origin as well. Finalize the response
     * here and tell nginx the request is done. */
    rc = ngx_http_output_filter(r, &out);
    ngx_http_finalize_request(r, rc);
    return NGX_DONE;
}

/* Copies the request headers into a bl_header array allocated from the pool. */
static bl_header *
collect_headers(ngx_http_request_t *r, size_t *count)
{
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i, total = 0, n = 0;
    bl_header        *headers;

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        total += part->nelts;
    }

    headers = ngx_pnalloc(r->pool, sizeof(bl_header) * (total ? total : 1));
    if (headers == NULL) {
        return NULL;
    }

    for (part = &r->headers_in.headers.part; part; part = part->next) {
        h = part->elts;
        for (i = 0; i < part->nelts; i++) {
            if (h[i].hash == 0) {
                continue;   /* removed header */
            }
            headers[n].name = (const char *) h[i].key.data;
            headers[n].name_len = h[i].key.len;
            headers[n].value = (const char *) h[i].value.data;
            headers[n].value_len = h[i].value.len;
            n++;
        }
    }

    *count = n;
    return headers;
}

static ngx_int_t
ngx_http_botlocker_handler(ngx_http_request_t *r)
{
    ngx_http_botlocker_loc_conf_t   *lcf;
    ngx_http_botlocker_main_conf_t  *mcf;
    ngx_http_botlocker_ctx_t        *ctx;
    bl_request                        req;
    bl_action                         action;
    bl_header                        *headers;
    size_t                            header_count = 0;
    uint64_t                          now = (uint64_t) ngx_time();
    char                             *html;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_botlocker_module);
    if (!lcf->enabled) {
        return NGX_DECLINED;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_botlocker_module);
    if (mcf->engine == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "botlocker is on but botlocker_config is missing; request not checked");
        return NGX_DECLINED;
    }

    headers = collect_headers(r, &header_count);
    if (headers == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* The challenge endpoint is always reachable, so it bypasses classification. */
    if (r->uri.len == bl_challenge_uri.len
        && ngx_strncmp(r->uri.data, bl_challenge_uri.data, bl_challenge_uri.len) == 0)
    {
        html = bl_challenge_endpoint_html(mcf->engine,
                                          (const char *) r->connection->addr_text.data,
                                          r->connection->addr_text.len,
                                          now,
                                          (const char *) r->args.data, r->args.len);
        if (html == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return send_body(r, html, "text/html; charset=utf-8");
    }

    /* The challenge page reports browser signals here. Like the challenge, it bypasses classification. */
    if (r->uri.len == bl_report_uri.len
        && ngx_strncmp(r->uri.data, bl_report_uri.data, bl_report_uri.len) == 0)
    {
        html = bl_report(mcf->engine,
                         (const char *) r->connection->addr_text.data,
                         r->connection->addr_text.len,
                         now,
                         (const char *) r->args.data, r->args.len);
        if (html == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return send_body(r, html, "application/json; charset=utf-8");
    }

    req.method = (const char *) r->method_name.data;
    req.method_len = r->method_name.len;
    req.path = (const char *) r->uri.data;
    req.path_len = r->uri.len;
    req.query = (const char *) r->args.data;
    req.query_len = r->args.len;
    req.client_ip = (const char *) r->connection->addr_text.data;
    req.client_ip_len = r->connection->addr_text.len;
    req.headers = headers;
    req.header_count = header_count;

    bl_decision decision = bl_classify_detail(mcf->engine, &req, now);
    action = decision.action;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_botlocker_ctx_t));
    if (ctx == NULL) {
        bl_decision_free(decision);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx->action = action;
    ctx->reason = copy_to_pool(r->pool, decision.reason);
    ctx->evidence = copy_to_pool(r->pool, decision.evidence);
    bl_decision_free(decision);
    ngx_http_set_ctx(r, ctx, ngx_http_botlocker_module);

    switch (action) {

    case BL_ACTION_CHALLENGE:
        /* Gray zone: send the page that sets the pass cookie and returns the visitor here. */
        html = bl_challenge_html(mcf->engine,
                                 (const char *) r->connection->addr_text.data,
                                 r->connection->addr_text.len,
                                 now,
                                 (const char *) r->unparsed_uri.data,
                                 r->unparsed_uri.len);
        if (html == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return send_body(r, html, "text/html; charset=utf-8");

    case BL_ACTION_TRAP:
        html = bl_maze_html(mcf->engine, (const char *) r->uri.data, r->uri.len);
        if (html == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        return send_body(r, html, "text/html; charset=utf-8");

    case BL_ACTION_PROXY:
    default:
        return NGX_DECLINED;
    }
}

/* ---------- variables ---------- */

static ngx_int_t
ngx_http_botlocker_action_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_botlocker_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_botlocker_module);
    static const char          *names[] = { "proxied", "challenged", "trapped" };
    const char                 *name = "";

    if (ctx != NULL && ctx->action < 3) {
        name = names[ctx->action];
    }

    v->len = strlen(name);
    v->data = (u_char *) name;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_botlocker_honeypot_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_botlocker_main_conf_t  *mcf = ngx_http_get_module_main_conf(r, ngx_http_botlocker_module);
    char                             *link;
    size_t                            len;
    u_char                           *copy;

    if (mcf->engine == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    link = bl_honeypot_link(mcf->engine);
    if (link == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    len = strlen(link);
    copy = ngx_pnalloc(r->pool, len);
    if (copy == NULL) {
        bl_string_free(link);
        return NGX_ERROR;
    }
    ngx_memcpy(copy, link, len);
    bl_string_free(link);

    v->len = len;
    v->data = copy;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_botlocker_reason_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_botlocker_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_botlocker_module);
    ngx_str_t                  empty = ngx_null_string;
    ngx_str_t                 *value = (ctx != NULL) ? &ctx->reason : &empty;

    v->len = value->len;
    v->data = (value->data != NULL) ? value->data : (u_char *) "";
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t
ngx_http_botlocker_evidence_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_botlocker_ctx_t  *ctx = ngx_http_get_module_ctx(r, ngx_http_botlocker_module);
    ngx_str_t                  empty = ngx_null_string;
    ngx_str_t                 *value = (ctx != NULL) ? &ctx->evidence : &empty;

    v->len = value->len;
    v->data = (value->data != NULL) ? value->data : (u_char *) "";
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}
