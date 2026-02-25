/*
 * Coraza connector for Apache HTTPD
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#ifndef MOD_CORAZA_H
#define MOD_CORAZA_H

#include <httpd.h>
#include <http_config.h>
#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>
#include <http_request.h>
#include <ap_config.h>
#include <apr_strings.h>
#include <apr_tables.h>
#include <apr_buckets.h>
#include <util_filter.h>
#include <coraza/coraza.h>

#define CORAZA_APACHE_MAJOR "0"
#define CORAZA_APACHE_MINOR "1"
#define CORAZA_APACHE_PATCHLEVEL "0"

#define CORAZA_APACHE_VERSION CORAZA_APACHE_MAJOR "." \
    CORAZA_APACHE_MINOR "." CORAZA_APACHE_PATCHLEVEL

#define CORAZA_APACHE_WHOAMI "coraza-apache v" CORAZA_APACHE_VERSION

#define CORAZA_IN_FILTER  "CORAZA_IN"
#define CORAZA_OUT_FILTER "CORAZA_OUT"


/* Deferred rule storage -- rules are collected as strings during config
 * parsing (parent process) and replayed after fork in child_init. */

typedef enum {
    CORAZA_RULE_INLINE,
    CORAZA_RULE_FILE
} coraza_rule_type_e;

typedef struct {
    coraza_rule_type_e  type;
    const char         *value;
} coraza_rule_entry_t;


/* Per-directory (Location) configuration */
typedef struct {
    int                 enable;          /* -1=unset, 0=off, 1=on */
    int                 has_rules;
    apr_array_header_t *rules;           /* of coraza_rule_entry_t */
    const char         *transaction_id;
    coraza_waf_t        waf;             /* built in child_init */
    void               *merge_child;     /* stable child dir_conf for WAF caching */
} coraza_dir_conf_t;


/* Per-server configuration */
typedef struct {
    apr_array_header_t *rules;           /* of coraza_rule_entry_t */
    apr_array_header_t *dir_confs;       /* of coraza_dir_conf_t * */
    coraza_waf_t        waf;             /* fallback WAF */
    unsigned int        rules_inline;
    unsigned int        rules_file;
} coraza_server_conf_t;


/* Per-request context */
typedef struct {
    coraza_transaction_t  transaction;
    apr_bucket_brigade   *pending_brigade;  /* buffered body for header delay */
    int headers_delayed;           /* response held back pending body inspection */
    int phase2_done;               /* request body processed */
    int phase3_done;               /* response headers processed */
    int phase4_done;               /* response body processed */
    int logged;                    /* audit log already emitted (prevents double-log) */
    int intervention_triggered;    /* WAF denied the request */
} coraza_request_ctx_t;


extern module AP_MODULE_DECLARE_DATA coraza_module;

/* mod_coraza.c */

/* Check WAF intervention; return HTTP status (e.g. 403) or OK if none.
 * If early_log is set, triggers audit logging before returning. */
int coraza_process_intervention(coraza_transaction_t transaction,
                                request_rec *r, int early_log);

/* Create per-request context with a WAF transaction.
 * Lazily builds a WAF for the dir_conf if needed (3-tier cache). */
coraza_request_ctx_t *coraza_create_ctx(request_rec *r);

/* Build a WAF handle by replaying a deferred rules array via libcoraza. */
coraza_waf_t coraza_build_waf(apr_array_header_t *rules, server_rec *s);

/* mod_coraza_dl.c */

/* dlopen libcoraza.so and resolve all function pointers. */
int coraza_dl_open(server_rec *s);

/* dlclose libcoraza.so. */
void coraza_dl_close(server_rec *s);

/* mod_coraza_phase1.c */

/* Fixups hook: phases 1+2 — connection, URI, headers, request body. */
int coraza_post_read_request(request_rec *r);

/* mod_coraza_body_in.c */

/* Input filter fallback: inspects body if fixups didn't read it. */
apr_status_t coraza_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                 ap_input_mode_t mode, apr_read_type_e block,
                                 apr_off_t readbytes);

/* mod_coraza_filter_out.c */

/* Output filter: response headers (phase 3), body (phase 4), header delay. */
apr_status_t coraza_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);

/* mod_coraza_log.c */

/* Log transaction hook: phase 5 audit logging. */
int coraza_log_transaction(request_rec *r);

#endif /* MOD_CORAZA_H */
