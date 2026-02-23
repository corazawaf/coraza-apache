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
    int headers_delayed;
    int phase2_done;
    int phase3_done;
    int phase4_done;
    int logged;
    int intervention_triggered;
} coraza_request_ctx_t;


extern module AP_MODULE_DECLARE_DATA coraza_module;

/* mod_coraza.c */
int coraza_process_intervention(coraza_transaction_t transaction,
                                request_rec *r, int early_log);
coraza_request_ctx_t *coraza_create_ctx(request_rec *r);
coraza_waf_t coraza_build_waf(apr_array_header_t *rules, server_rec *s);

/* mod_coraza_dl.c */
int coraza_dl_open(server_rec *s);
void coraza_dl_close(server_rec *s);

/* mod_coraza_phase1.c */
int coraza_post_read_request(request_rec *r);

/* mod_coraza_body_in.c */
apr_status_t coraza_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                                 ap_input_mode_t mode, apr_read_type_e block,
                                 apr_off_t readbytes);

/* mod_coraza_filter_out.c */
apr_status_t coraza_output_filter(ap_filter_t *f, apr_bucket_brigade *bb);

/* mod_coraza_log.c */
int coraza_log_transaction(request_rec *r);

#endif /* MOD_CORAZA_H */
