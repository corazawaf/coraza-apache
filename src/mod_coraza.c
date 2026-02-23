/*
 * Coraza connector for Apache HTTPD
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "mod_coraza.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forward declarations */
static void coraza_register_hooks(apr_pool_t *p);
static void *coraza_create_dir_conf(apr_pool_t *p, char *dir);
static void *coraza_merge_dir_conf(apr_pool_t *p, void *parent, void *child);
static void *coraza_create_server_conf(apr_pool_t *p, server_rec *s);
static void coraza_child_init(apr_pool_t *p, server_rec *s);
static apr_status_t coraza_child_exit(void *data);

static const char *cmd_coraza_enable(cmd_parms *cmd, void *dcfg, int flag);
static const char *cmd_coraza_rules(cmd_parms *cmd, void *dcfg, const char *arg);
static const char *cmd_coraza_rules_file(cmd_parms *cmd, void *dcfg, const char *arg);
static const char *cmd_coraza_transaction_id(cmd_parms *cmd, void *dcfg, const char *arg);

/*
 * Module-level tracking of all merged dir_confs.
 * Apache's merge_dir_conf callback doesn't receive a server_rec, so we
 * use a static array (safe: config parsing is single-threaded in parent).
 */
static apr_array_header_t *g_tracked_dir_confs = NULL;


/* ------------------------------------------------------------------ */
/* Intervention processing                                             */
/* ------------------------------------------------------------------ */

int
coraza_process_intervention(coraza_transaction_t transaction,
                            request_rec *r, int early_log)
{
    coraza_intervention_t *intervention;
    coraza_request_ctx_t *ctx;

    ctx = ap_get_module_config(r->request_config, &coraza_module);
    if (ctx == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    intervention = coraza_intervention(transaction);
    if (intervention == NULL) {
        return OK;
    }

    if (intervention->status != 200) {
        coraza_update_status_code(ctx->transaction, intervention->status);

        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                      "Coraza: Access denied with code %d",
                      intervention->status);

        if (early_log) {
            coraza_log_transaction(r);
            ctx->logged = 1;
        }

        int status = intervention->status;
        coraza_free_intervention(intervention);
        return status;
    }

    coraza_free_intervention(intervention);
    return OK;
}


/* ------------------------------------------------------------------ */
/* Transaction cleanup (called when request pool is destroyed)         */
/* ------------------------------------------------------------------ */

static apr_status_t
coraza_cleanup_transaction(void *data)
{
    coraza_request_ctx_t *ctx = (coraza_request_ctx_t *)data;

    if (ctx->transaction != 0) {
        coraza_free_transaction(ctx->transaction);
        ctx->transaction = 0;
    }

    return APR_SUCCESS;
}


/* ------------------------------------------------------------------ */
/* Create per-request context with transaction                         */
/* ------------------------------------------------------------------ */

coraza_request_ctx_t *
coraza_create_ctx(request_rec *r)
{
    coraza_request_ctx_t *ctx;
    coraza_dir_conf_t *dcf;
    coraza_server_conf_t *scf;
    coraza_waf_t waf;

    ctx = apr_pcalloc(r->pool, sizeof(coraza_request_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    dcf = ap_get_module_config(r->per_dir_config, &coraza_module);
    scf = ap_get_module_config(r->server->module_config, &coraza_module);

    /*
     * Lazy WAF building: if this dir_conf has rules but no WAF yet
     * (e.g. the server-level dir_conf that didn't go through merge,
     * or a dir_conf whose WAF wasn't built in child_init), build it now.
     */
    if (dcf->waf == 0 && dcf->has_rules && dcf->rules->nelts > 0) {
        dcf->waf = coraza_build_waf(dcf->rules, r->server);
    }

    /* Use directory WAF if available, otherwise fall back to server WAF */
    waf = dcf->waf != 0 ? dcf->waf : scf->waf;

    if (waf == 0) {
        return NULL;
    }

    if (dcf->transaction_id != NULL) {
        ctx->transaction = coraza_new_transaction_with_id(waf,
            (char *)dcf->transaction_id);
    } else {
        ctx->transaction = coraza_new_transaction(waf);
    }

    ap_set_module_config(r->request_config, &coraza_module, ctx);

    apr_pool_cleanup_register(r->pool, ctx, coraza_cleanup_transaction,
                              apr_pool_cleanup_null);

    return ctx;
}


/* ------------------------------------------------------------------ */
/* Directive handlers                                                  */
/* ------------------------------------------------------------------ */

static const char *
cmd_coraza_enable(cmd_parms *cmd, void *dcfg, int flag)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    dcf->enable = flag ? 1 : 0;
    return NULL;
}

static const char *
cmd_coraza_rules(cmd_parms *cmd, void *dcfg, const char *arg)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    coraza_server_conf_t *scf;
    coraza_rule_entry_t *entry;

    entry = apr_array_push(dcf->rules);
    entry->type = CORAZA_RULE_INLINE;
    entry->value = apr_pstrdup(cmd->pool, arg);

    dcf->has_rules = 1;

    scf = ap_get_module_config(cmd->server->module_config, &coraza_module);
    scf->rules_inline++;

    /* Also store server-level rules in scf->rules for the fallback WAF */
    if (cmd->path == NULL) {
        entry = apr_array_push(scf->rules);
        entry->type = CORAZA_RULE_INLINE;
        entry->value = apr_pstrdup(cmd->pool, arg);
    }

    return NULL;
}

static const char *
cmd_coraza_rules_file(cmd_parms *cmd, void *dcfg, const char *arg)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    coraza_server_conf_t *scf;
    coraza_rule_entry_t *entry;

    entry = apr_array_push(dcf->rules);
    entry->type = CORAZA_RULE_FILE;
    entry->value = apr_pstrdup(cmd->pool, arg);

    dcf->has_rules = 1;

    scf = ap_get_module_config(cmd->server->module_config, &coraza_module);
    scf->rules_file++;

    /* Also store server-level rules in scf->rules for the fallback WAF */
    if (cmd->path == NULL) {
        entry = apr_array_push(scf->rules);
        entry->type = CORAZA_RULE_FILE;
        entry->value = apr_pstrdup(cmd->pool, arg);
    }

    return NULL;
}

static const char *
cmd_coraza_transaction_id(cmd_parms *cmd, void *dcfg, const char *arg)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    dcf->transaction_id = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


/* ------------------------------------------------------------------ */
/* Directives                                                          */
/* ------------------------------------------------------------------ */

static const command_rec coraza_directives[] = {
    AP_INIT_FLAG("Coraza", cmd_coraza_enable, NULL,
                 RSRC_CONF | ACCESS_CONF,
                 "Enable or disable Coraza WAF"),
    AP_INIT_TAKE1("CorazaRules", cmd_coraza_rules, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Inline Coraza rules"),
    AP_INIT_TAKE1("CorazaRulesFile", cmd_coraza_rules_file, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Path to Coraza rules file"),
    AP_INIT_TAKE1("CorazaTransactionId", cmd_coraza_transaction_id, NULL,
                  RSRC_CONF | ACCESS_CONF,
                  "Custom transaction ID"),
    { NULL }
};


/* ------------------------------------------------------------------ */
/* Config creation and merge                                           */
/* ------------------------------------------------------------------ */

static void *
coraza_create_dir_conf(apr_pool_t *p, char *dir)
{
    coraza_dir_conf_t *dcf;

    dcf = apr_pcalloc(p, sizeof(coraza_dir_conf_t));
    dcf->enable = -1;  /* unset */
    dcf->rules = apr_array_make(p, 4, sizeof(coraza_rule_entry_t));

    return dcf;
}

static void *
coraza_merge_dir_conf(apr_pool_t *p, void *parent, void *child)
{
    coraza_dir_conf_t *pconf = (coraza_dir_conf_t *)parent;
    coraza_dir_conf_t *cconf = (coraza_dir_conf_t *)child;
    coraza_dir_conf_t *merged;

    merged = apr_pcalloc(p, sizeof(coraza_dir_conf_t));

    /* Child enable overrides parent when set */
    merged->enable = (cconf->enable != -1) ? cconf->enable : pconf->enable;

    /* Child transaction_id overrides parent when set */
    merged->transaction_id = cconf->transaction_id ?
        cconf->transaction_id : pconf->transaction_id;

    /* Prepend parent rules before child rules */
    if (pconf->rules->nelts > 0) {
        if (cconf->rules->nelts > 0) {
            /* Both have rules: merge parent + child */
            merged->rules = apr_array_make(p,
                pconf->rules->nelts + cconf->rules->nelts,
                sizeof(coraza_rule_entry_t));
            apr_array_cat(merged->rules, pconf->rules);
            apr_array_cat(merged->rules, cconf->rules);
            merged->has_rules = 1;
        } else {
            /* Only parent has rules: share pointer */
            merged->rules = pconf->rules;
            merged->has_rules = pconf->has_rules;
        }
    } else if (cconf->rules->nelts > 0) {
        /* Only child has rules */
        merged->rules = cconf->rules;
        merged->has_rules = cconf->has_rules;
    } else {
        /* Neither has rules */
        merged->rules = apr_array_make(p, 4, sizeof(coraza_rule_entry_t));
    }

    /* Track this merged dir_conf for WAF building in child_init */
    if (g_tracked_dir_confs != NULL) {
        coraza_dir_conf_t **dcp = apr_array_push(g_tracked_dir_confs);
        *dcp = merged;
    }

    return merged;
}

static void *
coraza_create_server_conf(apr_pool_t *p, server_rec *s)
{
    coraza_server_conf_t *scf;

    scf = apr_pcalloc(p, sizeof(coraza_server_conf_t));
    scf->rules = apr_array_make(p, 4, sizeof(coraza_rule_entry_t));
    scf->dir_confs = apr_array_make(p, 8, sizeof(coraza_dir_conf_t *));

    /*
     * Re-create the global tracking array each time.  Apache may parse
     * the config multiple times (e.g. -t, graceful restart) and we need
     * a fresh array allocated from the current config pool each time.
     */
    g_tracked_dir_confs = apr_array_make(p, 16,
                                         sizeof(coraza_dir_conf_t *));

    return scf;
}


/* ------------------------------------------------------------------ */
/* Helper: build a WAF from a rules array                              */
/* ------------------------------------------------------------------ */

coraza_waf_t
coraza_build_waf(apr_array_header_t *rules, server_rec *s)
{
    coraza_rule_entry_t *entries;
    coraza_waf_config_t config;
    coraza_waf_t waf;
    char *error = NULL;
    char *cstr;
    int i;

    if (rules == NULL || rules->nelts == 0) {
        return 0;
    }

    config = coraza_new_waf_config();
    if (config == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "coraza: failed to create WAF config");
        return 0;
    }

    entries = (coraza_rule_entry_t *)rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        cstr = strdup(entries[i].value);
        if (cstr == NULL) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                         "coraza: strdup failed for rule string");
            coraza_free_waf_config(config);
            return 0;
        }

        if (entries[i].type == CORAZA_RULE_INLINE) {
            if (coraza_rules_add(config, cstr) < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "coraza: failed to add inline rule: \"%s\"", cstr);
                free(cstr);
                coraza_free_waf_config(config);
                return 0;
            }
        } else {
            if (coraza_rules_add_file(config, cstr) < 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "coraza: failed to add rules file: \"%s\"", cstr);
                free(cstr);
                coraza_free_waf_config(config);
                return 0;
            }
        }
        free(cstr);
    }

    waf = coraza_new_waf(config, &error);
    coraza_free_waf_config(config);

    if (waf == 0) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                     "coraza: failed to create WAF: %s",
                     error ? error : "unknown error");
        return 0;
    }

    return waf;
}


/* ------------------------------------------------------------------ */
/* child_init: called in each child after fork                         */
/* ------------------------------------------------------------------ */

static void
coraza_child_init(apr_pool_t *p, server_rec *s)
{
    coraza_server_conf_t *scf;
    int i;

    /* Step 1: load libcoraza.so -- Go runtime initializes fresh here */
    if (coraza_dl_open(s) != OK) {
        ap_log_error(APLOG_MARK, APLOG_EMERG, 0, s,
                     "coraza: failed to load libcoraza.so, module disabled");
        return;
    }

    /* Step 2: build server WAFs for all server_recs */
    server_rec *sv;
    for (sv = s; sv; sv = sv->next) {
        scf = ap_get_module_config(sv->module_config, &coraza_module);
        if (scf == NULL) {
            continue;
        }

        if (scf->rules->nelts > 0) {
            scf->waf = coraza_build_waf(scf->rules, sv);
        } else {
            /* Empty WAF -- transactions pass through without rules */
            coraza_waf_config_t cfg = coraza_new_waf_config();
            if (cfg != 0) {
                char *err = NULL;
                scf->waf = coraza_new_waf(cfg, &err);
                coraza_free_waf_config(cfg);
            }
        }

        if (scf->waf == 0) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, sv,
                         "coraza: failed to build server WAF in child");
            continue;
        }

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                     "coraza: server WAF initialized with %d rules",
                     coraza_rules_count(scf->waf));
    }

    /* Step 3: build WAFs for tracked dir_confs */
    if (g_tracked_dir_confs != NULL) {
        coraza_dir_conf_t **dir_confs;
        dir_confs = (coraza_dir_conf_t **)g_tracked_dir_confs->elts;

        for (i = 0; i < g_tracked_dir_confs->nelts; i++) {
            coraza_dir_conf_t *dcf = dir_confs[i];

            if (!dcf->has_rules || dcf->rules->nelts == 0) {
                continue;
            }

            /* Check if another dir_conf already built this rules array */
            int j, found = 0;
            for (j = 0; j < i; j++) {
                if (dir_confs[j]->rules == dcf->rules &&
                    dir_confs[j]->waf != 0) {
                    dcf->waf = dir_confs[j]->waf;
                    found = 1;
                    break;
                }
            }
            if (found) {
                continue;
            }

            dcf->waf = coraza_build_waf(dcf->rules, s);
            if (dcf->waf == 0) {
                ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
                             "coraza: failed to build dir WAF in child");
                continue;
            }
            ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                         "coraza: dir WAF initialized with %d rules",
                         coraza_rules_count(dcf->waf));
        }
    }

    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s,
                 "coraza: WAFs initialized in child process %d",
                 (int)getpid());

    /* Register cleanup for child exit */
    apr_pool_cleanup_register(p, s, coraza_child_exit,
                              apr_pool_cleanup_null);
}


/* ------------------------------------------------------------------ */
/* child_exit: cleanup when a child shuts down                         */
/* ------------------------------------------------------------------ */

static apr_status_t
coraza_child_exit(void *data)
{
    server_rec *s = (server_rec *)data;
    server_rec *sv;
    coraza_server_conf_t *scf;
    int i;

    /* Free dir_conf WAFs */
    if (g_tracked_dir_confs != NULL) {
        coraza_dir_conf_t **dir_confs;
        dir_confs = (coraza_dir_conf_t **)g_tracked_dir_confs->elts;

        for (i = 0; i < g_tracked_dir_confs->nelts; i++) {
            coraza_dir_conf_t *dcf = dir_confs[i];

            if (dcf->waf == 0) {
                continue;
            }

            /* Skip if shared with a server WAF */
            int skip = 0;
            for (sv = s; sv; sv = sv->next) {
                scf = ap_get_module_config(sv->module_config, &coraza_module);
                if (scf && dcf->waf == scf->waf) {
                    skip = 1;
                    break;
                }
            }
            if (skip) {
                dcf->waf = 0;
                continue;
            }

            /* Skip if an earlier dir_conf shares this WAF */
            int j, shared = 0;
            for (j = 0; j < i; j++) {
                if (dir_confs[j]->waf == dcf->waf) {
                    shared = 1;
                    break;
                }
            }
            if (!shared) {
                coraza_free_waf(dcf->waf);
            }
            dcf->waf = 0;
        }
    }

    /* Free server WAFs */
    for (sv = s; sv; sv = sv->next) {
        scf = ap_get_module_config(sv->module_config, &coraza_module);
        if (scf == NULL) {
            continue;
        }
        if (scf->waf != 0) {
            coraza_free_waf(scf->waf);
            scf->waf = 0;
        }
    }

    coraza_dl_close(s);
    return APR_SUCCESS;
}


/* ------------------------------------------------------------------ */
/* post_config: log rule counts                                        */
/* ------------------------------------------------------------------ */

static int
coraza_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                   apr_pool_t *ptemp, server_rec *s)
{
    server_rec *sv;
    coraza_server_conf_t *scf;

    for (sv = s; sv; sv = sv->next) {
        scf = ap_get_module_config(sv->module_config, &coraza_module);
        if (scf == NULL) {
            continue;
        }

        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, sv,
                     "coraza: rules collected inline/file: %u/%u "
                     "(WAFs will be created in child processes)",
                     scf->rules_inline, scf->rules_file);
    }

    return OK;
}


/* ------------------------------------------------------------------ */
/* Hook registration                                                   */
/* ------------------------------------------------------------------ */

static void
coraza_register_hooks(apr_pool_t *p)
{
    /*
     * Phase 1: connection + URI + request headers.
     * We use fixups (not post_read_request) because <Location> per-dir
     * config is only resolved after translate_name/map_to_storage.
     */
    ap_hook_fixups(coraza_post_read_request, NULL, NULL,
                   APR_HOOK_REALLY_FIRST);

    /* Phase 5: logging */
    ap_hook_log_transaction(coraza_log_transaction, NULL, NULL,
                            APR_HOOK_MIDDLE);

    /* Input filter: request body (phase 2) */
    ap_register_input_filter(CORAZA_IN_FILTER, coraza_input_filter,
                             NULL, AP_FTYPE_CONTENT_SET);

    /* Output filter: response headers + body (phases 3-4) */
    ap_register_output_filter(CORAZA_OUT_FILTER, coraza_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);

    /* Post-config for logging */
    ap_hook_post_config(coraza_post_config, NULL, NULL, APR_HOOK_MIDDLE);

    /* child_init for dlopen and WAF building */
    ap_hook_child_init(coraza_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}


/* ------------------------------------------------------------------ */
/* Module declaration                                                  */
/* ------------------------------------------------------------------ */

AP_DECLARE_MODULE(coraza) = {
    STANDARD20_MODULE_STUFF,
    coraza_create_dir_conf,     /* create per-dir config */
    coraza_merge_dir_conf,      /* merge per-dir config */
    coraza_create_server_conf,  /* create per-server config */
    NULL,                       /* merge per-server config */
    coraza_directives,          /* directives */
    coraza_register_hooks       /* register hooks */
};
