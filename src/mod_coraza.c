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
#include <apr_thread_mutex.h>

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
static const char *cmd_sec_directive(cmd_parms *cmd, void *dcfg, const char *args);

/*
 * Module-level tracking of all merged dir_confs.
 * Apache's merge_dir_conf callback doesn't receive a server_rec, so we
 * use a static array (safe: config parsing is single-threaded in parent).
 */
static apr_array_header_t *g_tracked_dir_confs = NULL;
static apr_array_header_t *g_config_dir_confs = NULL; /* frozen after child_init */
static apr_thread_mutex_t *g_waf_build_mutex = NULL;

/*
 * WAF cache: content-based hash → WAF handle.
 * Linear array — no slot collisions, bounded by unique rule sets (~30).
 * Hash is computed from rule string CONTENT, not pointer values,
 * so .htaccess (per-request pool) and Location merges produce stable hashes.
 * Protected by g_waf_build_mutex.
 */
#define WAF_CACHE_MAX 64

typedef struct {
    unsigned long hash;
    int           rules_nelts;
    coraza_waf_t  waf;
} waf_cache_entry_t;

static waf_cache_entry_t g_waf_cache[WAF_CACHE_MAX];
static int g_waf_cache_count = 0;

/* DJB2 hash over rule content (type + value strings). */
static unsigned long
rules_hash(apr_array_header_t *rules)
{
    coraza_rule_entry_t *entries = (coraza_rule_entry_t *)rules->elts;
    unsigned long h = 5381;
    int i;
    for (i = 0; i < rules->nelts; i++) {
        const char *s = entries[i].value;
        h = h * 33 + entries[i].type;
        while (*s) {
            h = h * 33 + (unsigned char)*s++;
        }
    }
    return h;
}

static coraza_waf_t
waf_cache_find(unsigned long hash, int nelts)
{
    int i;
    for (i = 0; i < g_waf_cache_count; i++) {
        if (g_waf_cache[i].hash == hash && g_waf_cache[i].rules_nelts == nelts) {
            return g_waf_cache[i].waf;
        }
    }
    return 0;
}

static void
waf_cache_add(unsigned long hash, int nelts, coraza_waf_t waf)
{
    if (g_waf_cache_count < WAF_CACHE_MAX) {
        g_waf_cache[g_waf_cache_count].hash = hash;
        g_waf_cache[g_waf_cache_count].rules_nelts = nelts;
        g_waf_cache[g_waf_cache_count].waf = waf;
        g_waf_cache_count++;
    }
}


/* ------------------------------------------------------------------ */
/* Intervention processing                                             */
/* ------------------------------------------------------------------ */

/*
 * Check if the WAF engine has queued an intervention (block/deny/redirect).
 * Returns OK if no action needed, or an HTTP status code (e.g. 403) to abort.
 * When early_log is set, triggers audit logging immediately so the denied
 * request is logged even though the log_transaction hook hasn't run yet.
 */
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

/*
 * Allocate a per-request context and create a WAF transaction.
 * The WAF handle is resolved with a 3-tier strategy:
 *   1. merge_child fast path — reuse WAF already built for the stable child
 *   2. Content-hash cache — O(N) scan of cached WAFs by rule content hash
 *   3. Build new WAF — compile rules, add to cache
 * Falls back to the server-level WAF if the dir_conf has no rules.
 */
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
     * Lazy WAF building: if this dir_conf has rules but no WAF yet,
     * try merge_child cache, then WAF hash cache, then build new.
     */
    if (dcf->waf == 0 && dcf->has_rules && dcf->rules->nelts > 0) {
        apr_thread_mutex_lock(g_waf_build_mutex);

        /* Strategy 1: re-check merge_child for concurrent build race */
        if (dcf->waf == 0 && dcf->merge_child != NULL) {
            dcf->waf = ((coraza_dir_conf_t *)dcf->merge_child)->waf;
        }

        /* Strategy 2: WAF content-hash cache lookup */
        if (dcf->waf == 0) {
            unsigned long h = rules_hash(dcf->rules);
            coraza_waf_t cached = waf_cache_find(h, dcf->rules->nelts);
            if (cached != 0) {
                dcf->waf = cached;
                if (dcf->merge_child != NULL) {
                    ((coraza_dir_conf_t *)dcf->merge_child)->waf = dcf->waf;
                }
            }
        }

        /* Strategy 3: build new WAF and cache it */
        if (dcf->waf == 0) {
            unsigned long h = rules_hash(dcf->rules);
            dcf->waf = coraza_build_waf(dcf->rules, r->server);
            if (dcf->waf != 0) {
                waf_cache_add(h, dcf->rules->nelts, dcf->waf);
            }
            if (dcf->merge_child != NULL) {
                ((coraza_dir_conf_t *)dcf->merge_child)->waf = dcf->waf;
            }
        }

        apr_thread_mutex_unlock(g_waf_build_mutex);
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

/* Handle "Coraza On|Off" — sets enable flag for this scope. */
static const char *
cmd_coraza_enable(cmd_parms *cmd, void *dcfg, int flag)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    dcf->enable = flag ? 1 : 0;
    return NULL;
}

/* Handle "CorazaRules <rule>" — store an inline rule string.
 * Server-level rules (cmd->path==NULL) also go into scf->rules for the
 * fallback WAF; per-dir rules stay in the dir_conf only. */
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

/* Handle "CorazaRulesFile <path>" — store a rules file path.
 * Paths with relative @pmFromFile data are resolved by Coraza relative
 * to the rules file, not the Apache config. */
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

/* Handle "CorazaTransactionId <id>" — override auto-generated transaction ID. */
static const char *
cmd_coraza_transaction_id(cmd_parms *cmd, void *dcfg, const char *arg)
{
    coraza_dir_conf_t *dcf = (coraza_dir_conf_t *)dcfg;
    dcf->transaction_id = apr_pstrdup(cmd->pool, arg);
    return NULL;
}


/*
 * Generic handler for native Sec* directives.
 * AP_INIT_RAW_ARGS passes the raw text after the directive name.
 * We reconstruct the full line (e.g. "SecRuleEngine On") and store it
 * as an inline rule — coraza_rules_add() already parses all Sec* directives.
 */
static const char *
cmd_sec_directive(cmd_parms *cmd, void *dcfg, const char *args)
{
    const char *full;

    /* Reconstruct: "SecRuleEngine On" from name="SecRuleEngine", args="On" */
    full = apr_pstrcat(cmd->pool, cmd->cmd->name, " ", args, NULL);

    /* Same logic as cmd_coraza_rules */
    return cmd_coraza_rules(cmd, dcfg, full);
}


/* ------------------------------------------------------------------ */
/* Directives                                                          */
/* ------------------------------------------------------------------ */

/*
 * Macro: register a native Sec* directive.
 * All use AP_INIT_RAW_ARGS so the raw text is passed through unchanged.
 */
#define SEC_DIRECTIVE(name) \
    AP_INIT_RAW_ARGS(name, cmd_sec_directive, NULL, \
                     RSRC_CONF | ACCESS_CONF | OR_ALL, \
                     "Native modsecurity directive (handled by Coraza)")

static const command_rec coraza_directives[] = {
    AP_INIT_FLAG("Coraza", cmd_coraza_enable, NULL,
                 RSRC_CONF | ACCESS_CONF | OR_ALL,
                 "Enable or disable Coraza WAF"),
    AP_INIT_TAKE1("CorazaRules", cmd_coraza_rules, NULL,
                  RSRC_CONF | ACCESS_CONF | OR_ALL,
                  "Inline Coraza rules"),
    AP_INIT_TAKE1("CorazaRulesFile", cmd_coraza_rules_file, NULL,
                  RSRC_CONF | ACCESS_CONF | OR_ALL,
                  "Path to Coraza rules file"),
    AP_INIT_TAKE1("CorazaTransactionId", cmd_coraza_transaction_id, NULL,
                  RSRC_CONF | ACCESS_CONF | OR_ALL,
                  "Custom transaction ID"),

    /* Native Sec* directives — all handled by cmd_sec_directive */
    SEC_DIRECTIVE("SecRuleEngine"),
    SEC_DIRECTIVE("SecRule"),
    SEC_DIRECTIVE("SecAction"),
    SEC_DIRECTIVE("SecMarker"),
    SEC_DIRECTIVE("SecDefaultAction"),
    SEC_DIRECTIVE("SecRequestBodyAccess"),
    SEC_DIRECTIVE("SecRequestBodyLimit"),
    SEC_DIRECTIVE("SecRequestBodyNoFilesLimit"),
    SEC_DIRECTIVE("SecRequestBodyInMemoryLimit"),
    SEC_DIRECTIVE("SecRequestBodyLimitAction"),
    SEC_DIRECTIVE("SecResponseBodyAccess"),
    SEC_DIRECTIVE("SecResponseBodyMimeType"),
    SEC_DIRECTIVE("SecResponseBodyLimit"),
    SEC_DIRECTIVE("SecResponseBodyLimitAction"),
    SEC_DIRECTIVE("SecTmpDir"),
    SEC_DIRECTIVE("SecDataDir"),
    SEC_DIRECTIVE("SecAuditEngine"),
    SEC_DIRECTIVE("SecAuditLog"),
    SEC_DIRECTIVE("SecAuditLogParts"),
    SEC_DIRECTIVE("SecAuditLogRelevantStatus"),
    SEC_DIRECTIVE("SecAuditLogType"),
    SEC_DIRECTIVE("SecAuditLogStorageDir"),
    SEC_DIRECTIVE("SecArgumentSeparator"),
    SEC_DIRECTIVE("SecCookieFormat"),
    SEC_DIRECTIVE("SecUnicodeMapFile"),
    SEC_DIRECTIVE("SecStatusEngine"),
    SEC_DIRECTIVE("SecPcreMatchLimit"),
    SEC_DIRECTIVE("SecPcreMatchLimitRecursion"),
    SEC_DIRECTIVE("SecDebugLog"),
    SEC_DIRECTIVE("SecDebugLogLevel"),
    SEC_DIRECTIVE("SecRuleRemoveById"),
    SEC_DIRECTIVE("SecRuleRemoveByTag"),
    SEC_DIRECTIVE("SecRuleRemoveByMsg"),
    SEC_DIRECTIVE("SecRuleUpdateActionById"),
    SEC_DIRECTIVE("SecRuleUpdateTargetById"),
    SEC_DIRECTIVE("SecRuleUpdateTargetByTag"),
    SEC_DIRECTIVE("SecRuleUpdateTargetByMsg"),
    SEC_DIRECTIVE("SecComponentSignature"),
    SEC_DIRECTIVE("SecWebAppId"),
    SEC_DIRECTIVE("SecCollectionTimeout"),
    SEC_DIRECTIVE("SecContentInjection"),
    SEC_DIRECTIVE("SecConnEngine"),
    SEC_DIRECTIVE("SecSensorId"),
    SEC_DIRECTIVE("SecHashEngine"),
    SEC_DIRECTIVE("SecHashKey"),
    SEC_DIRECTIVE("SecHashParam"),
    SEC_DIRECTIVE("SecHashMethodRx"),
    SEC_DIRECTIVE("SecHashMethodPm"),
    SEC_DIRECTIVE("SecStreamInBodyInspection"),
    SEC_DIRECTIVE("SecStreamOutBodyInspection"),
    SEC_DIRECTIVE("SecUploadDir"),
    SEC_DIRECTIVE("SecUploadKeepFiles"),
    SEC_DIRECTIVE("SecUploadFileMode"),
    SEC_DIRECTIVE("SecUploadFileLimit"),
    SEC_DIRECTIVE("SecRemoteRules"),
    SEC_DIRECTIVE("SecRemoteRulesFailAction"),
    SEC_DIRECTIVE("SecInterceptOnError"),
    SEC_DIRECTIVE("SecDisableBackendCompression"),
    SEC_DIRECTIVE("SecHttpBlKey"),
    SEC_DIRECTIVE("SecGsbLookupDb"),
    SEC_DIRECTIVE("SecXmlExternalEntity"),
    SEC_DIRECTIVE("SecRuleScript"),
    SEC_DIRECTIVE("SecTmpSaveUploadedFiles"),

    { NULL }
};


/* ------------------------------------------------------------------ */
/* Config creation and merge                                           */
/* ------------------------------------------------------------------ */

/* Allocate a fresh per-directory config with enable=-1 (unset). */
static void *
coraza_create_dir_conf(apr_pool_t *p, char *dir)
{
    coraza_dir_conf_t *dcf;

    dcf = apr_pcalloc(p, sizeof(coraza_dir_conf_t));
    dcf->enable = -1;  /* unset */
    dcf->rules = apr_array_make(p, 4, sizeof(coraza_rule_entry_t));

    return dcf;
}

/* Merge parent + child dir_confs: child enable/txid override parent when set,
 * parent rules are prepended before child rules for correct evaluation order. */
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
            /* Propagate cached WAF from stable child; set back-pointer for caching */
            merged->waf = cconf->waf;
            merged->merge_child = cconf;
        } else {
            /* Only parent has rules: propagate parent's WAF */
            merged->rules = pconf->rules;
            merged->has_rules = pconf->has_rules;
            merged->waf = pconf->waf;
        }
    } else if (cconf->rules->nelts > 0) {
        /* Only child has rules: propagate child's WAF */
        merged->rules = cconf->rules;
        merged->has_rules = cconf->has_rules;
        merged->waf = cconf->waf;
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

/* Allocate per-server config. Also resets the global dir_conf tracker
 * (Apache may parse config multiple times: -t, graceful restart). */
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

/*
 * Replay a deferred rules array through libcoraza to produce a WAF handle.
 * Each entry is either an inline rule string (coraza_rules_add) or a file
 * path (coraza_rules_add_file). Returns 0 on failure.
 */
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

/*
 * Post-fork initialization in each child process:
 *   Step 1: dlopen libcoraza.so (Go runtime starts fresh in child)
 *   Step 2: Build server-level WAFs for all server_recs (main + VHosts)
 *   Step 3: Build WAFs for tracked dir_confs (Location/Directory merges)
 * After this, g_tracked_dir_confs is frozen to prevent dangling pointers
 * from request-time merges (.htaccess) into the config-time array.
 */
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

    /* Create mutex for lazy WAF building (event MPM thread safety) */
    apr_thread_mutex_create(&g_waf_build_mutex, APR_THREAD_MUTEX_DEFAULT, p);

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

        /* Share WAF with server base dir_conf so request-time merges inherit it */
        coraza_dir_conf_t *base_dcf = ap_get_module_config(sv->lookup_defaults,
                                                            &coraza_module);
        if (base_dcf != NULL && base_dcf->waf == 0) {
            base_dcf->waf = scf->waf;
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

    /* Freeze config-time dir_confs for child_exit cleanup.
     * Stop accumulating request-time merges (they'd be dangling pointers). */
    g_config_dir_confs = g_tracked_dir_confs;
    g_tracked_dir_confs = NULL;

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

/*
 * Child process cleanup: free all WAF handles then dlclose libcoraza.
 * Deduplicates shared WAF pointers: dir_conf WAFs that point to a server
 * WAF are zeroed first, then earlier dir_conf duplicates are skipped,
 * ensuring each unique WAF is freed exactly once.
 */
static apr_status_t
coraza_child_exit(void *data)
{
    server_rec *s = (server_rec *)data;
    server_rec *sv;
    coraza_server_conf_t *scf;
    int i;

    /* Free dir_conf WAFs (config-time only — frozen in child_init).
     * Two-pass approach: first pass frees unique WAFs while keeping
     * pointers intact for dedup comparison, second pass zeroes all.
     * This prevents double-free when multiple dir_confs share a handle. */
    if (g_config_dir_confs != NULL) {
        coraza_dir_conf_t **dir_confs;
        dir_confs = (coraza_dir_conf_t **)g_config_dir_confs->elts;

        for (i = 0; i < g_config_dir_confs->nelts; i++) {
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
                continue;
            }

            /* Skip if an earlier dir_conf already freed this WAF */
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
        }
        for (i = 0; i < g_config_dir_confs->nelts; i++) {
            dir_confs[i]->waf = 0;
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

/* Post-config hook: log collected rule counts for each server_rec.
 * WAFs aren't built yet (that happens post-fork in child_init). */
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
    NULL,                       /* merge per-server config — intentionally NULL:
                                 * Apache copies the parent server config as the
                                 * base for each VirtualHost, so CRS rules from
                                 * server scope inherit automatically. */
    coraza_directives,          /* directives */
    coraza_register_hooks       /* register hooks */
};
