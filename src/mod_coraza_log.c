/*
 * Coraza connector for Apache HTTPD -- Phase 5 (Logging)
 *
 * log_transaction hook: calls coraza_process_logging() for audit logs.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "mod_coraza.h"

/*
 * Phase 5 audit logging via log_transaction hook.
 *
 * Guard clauses:
 * - enable != 1: WAF is off for this scope (Coraza Off or unset)
 * - ctx == NULL: no transaction — subrequest or non-inspected request
 * - ctx->logged: already logged (early log during phase 1/2 intervention)
 */
int
coraza_log_transaction(request_rec *r)
{
    coraza_dir_conf_t *dcf;
    coraza_request_ctx_t *ctx;

    /* Skip if WAF disabled for this scope */
    dcf = ap_get_module_config(r->per_dir_config, &coraza_module);
    if (dcf == NULL || dcf->enable != 1) {
        return OK;
    }

    /* No transaction context — subrequest or uninspected request */
    ctx = ap_get_module_config(r->request_config, &coraza_module);
    if (ctx == NULL) {
        return OK;
    }

    /* Prevent double-logging after early log in phase 1/2 intervention */
    if (ctx->logged) {
        return OK;
    }

    ctx->logged = 1;
    coraza_process_logging(ctx->transaction);

    return OK;
}
