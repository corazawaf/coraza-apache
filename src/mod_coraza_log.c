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

int
coraza_log_transaction(request_rec *r)
{
    coraza_dir_conf_t *dcf;
    coraza_request_ctx_t *ctx;

    dcf = ap_get_module_config(r->per_dir_config, &coraza_module);
    if (dcf == NULL || dcf->enable != 1) {
        return OK;
    }

    ctx = ap_get_module_config(r->request_config, &coraza_module);
    if (ctx == NULL) {
        return OK;
    }

    if (ctx->logged) {
        return OK;
    }

    ctx->logged = 1;
    coraza_process_logging(ctx->transaction);

    return OK;
}
