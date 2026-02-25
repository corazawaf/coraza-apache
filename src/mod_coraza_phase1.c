/*
 * Coraza connector for Apache HTTPD -- Phases 1+2
 *
 * fixups hook: connection + URI + request headers (phase 1),
 * then proactive request body read + inspection (phase 2).
 *
 * We read the body here (not in an input filter) because Apache's
 * default handler may not read the body for static-file requests,
 * and the WAF needs to inspect the body before the handler runs.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "mod_coraza.h"
#include <string.h>

/*
 * Fixups hook (runs as APR_HOOK_REALLY_FIRST):
 * - Phase 1: feed connection info, URI, method, and request headers to Coraza
 * - Phase 2: proactively read and inspect the full request body
 *
 * We use fixups instead of post_read_request because Apache resolves
 * per-dir config (<Location>) only after map_to_storage. Reading the body
 * here ensures the WAF inspects it even for handlers that never consume
 * it (e.g. static file serving returning 404).
 */
int
coraza_post_read_request(request_rec *r)
{
    coraza_dir_conf_t *dcf;
    coraza_request_ctx_t *ctx;
    int ret;

    /* Skip subrequests */
    if (r->main != NULL) {
        return DECLINED;
    }

    dcf = ap_get_module_config(r->per_dir_config, &coraza_module);
    if (dcf == NULL || dcf->enable != 1) {
        return DECLINED;
    }

    /* Check if context already exists */
    ctx = ap_get_module_config(r->request_config, &coraza_module);
    if (ctx != NULL) {
        return DECLINED;
    }

    /* Create transaction context */
    ctx = coraza_create_ctx(r);
    if (ctx == NULL) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Phase 1: Process connection info */
    {
        int client_port = r->useragent_addr ? r->useragent_addr->port : 0;
        int server_port = r->connection->local_addr ?
            r->connection->local_addr->port : 0;
        char *client_ip = r->useragent_ip ? r->useragent_ip : "0.0.0.0";
        char *server_ip = r->connection->local_ip ?
            r->connection->local_ip : "0.0.0.0";

        coraza_process_connection(ctx->transaction,
                                 client_ip, client_port,
                                 server_ip, server_port);

        ret = coraza_process_intervention(ctx->transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }

    /* Phase 1: Process URI, method, protocol */
    {
        const char *http_version;

        switch (r->proto_num) {
        case HTTP_VERSION(0, 9):
            http_version = "0.9";
            break;
        case HTTP_VERSION(1, 0):
            http_version = "1.0";
            break;
        case HTTP_VERSION(1, 1):
            http_version = "1.1";
            break;
        case HTTP_VERSION(2, 0):
            http_version = "2.0";
            break;
        default:
            http_version = "1.1";
            break;
        }

        coraza_process_uri(ctx->transaction,
                           (char *)r->unparsed_uri,
                           (char *)r->method,
                           (char *)http_version);

        ret = coraza_process_intervention(ctx->transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }

    /* Phase 1: Process request headers */
    {
        const apr_array_header_t *tarr;
        const apr_table_entry_t *telts;
        int i;

        tarr = apr_table_elts(r->headers_in);
        telts = (const apr_table_entry_t *)tarr->elts;

        for (i = 0; i < tarr->nelts; i++) {
            if (telts[i].key == NULL) {
                continue;
            }
            coraza_add_request_header(ctx->transaction,
                                      (char *)telts[i].key,
                                      (int)strlen(telts[i].key),
                                      (char *)telts[i].val,
                                      telts[i].val ? (int)strlen(telts[i].val) : 0);
        }

        coraza_process_request_headers(ctx->transaction);

        ret = coraza_process_intervention(ctx->transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ret;
        }
    }

    /* Add output filter for response phases 3+4 */
    ap_add_output_filter(CORAZA_OUT_FILTER, ctx, r, r->connection);

    /* Phase 2: Proactive request body read + inspection.
     * We read the body here instead of in an input filter because
     * the handler may never read the body (e.g. static file 404). */
    {
        int rc;
        char buf[8192];
        long nread;

        /* Prepare to read the request body with automatic chunked decoding */
        rc = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK);
        if (rc != OK) {
            return rc;
        }

        /* ap_should_client_block: returns true if there is a body to read */
        if (ap_should_client_block(r)) {
            /* ap_get_client_block: reads up to N bytes, returns count or -1 */
            while ((nread = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
                coraza_append_request_body(ctx->transaction,
                                           (unsigned char *)buf, (int)nread);

                ret = coraza_process_intervention(ctx->transaction, r, 1);
                if (ret > 0) {
                    ctx->intervention_triggered = 1;
                    return ret;
                }
            }

            if (nread < 0) {
                return HTTP_BAD_REQUEST;
            }

            coraza_process_request_body(ctx->transaction);
            ctx->phase2_done = 1;

            ret = coraza_process_intervention(ctx->transaction, r, 1);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                return ret;
            }
        } else {
            /* No body to read, still finalize phase 2 */
            coraza_process_request_body(ctx->transaction);
            ctx->phase2_done = 1;

            ret = coraza_process_intervention(ctx->transaction, r, 1);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                return ret;
            }
        }
    }

    return DECLINED;
}
