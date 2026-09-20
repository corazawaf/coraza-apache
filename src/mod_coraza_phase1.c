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
#include "apr_strings.h"
#include "apr_file_io.h"
#include "http_log.h"
#include <string.h>

/*
 * Open the temp file the saved request body spills into once it passes
 * CorazaRequestBodyInMemoryLimit. Exclusive, binary, and deleted on close --
 * the request pool closes it, so the file never outlives the request.
 */
static apr_status_t
coraza_open_body_spool(request_rec *r, apr_file_t **spool)
{
    const char *tmpdir;
    char *tmpl;
    apr_status_t rv;

    rv = apr_temp_dir_get(&tmpdir, r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "coraza: no temp directory to spool the request body");
        return rv;
    }
    tmpl = apr_pstrcat(r->pool, tmpdir, "/coraza-body-XXXXXX", NULL);
    rv = apr_file_mktemp(spool, tmpl,
                         APR_FOPEN_CREATE | APR_FOPEN_READ | APR_FOPEN_WRITE
                         | APR_FOPEN_EXCL | APR_FOPEN_BINARY
                         | APR_FOPEN_DELONCLOSE,
                         r->pool);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
                      "coraza: cannot create request body spool file %s", tmpl);
        return rv;
    }
    ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                  "coraza: request body exceeds CorazaRequestBodyInMemoryLimit, "
                  "spooling the remainder to %s", tmpl);
    return APR_SUCCESS;
}

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
/* The transaction of the request the client actually sent, found by walking
 * back through the internal-redirect chain (r->prev). NULL when none of the
 * earlier request_recs was inspected. */
static coraza_request_ctx_t *
coraza_ctx_from_prev(request_rec *r)
{
    request_rec *p;
    coraza_request_ctx_t *ctx;

    for (p = r->prev; p != NULL; p = p->prev) {
        ctx = ap_get_module_config(p->request_config, &coraza_module);
        if (ctx != NULL) {
            return ctx;
        }
    }
    return NULL;
}

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

    /* Internal redirect (ErrorDocument, FallbackResource, DirectoryIndex,
     * mod_rewrite): a new request_rec, but the same client request. The
     * transaction belongs to the request the client sent, so reuse it --
     * phases 1 and 2 already ran there and the body has been consumed -- and
     * re-attach the output filter, which httpd drops on an internal redirect,
     * so phases 3 and 4 inspect the response the client actually receives
     * under that transaction and its single audit entry. A transaction that
     * already denied (we are serving our own error page) passes the filter's
     * intervention guard untouched: no second deny, no error-page loop. When
     * no earlier request_rec was inspected, fall through and treat this as a
     * fresh request. */
    if (r->prev != NULL) {
        ctx = coraza_ctx_from_prev(r);
        if (ctx != NULL) {
            ap_set_module_config(r->request_config, &coraza_module, ctx);
            ap_add_output_filter(CORAZA_OUT_FILTER, ctx, r, r->connection);
            return DECLINED;
        }
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

        /* Coraza expects the protocol in slash-delimited form (e.g. "HTTP/1.1"),
         * matching REQUEST_PROTOCOL; passing a bare "1.1" makes protocol rules
         * miss.
         *
         * r->protocol is the token as it arrived, so prefer it: mapping
         * r->proto_num through the enum below collapses every version Apache
         * does not know onto "HTTP/1.1", and a rule whose whole job is to
         * reject versions outside a policy -- CRS 920430,
         * `REQUEST_PROTOCOL "!@within %{tx.allowed_http_versions}"` -- then has
         * nothing left to reject. The enum stays as the fallback for the case
         * where r->protocol is not set. (coraza-nginx has the same mapping and
         * cannot do better: nginx refuses an unknown version in its own
         * parser, so the string never reaches the module.) */
        switch (r->proto_num) {
        case HTTP_VERSION(0, 9):
            http_version = "HTTP/0.9";
            break;
        case HTTP_VERSION(1, 0):
            http_version = "HTTP/1.0";
            break;
        case HTTP_VERSION(1, 1):
            http_version = "HTTP/1.1";
            break;
        case HTTP_VERSION(2, 0):
            http_version = "HTTP/2.0";
            break;
        default:
            http_version = "HTTP/1.1";
            break;
        }

        if (r->protocol != NULL && *r->protocol != '\0') {
            http_version = r->protocol;
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
            size_t name_len, val_len;

            if (telts[i].key == NULL) {
                continue;
            }

            /*
             * coraza_add_request_header takes int lengths; guard the size_t ->
             * int narrowing so an oversized header cannot wrap to a bogus
             * length and slip past inspection. Fail closed.
             */
            name_len = strlen(telts[i].key);
            val_len  = telts[i].val ? strlen(telts[i].val) : 0;
            if (name_len > INT_MAX || val_len > INT_MAX) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "coraza: request header too long to inspect");
                ctx->intervention_triggered = 1;
                return HTTP_INTERNAL_SERVER_ERROR;
            }

            coraza_add_request_header(ctx->transaction,
                                      (char *)telts[i].key,
                                      (int)name_len,
                                      (char *)telts[i].val,
                                      (int)val_len);
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
     * the handler may never read the body (e.g. static file 404).
     *
     * ap_get_client_block() consumes the connection input, so every byte read
     * here is a byte the handler will never see. Coraza's other connectors do
     * not have that problem: under nginx the module calls
     * ngx_http_read_client_request_body(), which buffers into
     * r->request_body->bufs and leaves it there for the upstream. Apache has
     * no equivalent, so we keep a copy and replay it from CORAZA_IN, which
     * restores the same guarantee -- the application behind the WAF receives
     * the body it was sent. */
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
            apr_off_t mem_limit = (dcf->body_mem_limit >= 0)
                                  ? dcf->body_mem_limit
                                  : CORAZA_DEFAULT_BODY_MEM_LIMIT;
            apr_off_t saved_len = 0;
            apr_file_t *spool = NULL;
            apr_off_t spool_len = 0;

            ctx->saved_body = apr_brigade_create(r->pool,
                                                 r->connection->bucket_alloc);

            /* ap_get_client_block: reads up to N bytes, returns count or -1 */
            while ((nread = ap_get_client_block(r, buf, sizeof(buf))) > 0) {
                /* Keep a copy before inspecting: an intervention returns from
                 * inside this loop, and on that path the request never reaches
                 * a handler anyway. The copy lives in memory up to
                 * CorazaRequestBodyInMemoryLimit and in a temp file past it, so
                 * a large upload does not pin its whole body in worker memory
                 * (the engine's own limits do not bound this copy: under
                 * ProcessPartial the read continues past SecRequestBodyLimit). */
                if (spool == NULL && saved_len + nread <= mem_limit) {
                    if (apr_brigade_write(ctx->saved_body, NULL, NULL,
                                          buf, (apr_size_t)nread) != APR_SUCCESS) {
                        ctx->intervention_triggered = 1;
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    saved_len += nread;
                } else {
                    if (spool == NULL
                        && coraza_open_body_spool(r, &spool) != APR_SUCCESS) {
                        ctx->intervention_triggered = 1;
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    if (apr_file_write_full(spool, buf, (apr_size_t)nread, NULL)
                            != APR_SUCCESS) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                                      "coraza: failed to spool request body");
                        ctx->intervention_triggered = 1;
                        return HTTP_INTERNAL_SERVER_ERROR;
                    }
                    spool_len += nread;
                }

                if (CORAZA_CALL_FAILED(coraza_append_request_body(
                        ctx->transaction, (unsigned char *)buf, (int)nread))) {
                    /* Engine error: fail closed rather than skip inspection. */
                    ctx->intervention_triggered = 1;
                    return HTTP_INTERNAL_SERVER_ERROR;
                }

                ret = coraza_process_intervention(ctx->transaction, r, 1);
                if (ret > 0) {
                    ctx->intervention_triggered = 1;
                    return ret;
                }
            }

            if (nread < 0) {
                return HTTP_BAD_REQUEST;
            }

            if (spool != NULL) {
                /* The spooled tail follows the in-memory head as one file
                 * bucket; the replay filter partitions it like any other. */
                APR_BRIGADE_INSERT_TAIL(
                    ctx->saved_body,
                    apr_bucket_file_create(spool, 0, (apr_size_t)spool_len,
                                           r->pool, r->connection->bucket_alloc));
            }

            /* The handler reads until EOS, so the replay has to carry one. */
            APR_BRIGADE_INSERT_TAIL(
                ctx->saved_body,
                apr_bucket_eos_create(r->connection->bucket_alloc));
            /* ap_get_client_block() advanced r->read_length, and
             * ap_should_client_block() treats a non-zero read_length as "body
             * already read" (ap_setup_client_block() does not reset it). Zero
             * it so handlers on the legacy ap_get_client_block() API ask for
             * the body and receive the replay; brigade readers are unaffected. */
            r->read_length = 0;
            ap_add_input_filter(CORAZA_IN_FILTER, ctx, r, r->connection);

            if (coraza_process_failed(coraza_process_request_body(ctx->transaction))) {
                ctx->intervention_triggered = 1;
                return HTTP_INTERNAL_SERVER_ERROR;
            }
            ctx->phase2_done = 1;

            ret = coraza_process_intervention(ctx->transaction, r, 1);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                return ret;
            }
        } else {
            /* No body to read, still finalize phase 2 */
            if (coraza_process_failed(coraza_process_request_body(ctx->transaction))) {
                ctx->intervention_triggered = 1;
                return HTTP_INTERNAL_SERVER_ERROR;
            }
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
