/*
 * Coraza connector for Apache HTTPD -- Phases 3+4 (Response)
 *
 * Output filter: response headers (phase 3) and response body (phase 4).
 * Implements header delay: buffers output until body inspection completes
 * so that a phase-4 block can still return a clean error page.
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
 * Output filter: phases 3 (response headers) and 4 (response body).
 *
 * Implements header delay: buffers all output buckets in a pending brigade
 * until EOS arrives and body inspection passes. This lets the WAF reject
 * a response mid-stream with a clean error page instead of aborting after
 * 200 headers have already been sent to the client.
 */
apr_status_t
coraza_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    coraza_request_ctx_t *ctx = f->ctx;
    request_rec *r = f->r;
    apr_bucket *b;
    int ret;
    int has_eos = 0;

    if (ctx == NULL || ctx->intervention_triggered) {
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    /* Phase 3: Process response headers (first invocation) */
    if (!ctx->phase3_done) {
        const apr_array_header_t *tarr;
        const apr_table_entry_t *telts;
        int i;
        int status;
        const char *http_response_ver;

        ctx->phase3_done = 1;

        /* Send response headers to coraza */
        tarr = apr_table_elts(r->headers_out);
        telts = (const apr_table_entry_t *)tarr->elts;

        for (i = 0; i < tarr->nelts; i++) {
            if (telts[i].key == NULL) {
                continue;
            }
            coraza_add_response_header(ctx->transaction,
                                       (char *)telts[i].key,
                                       (int)strlen(telts[i].key),
                                       (char *)telts[i].val,
                                       telts[i].val ? (int)strlen(telts[i].val) : 0);
        }

        /* Also send err_headers_out (headers sent even on error) */
        tarr = apr_table_elts(r->err_headers_out);
        telts = (const apr_table_entry_t *)tarr->elts;

        for (i = 0; i < tarr->nelts; i++) {
            if (telts[i].key == NULL) {
                continue;
            }
            coraza_add_response_header(ctx->transaction,
                                       (char *)telts[i].key,
                                       (int)strlen(telts[i].key),
                                       (char *)telts[i].val,
                                       telts[i].val ? (int)strlen(telts[i].val) : 0);
        }

        status = r->status;
        http_response_ver = r->protocol ? r->protocol : "HTTP/1.1";

        coraza_process_response_headers(ctx->transaction, status,
                                        (char *)http_response_ver);

        ret = coraza_process_intervention(ctx->transaction, r, 0);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            ap_remove_output_filter(f);
            apr_brigade_cleanup(bb);
            r->status = ret;
            return APR_EGENERAL;
        }

        /* Begin header delay — skip for HEAD (no body), subrequests (internal),
         * and error responses (already have final status, e.g. ErrorDocument) */
        if (r->header_only || r->main != NULL || r->status >= 400) {
            /* Skip delay */
        } else {
            ctx->pending_brigade = apr_brigade_create(r->pool,
                                                       f->c->bucket_alloc);
            if (ctx->pending_brigade != NULL) {
                ctx->headers_delayed = 1;
            }
        }
    }

    /* Phase 4: Process response body buckets */
    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        const char *data;
        apr_size_t len;
        apr_status_t rv;

        if (APR_BUCKET_IS_EOS(b)) {
            has_eos = 1;
            continue;
        }

        if (APR_BUCKET_IS_METADATA(b)) {
            continue;
        }

        rv = apr_bucket_read(b, &data, &len, APR_BLOCK_READ);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        if (len > 0) {
            coraza_append_response_body(ctx->transaction,
                                        (unsigned char *)data, (int)len);

            ret = coraza_process_intervention(ctx->transaction, r, 0);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                ap_remove_output_filter(f);
                if (ctx->headers_delayed) {
                    ctx->headers_delayed = 0;
                    apr_brigade_cleanup(ctx->pending_brigade);
                }
                apr_brigade_cleanup(bb);
                r->status = ret;
                return APR_EGENERAL;
            }
        }
    }

    if (has_eos) {
        /* Process complete response body */
        coraza_process_response_body(ctx->transaction);

        ret = coraza_process_intervention(ctx->transaction, r, 0);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            ctx->phase4_done = 1;
            ap_remove_output_filter(f);
            if (ctx->headers_delayed) {
                ctx->headers_delayed = 0;
                apr_brigade_cleanup(ctx->pending_brigade);
            }
            apr_brigade_cleanup(bb);
            r->status = ret;
            return APR_EGENERAL;
        }

        ctx->phase4_done = 1;

        if (ctx->headers_delayed) {
            /* Phase 4 completed clean -- release everything */
            ctx->headers_delayed = 0;

            /* Prepend pending before current brigade to maintain order */
            APR_BRIGADE_PREPEND(bb, ctx->pending_brigade);

            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
        }

        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    /* Not the last buffer yet */
    if (ctx->headers_delayed) {
        /* Accumulate into pending brigade during header delay */
        APR_BRIGADE_CONCAT(ctx->pending_brigade, bb);
        return APR_SUCCESS;
    }

    return ap_pass_brigade(f->next, bb);
}
