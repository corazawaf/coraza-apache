/*
 * Coraza connector for Apache HTTPD -- Phase 2 (Request Body)
 *
 * Input filter: reads request body from the next filter and feeds
 * it to coraza for inspection before passing it through.
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */

#include "mod_coraza.h"

/*
 * Input filter (fallback for streaming body inspection).
 * Normally the fixups hook reads the body proactively, making this filter
 * a no-op. It only activates if a content handler reads the body itself
 * before fixups consumed it (unlikely but possible with custom handlers).
 */
apr_status_t
coraza_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                    ap_input_mode_t mode, apr_read_type_e block,
                    apr_off_t readbytes)
{
    coraza_request_ctx_t *ctx = f->ctx;
    apr_status_t rv;
    apr_bucket *b;
    int ret;

    /* Remove self if body was already read in fixups or intervention fired */
    if (ctx == NULL || ctx->intervention_triggered || ctx->phase2_done) {
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    /* Fetch the next bucket brigade from the filter chain below us */
    rv = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (rv != APR_SUCCESS) {
        return rv;
    }

    for (b = APR_BRIGADE_FIRST(bb);
         b != APR_BRIGADE_SENTINEL(bb);
         b = APR_BUCKET_NEXT(b))
    {
        const char *data;
        apr_size_t len;

        if (APR_BUCKET_IS_EOS(b)) {
            /* End of request body -- process it */
            coraza_process_request_body(ctx->transaction);

            ret = coraza_process_intervention(ctx->transaction, f->r, 0);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                ctx->phase2_done = 1;
                ap_remove_input_filter(f);
                return APR_EGENERAL;
            }

            ctx->phase2_done = 1;
            ap_remove_input_filter(f);
            break;
        }

        /* Skip non-data buckets (flush, metadata) */
        if (APR_BUCKET_IS_METADATA(b)) {
            continue;
        }

        /* Read the bucket data */
        rv = apr_bucket_read(b, &data, &len, block);
        if (rv != APR_SUCCESS) {
            return rv;
        }

        if (len > 0) {
            coraza_append_request_body(ctx->transaction,
                                       (unsigned char *)data, (int)len);

            /* Check for stream intervention */
            ret = coraza_process_intervention(ctx->transaction, f->r, 0);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                ctx->phase2_done = 1;
                ap_remove_input_filter(f);
                return APR_EGENERAL;
            }
        }
    }

    return APR_SUCCESS;
}
