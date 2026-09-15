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
 * Hands the handler the body the fixups hook already consumed.
 *
 * Buckets move out of ctx->saved_body as they are delivered, so a handler
 * reading in chunks -- mod_cgid asks for HUGE_STRING_LEN at a time -- sees the
 * body once and in order, then the EOS that fixups appended.
 */
static apr_status_t
coraza_replay_saved_body(ap_filter_t *f, apr_bucket_brigade *bb,
                         ap_input_mode_t mode, apr_read_type_e block,
                         apr_off_t readbytes)
{
    coraza_request_ctx_t *ctx = f->ctx;
    apr_bucket_brigade *saved = ctx->saved_body;
    apr_bucket *stop;
    apr_status_t rv;

    /* Everything has been handed over: step aside and let the filter below
     * answer. Returning APR_EOF here instead would be read as a failure --
     * ap_discard_request_body() maps any non-APR_SUCCESS to 400, which turned
     * the 405 that a PUT to a static path should get into a 400. */
    if (APR_BRIGADE_EMPTY(saved)) {
        ctx->saved_body = NULL;
        ap_remove_input_filter(f);
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (mode == AP_MODE_EATCRLF) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    if (mode == AP_MODE_GETLINE) {
        return apr_brigade_split_line(bb, saved, block, HUGE_STRING_LEN);
    }

    if (mode == AP_MODE_SPECULATIVE) {
        apr_bucket *e;
        apr_off_t seen = 0;

        for (e = APR_BRIGADE_FIRST(saved);
             e != APR_BRIGADE_SENTINEL(saved) && seen < readbytes;
             e = APR_BUCKET_NEXT(e))
        {
            apr_bucket *copy;

            if (apr_bucket_copy(e, &copy) != APR_SUCCESS) {
                break;
            }
            APR_BRIGADE_INSERT_TAIL(bb, copy);
            if (!APR_BUCKET_IS_METADATA(e)) {
                seen += (apr_off_t)e->length;
            }
        }
        return APR_SUCCESS;
    }

    /* AP_MODE_READBYTES and AP_MODE_EXHAUSTIVE. */
    if (readbytes <= 0) {
        APR_BRIGADE_CONCAT(bb, saved);
        return APR_SUCCESS;
    }

    rv = apr_brigade_partition(saved, readbytes, &stop);
    if (rv == APR_INCOMPLETE) {
        /* Less left than asked for: hand over the remainder, EOS included. */
        APR_BRIGADE_CONCAT(bb, saved);
        return APR_SUCCESS;
    }
    if (rv != APR_SUCCESS) {
        return rv;
    }

    while (APR_BRIGADE_FIRST(saved) != stop) {
        apr_bucket *e = APR_BRIGADE_FIRST(saved);

        APR_BUCKET_REMOVE(e);
        APR_BRIGADE_INSERT_TAIL(bb, e);
    }

    return APR_SUCCESS;
}


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

    /* The fixups hook read the body with ap_get_client_block(), which consumes
     * the connection input. Replay the copy it kept, so the application behind
     * the WAF still receives the body the client sent. */
    if (ctx != NULL && ctx->saved_body != NULL && !ctx->intervention_triggered) {
        return coraza_replay_saved_body(f, bb, mode, block, readbytes);
    }

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
            if (coraza_process_failed(coraza_process_request_body(ctx->transaction))) {
                /* Engine error: fail closed rather than pass uninspected. */
                ctx->intervention_triggered = 1;
                ctx->phase2_done = 1;
                ap_remove_input_filter(f);
                return APR_EGENERAL;
            }

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
            /*
             * coraza_append_request_body takes an int length; guard the
             * apr_size_t -> int narrowing so a >INT_MAX bucket cannot wrap to a
             * bogus length and have the engine inspect the wrong span. Fail
             * closed.
             */
            if (len > INT_MAX) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                              "coraza: request body chunk too large to inspect");
                ctx->intervention_triggered = 1;
                ctx->phase2_done = 1;
                ap_remove_input_filter(f);
                return APR_EGENERAL;
            }

            if (CORAZA_CALL_FAILED(coraza_append_request_body(ctx->transaction,
                                       (unsigned char *)data, (int)len))) {
                ctx->intervention_triggered = 1;
                ctx->phase2_done = 1;
                ap_remove_input_filter(f);
                return APR_EGENERAL;
            }

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
