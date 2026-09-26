/*
 * Coraza connector for Apache HTTPD -- Phase 2 (Request Body)
 *
 * Input filter: replays to the handler the request body the fixups hook
 * consumed while inspecting it (issue #34). It never talks to the engine:
 * phase 2 is complete before any handler can read.
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
        /* Copy without consuming, and never more than asked for: partition
         * first, as the core input filter does, since a saved bucket can be
         * larger than readbytes. */
        apr_bucket *e;

        stop = APR_BRIGADE_SENTINEL(saved);
        if (readbytes > 0) {
            rv = apr_brigade_partition(saved, readbytes, &stop);
            if (rv != APR_SUCCESS && rv != APR_INCOMPLETE) {
                return rv;
            }
        }
        for (e = APR_BRIGADE_FIRST(saved); e != stop; e = APR_BUCKET_NEXT(e)) {
            apr_bucket *copy;

            rv = apr_bucket_copy(e, &copy);
            if (rv != APR_SUCCESS) {
                return rv;
            }
            APR_BRIGADE_INSERT_TAIL(bb, copy);
        }
        return APR_SUCCESS;
    }

    /* AP_MODE_EXHAUSTIVE reads until nothing is left and ignores readbytes;
     * AP_MODE_READBYTES with no limit is the same request. */
    if (mode == AP_MODE_EXHAUSTIVE || readbytes <= 0) {
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
 * Input filter. Only ever inserted by the fixups hook, right after it has read
 * the whole body and stored the copy in ctx->saved_body, so by the time a
 * handler reads, phase 2 has run. Replay the copy; once it is exhausted (or if
 * the request was denied) step out of the chain. The pre-#35 "inspect the body
 * as the handler reads it" path that used to follow was unreachable and is
 * gone (issue #47).
 */
apr_status_t
coraza_input_filter(ap_filter_t *f, apr_bucket_brigade *bb,
                    ap_input_mode_t mode, apr_read_type_e block,
                    apr_off_t readbytes)
{
    coraza_request_ctx_t *ctx = f->ctx;

    if (ctx != NULL && ctx->saved_body != NULL && !ctx->intervention_triggered) {
        return coraza_replay_saved_body(f, bb, mode, block, readbytes);
    }

    ap_remove_input_filter(f);
    return ap_get_brigade(f->next, bb, mode, block, readbytes);
}
