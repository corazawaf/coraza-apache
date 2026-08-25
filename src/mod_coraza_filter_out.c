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
 * A streaming response has no meaningful end-of-body: the origin emits events
 * indefinitely and never sends EOS, so the header delay (which flushes on EOS)
 * would hold the response headers forever and the client receives nothing.
 * Detect Server-Sent Events (Content-Type: text/event-stream) so the caller
 * can skip the delay.
 *
 * SECURITY TRADE-OFF: Content-Type is chosen by the upstream, so an origin that
 * emits text/event-stream opts this response out of response-body inspection.
 * Phases 1-3 are untouched, but phase 4 is SKIPPED for SSE: the caller removes
 * this filter before the body loop, so coraza_process_response_body() is not
 * called and the streamed body is not inspected. This is inherent -- a body
 * that never ends cannot be buffered or evaluated -- and is the same trade-off
 * 101 Switching Protocols already accepts. Streaming and full-response WAF
 * buffering are mutually exclusive by construction.
 *
 * The media-type match is strict: "text/event-streamx" and
 * "text/event-stream junk" do NOT qualify; only end-of-value or optional OWS
 * followed by ';' (a parameter list, RFC 9110 5.6.3) is accepted.
 */
static int
coraza_is_sse_response(request_rec *r)
{
    static const char sse[] = "text/event-stream";
    const apr_size_t sse_len = sizeof(sse) - 1;
    const char *ct = r->content_type;
    apr_size_t i, len;

    if (ct == NULL) {
        return 0;
    }
    len = strlen(ct);
    if (len < sse_len || strncasecmp(ct, sse, sse_len) != 0) {
        return 0;
    }
    for (i = sse_len; i < len; i++) {
        if (ct[i] == ' ' || ct[i] == '\t') {
            continue;
        }
        return ct[i] == ';';
    }
    return 1;  /* exact "text/event-stream" */
}

/*
 * Fail closed on a response-body engine error. If the headers are still delayed
 * nothing has been sent yet, so a clean 500 error page can be generated;
 * otherwise the headers are already on the wire and the response is truncated
 * with a reset. Either way the response is not passed through uninspected.
 */
static apr_status_t
coraza_fail_closed_response(ap_filter_t *f, request_rec *r,
                            coraza_request_ctx_t *ctx, apr_bucket_brigade *bb)
{
    ctx->intervention_triggered = 1;
    ap_remove_output_filter(f);
    r->status = HTTP_INTERNAL_SERVER_ERROR;

    if (ctx->headers_delayed) {
        ctx->headers_delayed = 0;
        apr_brigade_cleanup(ctx->pending_brigade);
        apr_brigade_cleanup(bb);
        ap_die(HTTP_INTERNAL_SERVER_ERROR, r);
        return AP_FILTER_ERROR;
    }

    apr_brigade_cleanup(bb);
    return APR_EGENERAL;
}

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

        /* Content-Type is stored in r->content_type, not in headers_out.
         * Apache's core output filter adds it when serializing the response,
         * but our filter runs before that, so we must add it explicitly. */
        if (r->content_type != NULL) {
            coraza_add_response_header(ctx->transaction,
                                       "Content-Type",
                                       (int)strlen("Content-Type"),
                                       (char *)r->content_type,
                                       (int)strlen(r->content_type));
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

        ctx->response_body_processable =
            coraza_is_response_body_processable(ctx->transaction);

        ret = coraza_process_intervention(ctx->transaction, r, 0);
        if (ret > 0) {
            /* Phase 3 intervention: no data sent yet, generate clean error */
            ctx->intervention_triggered = 1;
            ap_remove_output_filter(f);
            apr_brigade_cleanup(bb);
            r->status = ret;
            ap_die(ret, r);
            return AP_FILTER_ERROR;
        }

        /*
         * SSE / streaming responses: phases 1-3 are done. The body loop below
         * block-reads every bucket before forwarding the brigade, which drains
         * a streaming response pipe and holds it until EOS -- an SSE stream
         * never sends EOS, so the client would receive nothing. Step out of the
         * filter chain and let the response stream. Phase 4 cannot run on a body
         * that never ends anyway; this is the same trade-off 101 Switching
         * Protocols accepts (see coraza_is_sse_response).
         */
        if (coraza_is_sse_response(r)) {
            ap_remove_output_filter(f);
            return ap_pass_brigade(f->next, bb);
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

        /*
         * Bound worker memory while the header delay holds the response. The
         * loop reads (and thus buffers) every bucket before forwarding; a large
         * download or a long stream would otherwise be read into memory in full
         * before EOS. Once the buffered body passes the cap, stop delaying:
         * flush the buffered headers + everything read so far and let the rest
         * stream through uninspected. A later phase-4 match can then no longer
         * render a clean error page (headers are on the wire) -- the same
         * trade-off the SSE and 101 Switching Protocols paths accept.
         */
        if (ctx->headers_delayed && len > 0) {
            ctx->pending_len += len;
            if (ctx->pending_len > CORAZA_MAX_DELAYED_BODY) {
                ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
                              "coraza: delayed response body exceeded %"
                              APR_SIZE_T_FMT " bytes; flushing headers early",
                              (apr_size_t) CORAZA_MAX_DELAYED_BODY);
                ctx->headers_delayed = 0;
                /* Step out of the chain so the remainder truly streams through
                 * uninspected -- otherwise the body loop keeps inspecting later
                 * chunks and a post-flush intervention would drop an in-flight
                 * brigade, truncating a response the client is already reading. */
                ap_remove_output_filter(f);
                APR_BRIGADE_PREPEND(bb, ctx->pending_brigade);
                ctx->pending_brigade = NULL;
                return ap_pass_brigade(f->next, bb);
            }
        }

        if (len > 0 && ctx->response_body_processable) {
            /*
             * coraza_append_response_body takes an int length; guard the
             * apr_size_t -> int narrowing so a >INT_MAX bucket cannot wrap to a
             * bogus length and skip inspection. Fail closed.
             */
            if (len > INT_MAX) {
                ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                              "coraza: response body chunk too large to inspect");
                return coraza_fail_closed_response(f, r, ctx, bb);
            }

            if (CORAZA_CALL_FAILED(coraza_append_response_body(ctx->transaction,
                                        (unsigned char *)data, (int)len))) {
                /* Engine error: fail closed rather than stream uninspected. */
                return coraza_fail_closed_response(f, r, ctx, bb);
            }

            ret = coraza_process_intervention(ctx->transaction, r, 0);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                ap_remove_output_filter(f);
                if (ctx->headers_delayed) {
                    /* Nothing sent yet — generate clean error response */
                    ctx->headers_delayed = 0;
                    apr_brigade_cleanup(ctx->pending_brigade);
                    apr_brigade_cleanup(bb);
                    r->status = ret;
                    ap_die(ret, r);
                    return AP_FILTER_ERROR;
                }
                apr_brigade_cleanup(bb);
                r->status = ret;
                return APR_EGENERAL;
            }
        }
    }

    if (has_eos) {
        /* Process complete response body */
        if (CORAZA_CALL_FAILED(coraza_process_response_body(ctx->transaction))) {
            return coraza_fail_closed_response(f, r, ctx, bb);
        }

        ret = coraza_process_intervention(ctx->transaction, r, 0);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            ctx->phase4_done = 1;
            ap_remove_output_filter(f);
            if (ctx->headers_delayed) {
                /* Nothing sent yet — generate clean error response */
                ctx->headers_delayed = 0;
                apr_brigade_cleanup(ctx->pending_brigade);
                apr_brigade_cleanup(bb);
                r->status = ret;
                ap_die(ret, r);
                return AP_FILTER_ERROR;
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
        /* Accumulate into pending brigade during header delay. The total is
         * bounded by the per-bucket cap check in the phase-4 loop above. */
        APR_BRIGADE_CONCAT(ctx->pending_brigade, bb);
        return APR_SUCCESS;
    }

    return ap_pass_brigade(f->next, bb);
}
