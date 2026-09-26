## Stage 1: Build libcoraza
FROM --platform=$BUILDPLATFORM golang AS go-builder

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -qq --no-install-recommends \
        autoconf \
        automake \
        libtool \
        gcc \
        bash \
        make

ARG LIBCORAZA_VERSION=v1.8.0

RUN set -eux; \
    wget https://github.com/corazawaf/libcoraza/tarball/${LIBCORAZA_VERSION} -O /tmp/libcoraza.tar.gz; \
    tar -xvf /tmp/libcoraza.tar.gz; \
    cd *-libcoraza-*; \
    ./build.sh; \
    ./configure; \
    make; \
    cp libcoraza.a /usr/local/lib/; \
    cp libcoraza.so /usr/local/lib/; \
    mkdir -p /usr/local/include/coraza; \
    cp coraza/coraza.h /usr/local/include/coraza/

## Stage 2: Build mod_coraza
FROM httpd:2.4 AS apache-build

COPY --from=go-builder /usr/local/include/coraza /usr/local/include/coraza
COPY --from=go-builder /usr/local/lib/libcoraza.a /usr/local/lib/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib/

RUN set -eux; \
    apt-get update -qq; \
    apt-get install -qq --no-install-recommends \
        gcc \
        libc-dev \
        make \
        libapr1-dev \
        libaprutil1-dev \
        apache2-dev

COPY . /usr/src/coraza-apache

RUN set -eux; \
    cd /usr/src/coraza-apache; \
    make; \
    cp src/.libs/mod_coraza.so /usr/local/apache2/modules/

## Stage 3: Runtime
FROM httpd:2.4

COPY --from=apache-build /usr/local/apache2/modules/mod_coraza.so /usr/local/apache2/modules/
COPY --from=go-builder /usr/local/lib/libcoraza.so /usr/local/lib/

RUN ldconfig -v

# Switch MPM if requested (default: event)
ARG MPM=event
RUN set -eux; \
    if [ "$MPM" != "event" ]; then \
      sed -i \
        -e 's/^LoadModule mpm_event_module/#LoadModule mpm_event_module/' \
        -e "s/^#LoadModule mpm_${MPM}_module/LoadModule mpm_${MPM}_module/" \
        /usr/local/apache2/conf/httpd.conf; \
    fi

# Download OWASP CRS v4
RUN apt-get update -qq && \
    apt-get install -qq --no-install-recommends curl ca-certificates && \
    mkdir -p /etc/coraza/crs && \
    CRS_VERSION="4.23.0" && \
    curl -fSL "https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz" \
      -o /tmp/crs.tar.gz && \
    tar -xzf /tmp/crs.tar.gz -C /tmp && \
    cp /tmp/coreruleset-${CRS_VERSION}/crs-setup.conf.example /etc/coraza/crs/ && \
    cp -r /tmp/coreruleset-${CRS_VERSION}/rules /etc/coraza/crs/ && \
    rm -rf /tmp/crs.tar.gz /tmp/coreruleset-*

# Create log directory and web root
RUN mkdir -p /var/log/coraza && \
    touch /var/log/coraza/audit.log && \
    chmod 777 /var/log/coraza && \
    chmod 666 /var/log/coraza/audit.log && \
    mkdir -p /var/log/coraza/debug && \
    chmod 777 /var/log/coraza/debug && \
    mkdir -p /var/log/coraza/audit && \
    chmod 777 /var/log/coraza/audit && \
    echo "OK" > /usr/local/apache2/htdocs/index.html && \
    echo "CORAZA_CUSTOM_ERROR_PAGE" > /usr/local/apache2/htdocs/custom-error.html && \
    # Test directories for <Directory> and .htaccess tests
    mkdir -p /usr/local/apache2/htdocs/dir-protected && \
    echo "OK" > /usr/local/apache2/htdocs/dir-protected/index.html && \
    mkdir -p /usr/local/apache2/htdocs/dir-disabled && \
    echo "OK" > /usr/local/apache2/htdocs/dir-disabled/index.html && \
    mkdir -p /usr/local/apache2/htdocs/htaccess-protected && \
    echo "OK" > /usr/local/apache2/htdocs/htaccess-protected/index.html && \
    printf 'SecRule ARGS:block "@streq yes" "id:10002,phase:1,deny,status:403"\n' \
        > /usr/local/apache2/htdocs/htaccess-protected/.htaccess && \
    mkdir -p /usr/local/apache2/htdocs/htaccess-disabled && \
    echo "OK" > /usr/local/apache2/htdocs/htaccess-disabled/index.html && \
    printf 'Coraza Off\n' \
        > /usr/local/apache2/htdocs/htaccess-disabled/.htaccess && \
    # Two .htaccess policies whose rule text collides under the WAF cache's
    # DJB2 hash (h = h*33 + c: "xb" and "yA" hash alike, same length, same
    # rule count) but differ in behaviour. The cache must tell them apart
    # (issue #43).
    mkdir -p /usr/local/apache2/htdocs/htaccess-collide-a && \
    echo "OK" > /usr/local/apache2/htdocs/htaccess-collide-a/index.html && \
    printf 'SecRule ARGS:xb "@streq 1" "id:10003,phase:1,deny,status:403"\n' \
        > /usr/local/apache2/htdocs/htaccess-collide-a/.htaccess && \
    mkdir -p /usr/local/apache2/htdocs/htaccess-collide-b && \
    echo "OK" > /usr/local/apache2/htdocs/htaccess-collide-b/index.html && \
    printf 'SecRule ARGS:yA "@streq 1" "id:10003,phase:1,deny,status:403"\n' \
        > /usr/local/apache2/htdocs/htaccess-collide-b/.htaccess

# Copy WAF rules config
COPY coraza-waf.conf /etc/coraza/coraza-waf.conf

# SSE test endpoint (streaming CGI) for the header-delay skip test
COPY tests/cgi-bin/sse /usr/local/apache2/cgi-bin/sse
RUN chmod +x /usr/local/apache2/cgi-bin/sse
COPY tests/cgi-bin/bulk /usr/local/apache2/cgi-bin/bulk
RUN chmod +x /usr/local/apache2/cgi-bin/bulk
COPY tests/cgi-bin/echo /usr/local/apache2/cgi-bin/echo
RUN chmod +x /usr/local/apache2/cgi-bin/echo
COPY tests/cgi-bin/stream-json /usr/local/apache2/cgi-bin/stream-json
RUN chmod +x /usr/local/apache2/cgi-bin/stream-json

# Apache config: load module, enable coraza with CRS, FallbackResource for test URLs
RUN { \
    echo 'LoadModule coraza_module modules/mod_coraza.so'; \
    echo 'LoadModule info_module modules/mod_info.so'; \
    if [ "$MPM" = "prefork" ]; then \
      echo 'LoadModule cgi_module modules/mod_cgi.so'; \
    else \
      echo 'LoadModule cgid_module modules/mod_cgid.so'; \
    fi; \
    echo 'Coraza On'; \
    echo 'CorazaRulesFile /etc/coraza/coraza-waf.conf'; \
    echo 'FallbackResource /index.html'; \
    echo '<Location "/server-info">'; \
    echo '    SetHandler server-info'; \
    echo '    Coraza Off'; \
    echo '    Require all granted'; \
    echo '</Location>'; \
    echo '# Enable .htaccess processing'; \
    echo '<Directory "/usr/local/apache2/htdocs">'; \
    echo '    AllowOverride All'; \
    echo '</Directory>'; \
    echo '# Directory-based custom rule'; \
    echo '<Directory "/usr/local/apache2/htdocs/dir-protected">'; \
    echo '    SecRule ARGS:block "@streq yes" "id:10001,phase:1,deny,status:403"'; \
    echo '</Directory>'; \
    echo '# Directory-based WAF disable'; \
    echo '<Directory "/usr/local/apache2/htdocs/dir-disabled">'; \
    echo '    Coraza Off'; \
    echo '</Directory>'; \
    echo 'ErrorDocument 403 /custom-error.html'; \
    echo 'ErrorDocument 401 /custom-error.html'; \
    echo '# The error page is inspected like any other response. The phase-4'; \
    echo '# rule below matches its own body: it must fire on a direct request, and'; \
    echo '# must NOT fire when the page is served for a request this transaction'; \
    echo '# already denied (issue #40).'; \
    echo '<Location "/custom-error.html">'; \
    echo '    Coraza On'; \
    echo '    SecRule RESPONSE_BODY "@contains CORAZA_CUSTOM_ERROR_PAGE" "id:20999,phase:4,deny,status:500,log"'; \
    echo '</Location>'; \
    echo '# --- Non-403 status codes ---'; \
    echo '<Location "/deny-401">'; \
    echo '    SecRule ARGS:action "@streq block" "id:20401,phase:1,deny,status:401,log"'; \
    echo '</Location>'; \
    echo '# --- Location rule isolation ---'; \
    echo '<Location "/isolated-a">'; \
    echo '    SecRule ARGS:trigger "@streq a" "id:20501,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/isolated-b">'; \
    echo '    SecRule ARGS:trigger "@streq b" "id:20502,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- Custom error page testing ---'; \
    echo '<Location "/errorpage-test">'; \
    echo '    SecRule ARGS:action "@streq block" "id:20601,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/errorpage-401">'; \
    echo '    SecRule ARGS:action "@streq block" "id:20602,phase:1,deny,status:401,log"'; \
    echo '</Location>'; \
    echo '# --- Redirect tests ---'; \
    echo '<Location "/redirect-302">'; \
    echo '    SecRule ARGS:target "@streq redirect" "id:20701,phase:1,status:302,log,redirect:http://www.coraza.io"'; \
    echo '</Location>'; \
    echo '<Location "/redirect-301">'; \
    echo '    SecRule ARGS:target "@streq redirect" "id:20702,phase:1,status:301,log,redirect:http://www.coraza.io"'; \
    echo '</Location>'; \
    echo '# Clean path+query target: sanitizer must pass it byte-for-byte (no over-truncation)'; \
    echo '<Location "/redirect-clean-path">'; \
    echo '    SecRule ARGS:target "@streq redirect" "id:20703,phase:1,status:302,log,redirect:http://example.org/clean/path?a=b"'; \
    echo '</Location>'; \
    echo '# --- Per-phase testing ---'; \
    echo '<Location "/phase1">'; \
    echo '    SecRule ARGS:action "@streq block403" "id:20001,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/phase2">'; \
    echo '    SecRule REQUEST_BODY "@contains PHASE2ATTACK" "id:20002,phase:2,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- Request protocol (slash-delimited REQUEST_PROTOCOL) ---'; \
    echo '<Location "/protocol-check">'; \
    echo '    SecRule REQUEST_PROTOCOL "@streq HTTP/1.1" "id:20800,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# A version Apache does not know must reach REQUEST_PROTOCOL as sent, not'; \
    echo '# collapsed to HTTP/1.1. Phase-1 deny with a status CRS never uses, so a 406'; \
    echo '# can only come from this rule seeing the raw token.'; \
    echo '<Location "/protocol-raw">'; \
    echo '    SecRule REQUEST_PROTOCOL "@streq HTTP/4.0" "id:20801,phase:1,deny,status:406,log"'; \
    echo '</Location>'; \
    echo '# --- Large header inspection (cgo length-narrowing guard must not clip) ---'; \
    echo '<Location "/header-check">'; \
    echo '    SecRule REQUEST_HEADERS:X-Test "@contains BOOMHEADER" "id:20810,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- SSE streaming: header delay must be skipped (never sends EOS) ---'; \
    echo 'ScriptAlias "/sse-stream" "/usr/local/apache2/cgi-bin/sse"'; \
    echo 'ScriptAlias "/sse-nearmiss" "/usr/local/apache2/cgi-bin/sse"'; \
    echo 'ScriptAlias "/bulk-delayed" "/usr/local/apache2/cgi-bin/bulk"'; \
    echo 'ScriptAlias "/echo" "/usr/local/apache2/cgi-bin/echo"'; \
    echo 'ScriptAlias "/echo-bodyoff" "/usr/local/apache2/cgi-bin/echo"'; \
    echo 'ScriptAlias "/echo-bodyon" "/usr/local/apache2/cgi-bin/echo"'; \
    echo 'ScriptAlias "/stream-json-off" "/usr/local/apache2/cgi-bin/stream-json"'; \
    echo 'ScriptAlias "/stream-json-mime" "/usr/local/apache2/cgi-bin/stream-json"'; \
    echo 'ScriptAlias "/stream-json-on" "/usr/local/apache2/cgi-bin/stream-json"'; \
    echo '<Directory "/usr/local/apache2/cgi-bin">'; \
    echo '    Require all granted'; \
    echo '    Options +ExecCGI'; \
    echo '</Directory>'; \
    echo '# Request-body replay: spool from 64 KiB on the echo endpoint so the'; \
    echo '# 300 KB upload test exercises the directive, its per-Location override'; \
    echo '# and the spool path (default is 128 KiB).'; \
    echo '<Location "/echo">'; \
    echo '    CorazaRequestBodyInMemoryLimit 65536'; \
    echo '</Location>'; \
    echo '# --- SecRequestBodyAccess Off: body not submitted to the engine (issue #44) ---'; \
    echo '# The body-matching phase-2 rule must not fire (the engine never sees the'; \
    echo '# bytes), the header-matching phase-2 rule must, and the CGI must still'; \
    echo '# receive the whole body. /echo-bodyon carries the same rules with access'; \
    echo '# on, as the control that the body rule itself works.'; \
    echo '<Location "/echo-bodyoff">'; \
    echo '    SecRequestBodyAccess Off'; \
    echo '    SecRule REQUEST_BODY "@contains BODYOFFATTACK" "id:20020,phase:2,deny,status:403,log"'; \
    echo '    SecRule REQUEST_HEADERS:X-Phase2 "@streq attack" "id:20021,phase:2,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/echo-bodyon">'; \
    echo '    SecRequestBodyAccess On'; \
    echo '    SecRule REQUEST_BODY "@contains BODYOFFATTACK" "id:20022,phase:2,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/sse-stream">'; \
    echo '    SetEnv SSE_CT "text/event-stream"'; \
    echo '    SecRule ARGS:attack "@streq 1" "id:20810,phase:1,deny,status:403,log"'; \
    echo '    # text/event-stream is not in SecResponseBodyMimeType, so the body is'; \
    echo '    # not inspected; phase 4 must still run on non-body variables and'; \
    echo '    # deny cleanly before the stream starts (issue #60 review).'; \
    echo '    SecRule ARGS:attack4 "@streq 1" "id:20812,phase:4,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# The near-miss must be INSPECTED for its delay to mean anything: an'; \
    echo '# uninspected type streams by design (issue #60), so list it.'; \
    echo '<Location "/sse-nearmiss">'; \
    echo '    SetEnv SSE_CT "text/event-streamx"'; \
    echo '    SecResponseBodyMimeType text/event-streamx'; \
    echo '</Location>'; \
    echo '# The delayed-body cap only applies while a body is inspected; the bulk'; \
    echo '# CGI sends application/octet-stream, so list it for the cap tests.'; \
    echo '<Location "/bulk-delayed">'; \
    echo '    SecResponseBodyMimeType application/octet-stream'; \
    echo '</Location>'; \
    echo '# --- Header delay only when the body will be inspected (issue #60) ---'; \
    echo '# Body access off: the stream must reach the client at once, and a'; \
    echo '# phase-4 rule on a non-body variable must still deny cleanly.'; \
    echo '# Body access off: not inspected, must stream (libcoraza >= 1.8 exports'; \
    echo '# the predicate that makes the Off visible; 1.8 is the module floor).'; \
    echo '<Location "/stream-json-off">'; \
    echo '    SecResponseBodyAccess Off'; \
    echo '</Location>'; \
    echo '# Content-Type outside SecResponseBodyMimeType: not inspected on any'; \
    echo '# libcoraza. A phase-4 rule on a non-body variable must still deny.'; \
    echo '<Location "/stream-json-mime">'; \
    echo '    SecResponseBodyAccess On'; \
    echo '    SecResponseBodyMimeType text/html'; \
    echo '    SecRule ARGS:attack "@streq 1" "id:20811,phase:4,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# Inspected (application/json is in the default MIME list): the delay'; \
    echo '# is the intended behaviour, so this one must still be held until EOS.'; \
    echo '<Location "/stream-json-on">'; \
    echo '    SecResponseBodyAccess On'; \
    echo '</Location>'; \
    echo '# --- Config merging ---'; \
    echo '<Location "/merge-engine-off">'; \
    echo '    SecRuleEngine Off'; \
    echo '</Location>'; \
    echo '<Location "/merge-bodyaccess-off">'; \
    echo '    SecRequestBodyAccess Off'; \
    echo '</Location>'; \
    echo '<Location "/merge-inherited">'; \
    echo '    SecRule ARGS:localonly "@streq yes" "id:20010,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- Request body limits ---'; \
    echo '<Location "/bodylimit-reject">'; \
    echo '    SecRequestBodyLimit 128'; \
    echo '    SecRequestBodyLimitAction Reject'; \
    echo '</Location>'; \
    echo '<Location "/bodylimit-partial">'; \
    echo '    SecRequestBodyLimit 128'; \
    echo '    SecRequestBodyLimitAction ProcessPartial'; \
    echo '</Location>'; \
    echo '# --- Inherited body limit with location override ---'; \
    echo '<Location "/bodylimit-inherited">'; \
    echo '    SecRequestBodyLimit 128'; \
    echo '    SecRequestBodyLimitAction Reject'; \
    echo '</Location>'; \
    echo '<Location "/bodylimit-override">'; \
    echo '    SecRequestBodyLimit 512'; \
    echo '    SecRequestBodyLimitAction Reject'; \
    echo '</Location>'; \
    echo '# --- Scoring ---'; \
    echo '<Location "/scoring-absolute">'; \
    echo '    SecRule ARGS "@streq badarg1" "id:20101,phase:2,pass,setvar:tx.score=1"'; \
    echo '    SecRule ARGS "@streq badarg2" "id:20102,phase:2,pass,setvar:tx.score=2"'; \
    echo '    SecRule TX:SCORE "@ge 2" "id:20199,phase:2,deny,log,status:403"'; \
    echo '</Location>'; \
    echo '<Location "/scoring-iterative">'; \
    echo '    SecRule ARGS "@streq badarg1" "id:20201,phase:2,pass,setvar:tx.score=+1"'; \
    echo '    SecRule ARGS "@streq badarg2" "id:20202,phase:2,pass,setvar:tx.score=+1"'; \
    echo '    SecRule ARGS "@streq badarg3" "id:20203,phase:2,pass,setvar:tx.score=+1"'; \
    echo '    SecRule TX:SCORE "@ge 3" "id:20299,phase:2,deny,log,status:403"'; \
    echo '</Location>'; \
    echo '# --- Debug log per-location isolation ---'; \
    echo '<Location "/debuglog-root">'; \
    echo '    SecDebugLog /var/log/coraza/debug/root.log'; \
    echo '    SecDebugLogLevel 9'; \
    echo '    SecRule ARGS:what "@streq root" "id:30001,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/debuglog-sub1">'; \
    echo '    SecDebugLog /var/log/coraza/debug/sub1.log'; \
    echo '    SecDebugLogLevel 9'; \
    echo '    SecRule ARGS:what "@streq sub1" "id:30002,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/debuglog-sub2">'; \
    echo '    SecDebugLog /var/log/coraza/debug/sub2.log'; \
    echo '    SecDebugLogLevel 9'; \
    echo '    SecRule ARGS:what "@streq sub2" "id:30003,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '# --- Per-location audit log isolation ---'; \
    echo '<Location "/auditlog-root">'; \
    echo '    SecAuditEngine On'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/root.log'; \
    echo '    SecRule ARGS:what "@streq root" "id:31001,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/auditlog-sub1">'; \
    echo '    SecAuditEngine On'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/sub1.log'; \
    echo '    SecRule ARGS:what "@streq sub1" "id:31002,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/auditlog-sub1/sub2">'; \
    echo '    SecAuditEngine On'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/sub2.log'; \
    echo '    SecRule ARGS:what "@streq sub2" "id:31003,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/auditlog-sub3">'; \
    echo '    SecAuditEngine On'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/sub3.log'; \
    echo '    SecRule ARGS:what "@streq sub3" "id:31004,phase:1,pass,log"'; \
    echo '</Location>'; \
    echo '<Location "/auditlog-sub3/sub4">'; \
    echo '    SecAuditEngine On'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecResponseBodyAccess On'; \
    echo '    SecAuditLog /var/log/coraza/audit/sub4.log'; \
    echo '    SecRule ARGS:what "@streq sub4" "id:31005,phase:1,pass,log"'; \
    echo '    SecRule ARGS:what "@streq sub4withE" "id:31006,phase:1,pass,log,ctl:auditLogParts=+E"'; \
    echo '</Location>'; \
    echo '# --- auditlog action with RelevantOnly ---'; \
    echo '<Location "/auditlog-relevant">'; \
    echo '    SecAuditEngine RelevantOnly'; \
    echo '    SecAuditLogRelevantStatus "^(?:5|4[0-9][0-35-9])"'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/relevant.log'; \
    echo '    SecRule ARGS:trigger "@streq yes" "id:31010,phase:1,deny,status:403,auditlog"'; \
    echo '</Location>'; \
    echo '<Location "/auditlog-relevant-nolog">'; \
    echo '    SecAuditEngine RelevantOnly'; \
    echo '    SecAuditLogRelevantStatus "^(?:5|4[0-9][0-35-9])"'; \
    echo '    SecAuditLogParts ABHZ'; \
    echo '    SecAuditLogType Serial'; \
    echo '    SecAuditLog /var/log/coraza/audit/relevant-nolog.log'; \
    echo '    SecRule ARGS:trigger "@streq yes" "id:31011,phase:1,pass,noauditlog"'; \
    echo '</Location>'; \
    echo '# --- Response phase testing (phases 3+4) ---'; \
    echo '<Location "/phase3">'; \
    echo '    SecRule RESPONSE_HEADERS:Content-Type "@contains text/html" "id:20003,phase:3,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/phase3-pass">'; \
    echo '    SecRule RESPONSE_HEADERS:X-No-Such "@streq yes" "id:20005,phase:3,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/phase4">'; \
    echo '    SecResponseBodyAccess On'; \
    echo '    SecResponseBodyMimeType text/html text/plain'; \
    echo '    SecRule RESPONSE_BODY "@contains OK" "id:20004,phase:4,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/phase4-pass">'; \
    echo '    SecResponseBodyAccess On'; \
    echo '    SecResponseBodyMimeType text/html text/plain'; \
    echo '    SecRule RESPONSE_BODY "@contains NOTINRESPONSE" "id:20006,phase:4,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- Transaction ID ---'; \
    echo '<Location "/txid-test">'; \
    echo '    CorazaTransactionId "TESTID-APACHE-001"'; \
    echo '    SecRule ARGS:action "@streq block" "id:20301,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '# --- VirtualHost isolation ---'; \
    echo '# Default VHost for localhost — inherits server-level config'; \
    echo '<VirtualHost *:80>'; \
    echo '    ServerName localhost'; \
    echo '</VirtualHost>'; \
    echo '# --- Bulk response-header submission (issue #46): headers_out and'; \
    echo '# err_headers_out both reach the engine in the packed set. "Header set"'; \
    echo '# lands in headers_out, "Header always set" in err_headers_out. They are'; \
    echo '# "early" and at VirtualHost level: the normal mod_headers filter runs'; \
    echo '# after CORAZA_OUT (both AP_FTYPE_CONTENT_SET, ours inserted first), so'; \
    echo '# a late-set header is invisible to phase 3 -- a filter-order limitation,'; \
    echo '# not what is tested -- and early mode runs in post_read_request, before'; \
    echo '# <Location> sections are merged, so only server/vhost scope applies.'; \
    echo '<VirtualHost *:80>'; \
    echo '    ServerName resp-headers.test'; \
    echo '    DocumentRoot "/usr/local/apache2/htdocs"'; \
    echo '    Coraza On'; \
    echo '    Alias "/out" "/usr/local/apache2/htdocs/index.html"'; \
    echo '    Alias "/err" "/usr/local/apache2/htdocs/index.html"'; \
    echo '    Header set X-Marker "BOOMRESP" early'; \
    echo '    Header always set X-Err "BOOMERR" early'; \
    echo '    <Location "/out">'; \
    echo '        SecRule RESPONSE_HEADERS:X-Marker "@contains BOOMRESP" "id:20830,phase:3,deny,status:403,log"'; \
    echo '    </Location>'; \
    echo '    <Location "/err">'; \
    echo '        SecRule RESPONSE_HEADERS:X-Err "@contains BOOMERR" "id:20831,phase:3,deny,status:403,log"'; \
    echo '    </Location>'; \
    echo '</VirtualHost>'; \
    echo '<VirtualHost *:80>'; \
    echo '    ServerName vhost-off.test'; \
    echo '    DocumentRoot "/usr/local/apache2/htdocs"'; \
    echo '    Coraza Off'; \
    echo '</VirtualHost>'; \
    echo '<VirtualHost *:80>'; \
    echo '    ServerName vhost-custom.test'; \
    echo '    DocumentRoot "/usr/local/apache2/htdocs"'; \
    echo '    Coraza On'; \
    echo '    SecRule ARGS:vhaction "@streq block" "id:40001,phase:1,deny,status:403,log"'; \
    echo '</VirtualHost>'; \
    } > /usr/local/apache2/conf/extra/coraza.conf && \
    echo "Include conf/extra/coraza.conf" >> /usr/local/apache2/conf/httpd.conf

# Verify config
RUN httpd -t 2>&1 && echo "Config syntax OK"

EXPOSE 80

CMD ["httpd-foreground"]
