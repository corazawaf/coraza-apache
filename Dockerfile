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

ARG LIBCORAZA_VERSION=v1.0.0

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
        > /usr/local/apache2/htdocs/htaccess-disabled/.htaccess

# Copy WAF rules config
COPY coraza-waf.conf /etc/coraza/coraza-waf.conf

# Apache config: load module, enable coraza with CRS, FallbackResource for test URLs
RUN { \
    echo 'LoadModule coraza_module modules/mod_coraza.so'; \
    echo 'LoadModule info_module modules/mod_info.so'; \
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
    echo '<Location "/custom-error.html">'; \
    echo '    Coraza Off'; \
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
    echo '# --- Per-phase testing ---'; \
    echo '<Location "/phase1">'; \
    echo '    SecRule ARGS:action "@streq block403" "id:20001,phase:1,deny,status:403,log"'; \
    echo '</Location>'; \
    echo '<Location "/phase2">'; \
    echo '    SecRule REQUEST_BODY "@contains PHASE2ATTACK" "id:20002,phase:2,deny,status:403,log"'; \
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
