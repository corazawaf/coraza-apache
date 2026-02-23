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

ARG libcoraza_repo=ppomes/libcoraza
ARG libcoraza_branch=feat/implement-missing-apis

RUN set -eux; \
    wget https://github.com/${libcoraza_repo}/tarball/${libcoraza_branch} -O /tmp/master; \
    tar -xvf /tmp/master; \
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
    echo "OK" > /usr/local/apache2/htdocs/index.html

# Copy WAF rules config
COPY t/coraza-waf.conf /etc/coraza/coraza-waf.conf

# Apache config: load module, enable coraza with CRS, FallbackResource for test URLs
RUN { \
    echo 'LoadModule coraza_module modules/mod_coraza.so'; \
    echo 'Coraza On'; \
    echo 'CorazaRulesFile /etc/coraza/coraza-waf.conf'; \
    echo 'FallbackResource /index.html'; \
    } > /usr/local/apache2/conf/extra/coraza.conf && \
    echo "Include conf/extra/coraza.conf" >> /usr/local/apache2/conf/httpd.conf

# Verify config
RUN httpd -t 2>&1 && echo "Config syntax OK"

EXPOSE 80

CMD ["httpd-foreground"]
