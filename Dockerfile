## Stage 1: Build libcoraza
FROM --platform=$BUILDPLATFORM golang as go-builder

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
FROM httpd:2.4 as apache-build

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

# Create test page
RUN echo "Hello from Coraza-Apache" > /usr/local/apache2/htdocs/index.html

# Copy config
COPY coraza.conf /usr/local/apache2/conf/extra/coraza.conf
RUN echo "Include conf/extra/coraza.conf" >> /usr/local/apache2/conf/httpd.conf

# Install test dependencies and verify config
RUN apt-get update -qq && \
    apt-get install -qq --no-install-recommends curl && \
    httpd -t 2>&1 && \
    echo "Config syntax OK"

# Copy test script
COPY t/run_tests.sh /tmp/run_tests.sh
RUN chmod +x /tmp/run_tests.sh

CMD ["/tmp/run_tests.sh"]
