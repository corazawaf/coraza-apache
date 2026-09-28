# Coraza Apache Connector

**Experimental** -- not production ready.

Apache HTTPD module for the Coraza WAF engine, using libcoraza (C bindings).

Same dependency chain as coraza-nginx: coraza (Go) -> libcoraza (C bindings) -> this module.

## Install from PPA (Ubuntu)

Prebuilt packages are available from a Launchpad PPA:
https://launchpad.net/~pierrepomes/+archive/ubuntu/coraza-apache

```shell
sudo add-apt-repository ppa:pierrepomes/coraza-apache
sudo apt update
sudo apt install libapache2-mod-coraza
```

This pulls in libcoraza automatically. Built for Ubuntu 22.04 (jammy), 24.04 (noble), 26.04 (resolute) and 26.10 (stonking).

## Build

Requires libcoraza >= 1.8 for both the headers at compile time and the shared
library at runtime -- the module gates on `coraza_version_num()` at startup and
refuses to load against an older runtime library.
The module is not linked against libcoraza -- it loads it via dlopen()
after fork to avoid Go runtime deadlocks.

```
make
make install
```

Or with a custom apxs path:

```
make APXS=/path/to/apxs
```

## Docker

Builds everything from source (libcoraza + module):

```
docker build --no-cache -t coraza-apache-test .
docker run --rm -d --name coraza-apache-test -p 8888:80 coraza-apache-test
./test.sh http://localhost:8888 --mpm=event --container=coraza-apache-test
docker stop coraza-apache-test
```

To test with a specific MPM (default is event):

```
docker build --no-cache --build-arg MPM=prefork -t coraza-test-prefork .
docker run --rm -d --name coraza-test-prefork -p 8889:80 coraza-test-prefork
./test.sh http://localhost:8889 --mpm=prefork --container=coraza-test-prefork
docker stop coraza-test-prefork
```

## Testing

`test.sh` runs the integration suite against a running server; [TESTS.md](TESTS.md)
describes every section. The `--mpm` flag verifies the server runs the expected
MPM via the `server-info` endpoint. `--container=NAME` lets the suite look
inside the container: audit and debug log checks, config validation with
`httpd -t`, a graceful restart over in-flight requests, and a crash sweep after
every section. Without it about a third of the checks are skipped.

To run the same suite with the module built under AddressSanitizer and
UndefinedBehaviorSanitizer:

```
docker build --no-cache --build-arg SANITIZE=1 -t coraza-apache-asan .
docker run --rm -d --name coraza-apache-asan -p 8888:80 coraza-apache-asan
./test.sh http://localhost:8888 --mpm=event --container=coraza-apache-asan
```

The image preloads the sanitizer runtime into httpd, and any sanitizer report
in the log fails the suite. CI runs this on every pull request (`A/UBSan`
workflow). Outside Docker, `make SANITIZE=1` builds the instrumented module.

## Configuration example

All standard modsecurity `Sec*` directives are registered natively, so existing
modsecurity configs (including CRS) can be used directly via Apache's `Include`:

```apache
LoadModule coraza_module modules/mod_coraza.so

Coraza On
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off

# OWASP CRS — use CorazaRulesFile so that relative data file paths
# (e.g. @pmFromFile scanners-user-agents.data) resolve correctly
CorazaRulesFile /etc/coraza/coraza-waf.conf

# Custom exclusions for a specific path
<Location /api/upload>
    SecRuleRemoveById 920420
    SecRequestBodyLimit 52428800
</Location>

# Disable inspection entirely for health checks
<Location /health>
    Coraza Off
</Location>

# Directory-based custom rule
<Directory /var/www/uploads>
    SecRule FILES_NAMES "\.php$" "id:10001,phase:2,deny,status:403"
</Directory>

# Disable via .htaccess (requires AllowOverride All)
# In .htaccess: Coraza Off
```

### Directives

**Sec\*** -- all standard modsecurity directives (`SecRuleEngine`, `SecRule`,
`SecAction`, `SecRequestBodyAccess`, `SecAuditEngine`, etc.) are registered
natively and can be used directly in Apache config files. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

**Coraza** On|Off -- enable or disable the module. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

**CorazaRules** "..." -- inline rule or directive. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

**CorazaRulesFile** /path -- load rules from file. Use this for CRS and other rule
files that reference relative data file paths. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

**CorazaTransactionId** "..." -- custom transaction ID. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

Rules defined at server level are inherited by `<VirtualHost>`, `<Location>`, `<Directory>`, and `.htaccess`.
Setting `Coraza Off` in any context disables inspection for that scope.
`Coraza On` requires at least one rule directive (`CorazaRules`, `CorazaRulesFile`
or a `Sec*` directive) somewhere in the server configuration: a configuration
that enables the module without any rules is rejected at startup rather than
run an empty WAF. Rules that live only in `.htaccess` files are not visible at
that point.

`SecRemoteRules` is rejected at configuration time: the Coraza engine does not
implement it, so it would otherwise pass `httpd -t` and then make every child
process fail to start. Rules must come from local files or inline text. The
native directive, `CorazaRules` text and the content of each `CorazaRulesFile`
are checked (backslash continuations and backtick action lists are followed
the way Coraza's parser does); rules files are scanned at their top level only
(`Include`d files are not followed). A relative `CorazaRulesFile` path is
resolved against `ServerRoot`.

**CorazaRequestBodyInMemoryLimit** bytes -- how much of a request body is kept
in memory for replay to the handler before the remainder is spooled to a temp
file (default 131072, 128 KiB). The module reads the whole body up front so the
WAF can inspect it before the handler runs, then replays it; this bounds what
that copy pins in worker memory. Disk use by the spool files is bounded per
request by Apache's `LimitRequestBody` (1 GiB by default) and in aggregate by
that times `MaxRequestWorkers` -- size `LimitRequestBody` accordingly, as for
any module that spools request bodies. Separate from the engine's
`SecRequestBodyInMemoryLimit`. Context: server config, `<VirtualHost>`, `<Location>`, `<Directory>`, `.htaccess`.

## How it works

The module hooks into Apache's request processing:

- **Phase 1** (fixups hook): connection info, URI, request headers
- **Phase 2** (fixups hook): request body -- read in full before the handler
  runs, then replayed to the handler (or to `mod_proxy`) by the `CORAZA_IN`
  input filter. Under `SecRequestBodyAccess Off` the body is still read and
  replayed but not handed to the engine; phase-2 rules on headers and URI
  still run.
- **Phase 3-4** (output filter): response headers and body, with header delay
  while the body is inspected. When it will not be (`SecResponseBodyAccess Off`,
  or a Content-Type outside `SecResponseBodyMimeType`) phase 4 is finalised
  before the headers are sent and the response streams; a deny there still
  gets a clean error page.
- **Phase 5** (log_transaction hook): audit logging

An internal redirect (`ErrorDocument`, `FallbackResource`, `DirectoryIndex`,
`mod_rewrite`) creates a new `request_rec` for the same client request. The
module reuses the transaction of the request the client sent: phases 1-2 are
not repeated, phases 3-4 inspect the response actually served, and there is one
audit entry. An error page served because that transaction denied the request
is passed through as-is rather than inspected and possibly denied again.

Reverse-proxied traffic (`mod_proxy_http`) is inspected like local traffic:
the upstream's response headers reach phase 3 and the proxied body phase 4.
HTTP/2 is covered too (tested over h2c with `mod_http2`, event MPM).

Rules are collected as strings during config parsing (master process)
and replayed in each child process after dlopen. This is required because
the Go runtime inside libcoraza cannot be loaded before fork.

## Limitations

- Response headers that `mod_headers` sets in its normal mode (`Header set`)
  are not visible to phase-3 rules: its output filter runs after the module's.
  Headers set by the handler, by an upstream through `mod_proxy`, or with
  `Header ... early` are.
- Interim `1xx` responses from an upstream are neither inspected nor tested.
- `SecRemoteRules` is not supported (see Directives).
- Tested with the prefork and event MPMs. HTTP/2 needs event: `mod_http2`
  does not support prefork.

## License

Apache License 2.0
