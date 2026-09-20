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

Requires libcoraza >= 1.7 for both the headers at compile time and the shared
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
./test.sh http://localhost:8888
docker stop coraza-apache-test
```

To test with a specific MPM (default is event):

```
docker build --no-cache --build-arg MPM=prefork -t coraza-test-prefork .
docker run --rm -d --name coraza-test-prefork -p 8889:80 coraza-test-prefork
./test.sh http://localhost:8889 --mpm=prefork
docker stop coraza-test-prefork
```

The `--mpm` flag verifies the server is running the expected MPM via the
`server-info` endpoint.

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
- **Phase 2** (fixups hook): request body -- read proactively via ap_get_client_block()
- **Phase 3-4** (output filter): response headers and body, with header delay
- **Phase 5** (log_transaction hook): audit logging

An internal redirect (`ErrorDocument`, `FallbackResource`, `DirectoryIndex`,
`mod_rewrite`) creates a new `request_rec` for the same client request. The
module reuses the transaction of the request the client sent: phases 1-2 are
not repeated, phases 3-4 inspect the response actually served, and there is one
audit entry. An error page served because that transaction denied the request
is passed through as-is rather than inspected and possibly denied again.

Rules are collected as strings during config parsing (master process)
and replayed in each child process after dlopen. This is required because
the Go runtime inside libcoraza cannot be loaded before fork.

## Limitations

- Tested with prefork and event MPMs

## License

Apache License 2.0
