# Coraza Apache Connector

**Experimental** -- not production ready.

Apache HTTPD module for the Coraza WAF engine, using libcoraza (C bindings).

Same dependency chain as coraza-nginx: coraza (Go) -> libcoraza (C bindings) -> this module.

Requires the same forks until the patches are merged upstream:
- libcoraza: `ppomes/libcoraza` branch `feat/implement-missing-apis`
- coraza: `ppomes/coraza` branch `feat/rules-merge` (pulled in by libcoraza's go.mod)

## Build

Requires libcoraza headers at compile time and the shared library at runtime.
The module is not linked against libcoraza -- it loads it via dlopen()
after fork to avoid Go runtime deadlocks (same approach as coraza-nginx).

```
make
make install
```

Or with a custom apxs path:

```
make APXS=/path/to/apxs
```

## Docker

Builds everything from source (libcoraza + module) and runs basic tests:

```
docker build --no-cache -t coraza-apache-test .
docker run --rm coraza-apache-test
```

## Configuration example

```apache
LoadModule coraza_module modules/mod_coraza.so

Coraza On
CorazaRules "SecRuleEngine On"
CorazaRules "SecRequestBodyAccess On"
CorazaRules "SecResponseBodyAccess Off"

# OWASP CRS
CorazaRulesFile /etc/coraza/crs-setup.conf
CorazaRulesFile /etc/coraza/rules/*.conf

# Custom exclusions for a specific path
<Location /api/upload>
    CorazaRules "SecRuleRemoveById 920420"
    CorazaRules "SecRequestBodyLimit 52428800"
</Location>

# Disable inspection entirely for health checks
<Location /health>
    Coraza Off
</Location>
```

### Directives

**Coraza** On|Off -- enable or disable the module. Context: server config, `<Location>`.

**CorazaRules** "..." -- inline rule or directive. Context: server config, `<Location>`.

**CorazaRulesFile** /path -- load rules from file. Context: server config, `<Location>`.

**CorazaTransactionId** "..." -- custom transaction ID. Context: server config, `<Location>`.

Rules defined at server level are inherited by `<Location>` blocks.
A `<Location>` with `Coraza Off` disables inspection for that path.

## How it works

The module hooks into Apache's request processing:

- **Phase 1** (fixups hook): connection info, URI, request headers
- **Phase 2** (fixups hook): request body -- read proactively via ap_get_client_block()
- **Phase 3-4** (output filter): response headers and body, with header delay
- **Phase 5** (log_transaction hook): audit logging

Rules are collected as strings during config parsing (master process)
and replayed in each child process after dlopen. This is required because
the Go runtime inside libcoraza cannot be loaded before fork.

## Limitations

- Tested with prefork and event MPMs
- Only `<Location>` blocks, no `<Directory>` or .htaccess support yet
- No `CorazaRulesRemote` directive yet

## License

Apache License 2.0
