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

Builds everything from source (libcoraza + module) and runs basic tests:

```
docker build --no-cache -t coraza-apache-test .
docker run --rm coraza-apache-test
```

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
```

### Directives

**Sec\*** -- all standard modsecurity directives (`SecRuleEngine`, `SecRule`,
`SecAction`, `SecRequestBodyAccess`, `SecAuditEngine`, etc.) are registered
natively and can be used directly in Apache config files. Context: server config, `<Location>`.

**Coraza** On|Off -- enable or disable the module. Context: server config, `<Location>`.

**CorazaRules** "..." -- inline rule or directive. Context: server config, `<Location>`.

**CorazaRulesFile** /path -- load rules from file. Use this for CRS and other rule
files that reference relative data file paths. Context: server config, `<Location>`.

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
