# Test Coverage

The integration test suite (`test.sh`) runs **124 tests** against a Docker
container with CRS v4 and multiple Location/Directory/.htaccess/VirtualHost configurations.

## Running

```bash
# Build and start
docker build --no-cache -t coraza-apache-test .
docker run --rm -d --name coraza-apache-test -p 8888:80 coraza-apache-test

# Full suite (124 tests, event MPM)
./test.sh http://localhost:8888 --mpm=event --container=coraza-apache-test

# Minimal (104 tests, no audit/debug log checks, no MPM verification)
./test.sh http://localhost:8888

# Prefork MPM
docker build --no-cache --build-arg MPM=prefork -t coraza-prefork .
docker run --rm -d --name coraza-prefork -p 8889:80 coraza-prefork
./test.sh http://localhost:8889 --mpm=prefork --container=coraza-prefork
```

### Flags

| Flag | Effect |
|------|--------|
| `--mpm=event\|prefork` | Verifies active MPM via `/server-info` (+1 test) |
| `--container=NAME` | Enables audit/debug log tests via `docker exec` (+19 tests) |

## Test Categories

### CRS Attack Detection (23 tests)

GET and POST requests against OWASP CRS v4 rules.

| Category | GET | POST | Tests |
|----------|-----|------|-------|
| Normal requests (200) | 3 | 2 | 5 |
| SQL injection (403) | 4 | 3 | 7 |
| XSS (403) | 3 | 2 | 5 |
| Path traversal / LFI (403) | 2 | - | 2 |
| Remote command execution (403) | 2 | 2 | 4 |

### PUT/DELETE Body Inspection (16 tests)

Verifies WAF inspects request bodies for non-standard HTTP methods.
Clean requests return 405 (WAF passes, Apache rejects method).

| Method | Tests | Covers |
|--------|-------|--------|
| PUT | 8 | CRS attacks, phase 2 body rule, body limit reject/partial |
| DELETE | 8 | Same coverage as PUT |

### Directory and .htaccess (12 tests)

| Context | Tests | Covers |
|---------|-------|--------|
| `<Directory>` | 5 | Custom rule block/pass, `Coraza Off` bypass |
| `.htaccess` | 4 | Custom rule block/pass, `Coraza Off` bypass |
| CRS inheritance | 3 | Server-level CRS rules apply in Directory/.htaccess |

### Per-Phase Processing (8 tests)

| Phase | Hook | Tests |
|-------|------|-------|
| Phase 1 | fixups | 2 (ARGS match: deny + pass) |
| Phase 2 | fixups | 2 (REQUEST_BODY match: deny + pass) |
| Phase 3 | output filter | 2 (RESPONSE_HEADERS:Content-Type match: deny + pass) |
| Phase 4 | output filter | 2 (RESPONSE_BODY match: deny + pass) |

### Config Merging (6 tests)

| Scenario | Tests |
|----------|-------|
| `SecRuleEngine Off` in Location | 2 (SQLi passes, normal passes) |
| `SecRequestBodyAccess Off` in Location | 1 (POST SQLi passes) |
| Inherited CRS + local rule in Location | 3 (CRS blocks, local blocks, local passes) |

### Request Body Limits (11 tests)

| Scenario | Tests | Covers |
|----------|-------|--------|
| `SecRequestBodyLimitAction Reject` | 3 | Small OK, large 413, at-limit OK |
| `SecRequestBodyLimitAction ProcessPartial` | 3 | Small OK, large passes, attack detected |
| Inherited limit across methods | 4 | GET/POST/PUT/DELETE with inherited limit |
| Location override (larger limit) | 1 | Location overrides server limit |

### Scoring / TX Variables (5 tests)

| Mode | Tests | Covers |
|------|-------|--------|
| Absolute (`setvar:tx.score=N`) | 2 | Below threshold passes, at threshold blocks |
| Iterative (`setvar:tx.score=+1`) | 3 | 1 arg passes, 2 pass, 3 blocks |

### Non-403 Status Codes (3 tests)

Custom `deny,status:401` rules. Verifies CRS rules still return 403
while custom rules return their configured status.

### Location Rule Isolation (6 tests)

Two isolated Locations (`/isolated-a`, `/isolated-b`) with different rule IDs.
Verifies rules from one Location don't leak into another.

### Custom Error Pages (5 tests)

`ErrorDocument 403` and `ErrorDocument 401` with `Coraza Off` on the error
page Location. Verifies error page body is served on block and not on pass.

### VirtualHost Isolation (8 tests)

Three name-based VirtualHosts tested via explicit `Host:` headers. A default
VirtualHost for `localhost` preserves main server behavior for existing tests.

Server-level CRS rules inherit into VirtualHosts (Apache copies parent server
config as base). `Coraza Off` in a VirtualHost fully disables inspection.

| VirtualHost | Config | Tests | Covers |
|-------------|--------|-------|--------|
| `vhost-off.test` | `Coraza Off` | 3 | Normal OK, SQLi passes, XSS passes |
| `vhost-custom.test` | `Coraza On` + 1 custom rule | 4 | Normal OK, custom rule blocks/passes, inherited CRS blocks SQLi |
| Main server | CRS enabled | 1 | SQLi still blocked (regression check) |

### Audit Log (7 tests, requires `--container`)

| Scenario | Tests |
|----------|-------|
| Blocked request logged with sections A, B, H | 5 |
| Custom transaction ID in audit log | 2 |

### Debug Log Per-Location Isolation (3 tests, requires `--container`)

Three Locations with different `SecDebugLog` paths. Verifies each Location
writes to its own log file and rule IDs appear in the correct log.

### Per-Location Audit Log Isolation (9 tests, requires `--container`)

Five Locations with per-location `SecAuditLog` paths, including nested
Locations (`/auditlog-sub1/sub2`). Verifies:

- Each Location writes to its own audit log
- Nested Locations inherit parent rules (requests appear in child's log)
- `ctl:auditLogParts=+E` adds the E section to the audit log

## Apache Config Under Test

The Docker image configures:

- **Server level**: `Coraza On`, CRS v4 via `CorazaRulesFile`, `ErrorDocument 403/401`
- **29 Location blocks**: per-phase rules (1-4), config merging, body limits, scoring,
  audit/debug log isolation, rule isolation, error pages, transaction ID, status codes
- **2 VirtualHost blocks**: `vhost-off.test` (Coraza Off), `vhost-custom.test` (custom rule, no CRS)
- **2 Directory blocks**: custom rule + `Coraza Off`
- **2 .htaccess files**: custom rule + `Coraza Off` (created during Docker build)
- **mod_info**: enabled for MPM detection (`/server-info` with `Coraza Off`)

## Stress Testing

Validated with 80 parallel runs (8 concurrent × 10 rounds) under event MPM:
0 segfaults, container stable, memory plateaus after initial warmup.

## Graceful Restart

Validated `httpd -k graceful` survives multiple cycles including 3 rapid
restarts (1s apart). Full 124-test suite passes after all restarts.
Old workers clean up WAFs on exit, new workers rebuild via child_init.

## What's Not Covered

- Redirect interventions (`intervention->url` not available in libcoraza)
