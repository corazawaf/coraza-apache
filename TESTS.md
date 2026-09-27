# Test Coverage

The integration test suite (`test.sh`) runs **313 tests** against a Docker
container with CRS v4 and multiple Location/Directory/.htaccess/VirtualHost configurations.

## Running

```bash
# Build and start
docker build --no-cache -t coraza-apache-test .
docker run --rm -d --name coraza-apache-test -p 8888:80 coraza-apache-test

# Full suite (313 tests, event MPM)
./test.sh http://localhost:8888 --mpm=event --container=coraza-apache-test

# Minimal (214 tests, no audit/debug log checks, no MPM verification)
./test.sh http://localhost:8888

# Prefork MPM
docker build --no-cache --build-arg MPM=prefork -t coraza-prefork .
docker run --rm -d --name coraza-prefork -p 8889:80 coraza-prefork
./test.sh http://localhost:8889 --mpm=prefork --container=coraza-prefork
```

### Flags

| Flag | Effect |
|------|--------|
| `--mpm=event\|prefork` | Verifies active MPM via `/server-info` (+1 test). The HTTP/2 section is not flag-driven: it probes h2c and skips itself on a server that does not negotiate it, so a prefork image (no mod_http2) reports 8 tests fewer |
| `--container=NAME` | Enables audit/debug log tests via `docker exec` and the crash sweep (+98 tests) |

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

### Directory and .htaccess (16 tests)

| Context | Tests | Covers |
|---------|-------|--------|
| `<Directory>` | 5 | Custom rule block/pass, `Coraza Off` bypass |
| `.htaccess` | 8 | Custom rule block/pass, `Coraza Off` bypass; two policies whose rule text collides under the WAF cache's DJB2 hash with the same rule count (`ARGS:xb` / `ARGS:yA`) each run their own rules; the four requests share one keep-alive connection so a single child's cache serves them all (issue #43) |
| CRS inheritance | 3 | Server-level CRS rules apply in Directory/.htaccess |

### Per-Phase Processing (15 tests)

| Phase | Hook | Tests |
|-------|------|-------|
| Phase 1 | fixups | 2 (ARGS match: deny + pass) |
| Phase 2 | fixups | 2 (REQUEST_BODY match: deny + pass) |
| Phase 3 | output filter | 4 (RESPONSE_HEADERS:Content-Type match: deny + pass; the deny reaches the ErrorDocument, no recursive-error page) |
| Phase 4 | output filter | 4 (RESPONSE_BODY match: deny + pass; same ErrorDocument checks) |
| `ARGS_POST` | fixups (phase 2) | 3 (`cmd=boom` in the body denied, `cmd=safe` passes, `?cmd=boom` in the query passes: the selector is `ARGS_POST`, not `ARGS`; issue #49) |

### Phase 3/4 over HTTP/2 (7 tests + 1 sweep, event MPM only)

Issue #51. The image loads `mod_http2` and sets `Protocols h2c http/1.1` under
the event MPM (mod_http2 does not support prefork). With curl's
`--http2-prior-knowledge`, each check also asserts that the exchange ran over
HTTP/2: a plain request negotiates h2; the phase-3 Content-Type deny and the
phase-4 body deny return 403, the latter serving the custom error page with no
`OK` byte of the blocked body reaching the client (over h2 a blocked body must
never become DATA frames); the phase-4 pass delivers its body; a redirect
intervention keeps its 302; a body-less 204 crosses the header delay. The
section probes h2c first and skips itself, with a `SKIP` line, when the server
does not negotiate HTTP/2.

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

### Redirect interventions and response header guards (12 tests)

`redirect:` rules with `status:301` / `302`: status and `Location` are exactly
the configured target, a clean path and query survive, and no header can be
smuggled into a clean response. Issue #54 adds a target carrying a raw CR and
one carrying a raw DEL byte (written into the config with `printf`): the
connector truncates `Location` at the first C0 control or DEL byte, so each
answers 302 with exactly one `Location` cut to `http://example.org/a`, and
logs a warning (checked in the container log, +1 test with `--container`).

### Location Rule Isolation (6 tests)

Two isolated Locations (`/isolated-a`, `/isolated-b`) with different rule IDs.
Verifies rules from one Location don't leak into another.

### Source contract (4 tests)

Host-side greps over `src/` for properties the black-box suite cannot observe:
`coraza_free_string` is bound as a required symbol, both `coraza_new_waf()` call
sites release the Go-allocated error string through it (each check scoped to its
function, `coraza_build_waf` and `coraza_child_init`), and no libc `free()`
touches those strings (allocator mismatch, per the libcoraza docs). These run
without `--container`, so they count in the minimal run too.

### Source contract: request body read in 64 KiB chunks (4 tests)

Issue #45. The fixups read loop used an 8 KiB stack buffer: 128 engine
submissions, intervention polls and replay/spool copies per MiB of body. It now
reads `CORAZA_BODY_READ_CHUNK` (64 KiB, as coraza-nginx does) into a buffer
from the request pool, allocated only for requests that carry a body. Checked
by grep: the constant's value, its use in `ap_get_client_block()`, the pool
allocation, and the absence of any stack `char buf[]` in the file. The 20 KB
and 300 KB replay tests remain byte-exact. No `--container` needed.

### Bulk header submission (11 tests)

Issue #46. Request and response headers used to cross the C/Go boundary one
call per header. They are now packed by `coraza_pack_headers()` (u16 name
length, name, u32 value length, value, the format shared with coraza-nginx)
and handed to `coraza_add_request_headers()` / `coraza_add_response_headers()`
in one call per phase; a pack failure (a length the wire format cannot carry)
or a batch the engine rejects falls back to the per-header loop, which keeps
its fail-closed length guard. Request side: the trigger behind 60 padding
headers is still seen, the padding alone passes, an empty-valued header keeps
the framing intact. Response side, on the `resp-headers.test` vhost: a phase-3 rule fires on a
header set with `Header set` (headers_out) and on one set with `Header always
set` (err_headers_out), a path without a rule passes; the `/phase3`
Content-Type rule covers the third source. The markers are set `early` at
vhost level because the normal mod_headers filter runs after `CORAZA_OUT`
(a filter-order limitation, see the Dockerfile) and early mode precedes
`<Location>` merging.
Five source-contract checks pin the required symbols, both bulk call sites and
the packer's u16 guard. Followed by a crash sweep.

### Source contract: every engine result is checked (11 tests)

Issue #42. Greps over `src/` proving that every `coraza_process_*` call goes
through `coraza_process_failed()` and every `coraza_add_*` / `coraza_append_*`
call through `CORAZA_CALL_FAILED()`: six positive checks scoped to
`coraza_post_read_request` and `coraza_output_filter`, two negative checks
that no engine call opens a line bare in the phase-1 and output-filter
sources, one that the input filter never calls the engine at all (it only
replays the body, the pre-#35 inspection path is gone, issue #47), one that
the unused `coraza_request_body_from_file` binding is gone, and one that a
failing `apr_bucket_read()` no longer
returns its status bare (it takes `coraza_fail_closed_response()`, so a
delayed response still gets a clean 500). No `--container` needed.

### Request Protocol (5 tests)

`REQUEST_PROTOCOL` must carry the version as the client sent it. `/protocol-check`
matches `HTTP/1.1`; `/protocol-raw` matches `HTTP/4.0`, a version Apache does not
know, which the module used to collapse onto `HTTP/1.1`. Raw request lines are
sent over a socket because curl cannot emit arbitrary versions.

| Test | Asserts |
|------|---------|
| HTTP/1.1 matches REQUEST_PROTOCOL | slash-delimited form reaches the engine (403) |
| HTTP/1.0 does not match | `--http1.0` request is not mistaken for 1.1 (200) |
| HTTP/4.0 reaches REQUEST_PROTOCOL verbatim | raw token matches `@streq HTTP/4.0` (406) |
| HTTP/1.1 does not trip the raw rule | control on `/protocol-raw` (200) |
| CRS 920430 rejects HTTP/4.0 on / | the version policy is enforceable through the connector (403) |

### Raw-socket robustness (8 tests)

Issue #50. `raw_exchange` writes one payload on a single socket and reports
every status code received, in order. A phase-1 deny followed by a benign
request pipelined on the same keep-alive socket answers `403 200` (fresh, not
stale). A chunked body with a non-hex chunk size fails the dechunk read in
fixups and gets 400, not 500 and no hang. `Content-Length` together with
`Transfer-Encoding` is accepted by httpd 2.4 (Transfer-Encoding wins), so the
conflict reaches the WAF and CRS 920640 denies it with 403. `Expect:
100-continue` against a phase-1 trigger, body withheld, yields 403 as the first
and only status, never an interim 100 (the deny runs before any body read).
After each exchange a plain `GET /` must answer 200; a crash sweep closes the
section.

### In-flight cancellation and graceful restart (4 + 5 tests, 5 require `--container`)

Issue #53. A client announces a 100000-byte body, sends 10 bytes and hangs up
while fixups is mid-read (the send itself is asserted); another receives the
200 of a delayed 4 MiB download and is cut by its own 2 s cap (curl exit 28),
so the abort lands mid-response. After each, `GET /` must answer 200. With
`--container`, an SSE stream and a delayed download are in flight when
`httpd -k graceful` runs (its exit status is asserted): each must complete or
be cut cleanly (curl exit 0, or 28 on its own cap, never a reset), the new
workers must answer 200 and still enforce a phase-1 rule. Each half ends with a crash sweep.

### Config validation (12 tests, requires `--container`)

`httpd -t` inside the container on the image's own `httpd.conf` minus the rules
include, plus one delta per case: `Coraza On` with no rule anywhere fails with
the fail-closed diagnostic; `Coraza On` plus a single rule passes; `Coraza Off`
without rules passes.

`SecRemoteRules` (issue #62) is refused at `httpd -t` from all three entry
points: the native directive, `CorazaRules` text and a `CorazaRulesFile`
(reported with resolved path and record line, including a name split by a `\`
continuation, a directive past the 4 KiB read buffer on a last line without
newline, a record opening a backtick list left unclosed, and a relative path resolved against `ServerRoot`). Controls: a
commented-out `SecRemoteRules`, the words at the start of a continuation line
or inside a backtick action list, `SecRemoteRulesX`, and
`SecRemoteRulesFailAction` all pass.

### Custom Error Pages (7 tests)

`ErrorDocument 403` and `ErrorDocument 401`, with the error page Location
inspected (`Coraza On`) and carrying a phase-4 rule that matches the page's own
body. Verifies the error page body is served on block and not on pass, that
the page comes back untouched for a request this transaction already denied
(issue #40), and that the same rule fires when the page is requested directly.

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

### Error page audit (2 tests, requires `--container`)

A denied request served an `ErrorDocument` through an internal redirect is one
transaction: after clearing the log, it must hold exactly one entry (one
request line), followed by the section's crash sweep.

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

### Crash and worker-health sweep (50 tests: 49 sweeps + 1 self-test, requires `--container`)

Apache logs to the container's stderr (`ErrorLog /proc/self/fd/2`), so a worker
that dies during a test leaves an `AH00052: child pid N exit signal ...` line in
`docker logs` — and a sanitizer build leaves its report there. A test that kills
a worker and gets its 200 from the next one would otherwise pass. `check_no_crash`
runs after every section, reports only lines new since the previous sweep (so
the failing section is named), and probes `/server-info` to catch a wedged
server. A self-test injects a fake worker-exit line into httpd's stderr and
requires the sweep to detect it, so the oracle is proven live, not assumed.

### DetectionOnly proven via the audit log (6 tests, requires `--container`)

Issue #49. `/detection-only` carries the `/phase1` deny rule under
`SecRuleEngine DetectionOnly` with its own audit log: the matching request
gets a 200 and the audit log holds the rule id and `msg`, which is what
separates "matched, declined to block" from "never ran"; a non-matching
request first shows the rule id is absent until a match. Mutation control: the
`On` twin returns 403. A `noauditlog` twin was tried and dropped: coraza still
writes the DetectionOnly transaction under `RelevantOnly` + `noauditlog` (empty
H section), which is engine behaviour, not the connector's. Followed by a crash
sweep.

### auditlog action with RelevantOnly (3 tests, requires `--container`)

`SecAuditEngine RelevantOnly` with a rule carrying `auditlog` / `noauditlog`:
a matching request is logged, a non-matching one is not, and `noauditlog`
suppresses the entry even on a match (per-location audit files, checked via
`docker exec`).

### Header delay only when the body is inspected (4 tests)

`/stream-json-*` is a CGI that sends headers and a first chunk, holds the
response for 8 s, then finishes. `SecResponseBodyAccess Off` and a Content-Type
outside `SecResponseBodyMimeType` must both deliver the first chunk within
`check_stream`'s 4 s window (issue #60; the `Off` case needs
`coraza_is_response_body_accessible`, libcoraza >= 1.8, the module's floor).
With body inspection on it must not (the delay is the intended behaviour). A
phase-4 `ARGS` rule on the uninspected location must still return a clean 403,
proving phase 4 is finalised before the headers go out rather than skipped.
The same holds for SSE: `text/event-stream` is outside the MIME list, so an SSE
response takes this path too and a phase-4 `ARGS` rule denies it cleanly (the
SSE shortcut only applies to an inspected stream, which can never finish).

### Body-less responses through the header delay (4 tests)

Issue #52. `/status204` and `/status304` are one CGI (`tests/cgi-bin/status`)
answering with the status from `SetEnv STATUS_CODE`, under `text/html` so the
header delay engages, and with a phase-4 `RESPONSE_BODY` rule armed. With no
body, the delay must release the headers on the immediate EOS (a 5 s cap
catches a hang) and the status must come through untouched; a raw-socket read
checks that not one byte follows the headers (curl discards a 204/304 body by
design, so it cannot tell). Followed by a crash sweep.

### Delayed response cap log (1 test, requires `--container`)

Companion to the delayed-response cap tests above: the container log must
carry the "flushing headers early" line when the 4 MiB body crosses
`CORAZA_MAX_DELAYED_BODY`.

### Proxied backend through mod_proxy (6 tests)

Issue #55. The image listens on a second port (8081) with a WAF-off vhost that
serves the same documents and the echo CGI, and reverse-proxies `/proxied/` to
it with `mod_proxy_http`. The proxied exchange must be inspected like a local
one: a plain request is served, a phase-1 CRS deny still applies, an upstream
response header reaches the client and a phase-3 rule on it denies (mod_proxy
puts upstream headers in `headers_out` before `CORAZA_OUT` runs), the request
body consumed by fixups is replayed to the proxy and reaches the backend, and
a phase-4 rule on the proxied body denies with the custom error page. Followed
by a crash sweep. Interim 100/103 statuses still need a raw upstream and remain
out of reach.

### Request body replay (4 tests)

The fixups hook reads the request body with `ap_get_client_block()` to inspect
it before the handler runs. That consumes the connection input, so `CORAZA_IN`
replays the copy it kept (issue #34). `/echo` is a CGI script that writes back
what it received.

| Test | Asserts |
|------|---------|
| POST JSON body is delivered | echoed body equals the payload |
| POST 20 KB body is delivered intact | single 64 KiB read replayed byte-exact, terminated by EOS |
| PUT static file with body: 405, not 400 | exhausted replay delegates instead of returning `APR_EOF` |
| POST 300 KB multipart upload is delivered intact | several 64 KiB reads; body past `CorazaRequestBodyInMemoryLimit` is spooled to a temp file and replayed as a file bucket |

### SecRequestBodyAccess Off: body not submitted to the engine (4 tests)

Issue #44. With body access off the engine discards every body byte, so the
fixups hook keeps reading, spooling and replaying the body (the handler
depends on the replay) but no longer calls `coraza_append_request_body()` or
polls for an intervention per chunk. `/echo-bodyoff` carries a body-matching
and a header-matching phase-2 rule: the body rule must not fire and the CGI
must echo the full body with the right `Content-Length`; the header rule must
still fire, proving phase 2 ran. `/echo-bodyon` has the same body rule with
access on, as the control that the rule works. Followed by a crash sweep.

## Running under sanitizers

`docker build --build-arg SANITIZE=1` builds the module with ASan + UBSan
(`make SANITIZE=1`) and makes the image's entrypoint preload the sanitizer
runtime into httpd, with leak detection off and reports on stderr. The full
suite then runs unchanged: its crash sweep fails on any sanitizer line in the
container log, and the `A/UBSan` workflow (`.github/workflows/sanitizer.yml`)
does exactly that on every push and pull request, then greps the whole log
once more. This is what makes double-cleanup bugs on cancellation and reload
reproducible here (issue #55).

## Apache Config Under Test

The Docker image configures:

- **Server level**: `Coraza On`, CRS v4 via `CorazaRulesFile`, `ErrorDocument 403/401`
- **29 Location blocks**: per-phase rules (1-4), config merging, body limits, scoring,
  audit/debug log isolation, rule isolation, error pages, transaction ID, status codes
- **2 VirtualHost blocks**: `vhost-off.test` (Coraza Off), `vhost-custom.test` (custom rule, no CRS)
- **2 Directory blocks**: custom rule + `Coraza Off`
- **4 .htaccess files**: custom rule, `Coraza Off`, two hash-colliding policies (created during Docker build)
- **mod_info**: enabled for MPM detection (`/server-info` with `Coraza Off`)

## Stress Testing

Validated with 80 parallel runs (8 concurrent × 10 rounds) under event MPM:
0 segfaults, container stable, memory plateaus after initial warmup.

## Graceful Restart

Validated `httpd -k graceful` survives multiple cycles including 3 rapid
restarts (1s apart). Full 313-test suite passes after all restarts.
Old workers clean up WAFs on exit, new workers rebuild via child_init. The
suite itself now restarts the server once, over in-flight requests (issue #53
above).
