#!/bin/sh

# Parse arguments
URL=""
MPM=""
CONTAINER=""
for arg in "$@"; do
    case "$arg" in
        --mpm=*)       MPM="${arg#--mpm=}" ;;
        --container=*) CONTAINER="${arg#--container=}" ;;
        *)             URL="$arg" ;;
    esac
done
URL="${URL:-http://localhost:8080}"

PASS=0
FAIL=0

check() {
    desc="$1"
    url="$2"
    expected="$3"

    code=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

check_method() {
    desc="$1"
    method="$2"
    url="$3"
    body="$4"
    expected="$5"

    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -d "$body" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

check_method_large() {
    desc="$1"
    method="$2"
    url="$3"
    size="$4"
    expected="$5"

    body=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c "$size")
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" -d "$body" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

check_post() {
    check_method "$1" "POST" "$2" "$3" "$4"
}

check_post_large() {
    check_method_large "$1" "POST" "$2" "$3" "$4"
}

check_audit_log() {
    desc="$1"
    pattern="$2"

    if docker exec "$CONTAINER" grep -q "$pattern" /var/log/coraza/audit.log 2>/dev/null; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' not found)\n" "$desc" "$pattern"
        FAIL=$((FAIL + 1))
    fi
}

check_body() {
    desc="$1"
    url="$2"
    expected="$3"
    body_pattern="$4"
    negate="$5"

    resp=$(curl -s -w "\n%{http_code}" "$url")
    code=$(echo "$resp" | tail -1)
    body=$(echo "$resp" | sed '$d')

    status_ok=false
    body_ok=false

    [ "$code" = "$expected" ] && status_ok=true

    if [ "$negate" = "!" ]; then
        echo "$body" | grep -q "$body_pattern" || body_ok=true
    else
        echo "$body" | grep -q "$body_pattern" && body_ok=true
    fi

    if $status_ok && $body_ok; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        reason=""
        $status_ok || reason="status $code != $expected"
        $body_ok || { [ -n "$reason" ] && reason="$reason, "; reason="${reason}body mismatch"; }
        printf "  FAIL  %s -> %s (%s)\n" "$desc" "$code" "$reason"
        FAIL=$((FAIL + 1))
    fi
}

# POST a body and assert both the status and that the response body matches a
# pattern. Bounded by --max-time: a replayed body that lacks its EOS leaves the
# handler blocked on stdin, and that has to surface as a failure, not a hang.
check_post_body() {
    desc="$1"
    url="$2"
    ctype="$3"
    body="$4"
    expected="$5"
    body_pattern="$6"

    resp=$(curl -s --max-time 10 -w "\n%{http_code}" -X POST \
        -H "Content-Type: $ctype" --data-binary "$body" "$url")
    code=$(echo "$resp" | tail -1)
    out=$(echo "$resp" | sed '$d')

    if [ "$code" = "$expected" ] && echo "$out" | grep -q "$body_pattern"; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        reason="status $code"
        echo "$out" | grep -q "$body_pattern" || reason="$reason, body mismatch: $(echo "$out" | head -c 80)"
        printf "  FAIL  %s -> %s (%s)\n" "$desc" "$code" "$reason"
        FAIL=$((FAIL + 1))
    fi
}

# Upload a file as multipart/form-data and assert the status, a body pattern
# and the exact response size. For bodies that cross the in-memory replay
# limit, where the tail is served from the spool file.
#
# The echo CGI reports the request-body length Apache gave it and echoes the
# bytes it read, framed as "CONTENT_LENGTH=[n]\nBODY=[...]\n". The response
# must therefore be exactly n + 26 + digits(n) bytes: a replay that drops or
# truncates a bucket cannot pass on a lower bound.
check_upload_body() {
    desc="$1"
    url="$2"
    path="$3"
    expected="$4"
    body_pattern="$5"

    resp=$(curl -s --max-time 20 -w "\n%{http_code} %{size_download}" \
        -F "file=@$path;type=text/plain" "$url")
    meta=$(echo "$resp" | tail -1)
    code=${meta%% *}
    size=${meta#* }
    out=$(echo "$resp" | sed '$d')
    n=$(printf '%s\n' "$out" | sed -n 's/^CONTENT_LENGTH=\[\([0-9][0-9]*\)\].*/\1/p' | head -1)
    want=$(( ${n:-0} + 26 + ${#n} ))

    if [ "$code" = "$expected" ] && [ -n "$n" ] && [ "$size" -eq "$want" ] \
        && echo "$out" | grep -q "$body_pattern"; then
        printf "  PASS  %s -> %s (%s bytes = CONTENT_LENGTH %s + framing)\n" \
            "$desc" "$code" "$size" "$n"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (%s bytes, expected %s/%s for CONTENT_LENGTH %s, pattern %s)\n" \
            "$desc" "$code" "$size" "$expected" "$want" "${n:-?}" "$body_pattern"
        FAIL=$((FAIL + 1))
    fi
}

# Assert the number of audit-log lines matching a pattern. Count request
# lines (^GET / ^POST): one per entry. A tag would be counted once per part
# it appears in (request line, rule message) and say nothing about entries.
check_audit_count() {
    desc="$1"
    pattern="$2"
    expected="$3"

    n=$(docker exec "$CONTAINER" grep -c "$pattern" /var/log/coraza/audit.log 2>/dev/null)
    if [ "${n:-0}" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$n"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s matches of '%s')\n" "$desc" "${n:-0}" "$expected" "$pattern"
        FAIL=$((FAIL + 1))
    fi
}

clear_audit_log() {
    docker exec "$CONTAINER" truncate -s 0 /var/log/coraza/audit.log 2>/dev/null
}

check_debug_log() {
    desc="$1"
    file="$2"
    pattern="$3"

    if docker exec "$CONTAINER" grep -q "$pattern" "$file" 2>/dev/null; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' not in %s)\n" "$desc" "$pattern" "$file"
        FAIL=$((FAIL + 1))
    fi
}

clear_debug_logs() {
    docker exec "$CONTAINER" sh -c 'for f in /var/log/coraza/debug/*.log; do [ -f "$f" ] && truncate -s 0 "$f"; done' 2>/dev/null
}

check_perloc_audit_log() {
    desc="$1"
    file="$2"
    pattern="$3"

    if docker exec "$CONTAINER" grep -q "$pattern" "$file" 2>/dev/null; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' not in %s)\n" "$desc" "$pattern" "$file"
        FAIL=$((FAIL + 1))
    fi
}

check_perloc_audit_log_absent() {
    desc="$1"
    file="$2"
    pattern="$3"

    if docker exec "$CONTAINER" grep -q "$pattern" "$file" 2>/dev/null; then
        printf "  FAIL  %s (pattern '%s' found in %s)\n" "$desc" "$pattern" "$file"
        FAIL=$((FAIL + 1))
    else
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    fi
}

clear_perloc_audit_logs() {
    docker exec "$CONTAINER" sh -c 'for f in /var/log/coraza/audit/*.log; do [ -f "$f" ] && truncate -s 0 "$f"; done' 2>/dev/null
}

check_redirect() {
    desc="$1"
    url="$2"
    expected_code="$3"
    expected_location="$4"

    resp=$(curl -s -o /dev/null -D - -w "\n%{http_code}" "$url")
    code=$(echo "$resp" | tail -1)
    location=$(echo "$resp" | grep -i '^Location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')

    if [ "$code" = "$expected_code" ] && [ "$location" = "$expected_location" ]; then
        printf "  PASS  %s -> %s Location: %s\n" "$desc" "$code" "$location"
        PASS=$((PASS + 1))
    else
        reason=""
        [ "$code" != "$expected_code" ] && reason="status $code != $expected_code"
        if [ "$location" != "$expected_location" ]; then
            [ -n "$reason" ] && reason="$reason, "
            reason="${reason}Location: '${location}' != '${expected_location}'"
        fi
        printf "  FAIL  %s (%s)\n" "$desc" "$reason"
        FAIL=$((FAIL + 1))
    fi
}

check_vhost() {
    desc="$1"
    host="$2"
    url="$3"
    expected="$4"

    code=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $host" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# Assert a response header's value, or -- with a trailing "!" -- its absence.
# Reads the raw header block, so a value smuggled in via an injected CRLF
# surfaces as its own header line and is caught: a positive assertion requires
# exactly one matching line (a duplicate fails it), and the absence form
# requires zero. The request is bounded and a curl failure is a test failure,
# not a silent "absent". Only trailing CR is stripped, and the raw value is not
# printed for absence failures (avoids leaking e.g. Set-Cookie into CI logs).
check_header() {
    desc="$1"
    url="$2"
    header="$3"
    expected="$4"
    negate="$5"

    hdrs=$(curl -s -o /dev/null -D - --max-time 10 "$url")
    rv=$?

    count=$(printf '%s\n' "$hdrs" | grep -ic "^${header}:")
    value=$(printf '%s\n' "$hdrs" | grep -i "^${header}:" | head -1 \
        | sed 's/\r$//' | sed "s/^[^:]*:[ ]*//")

    ok=false
    if [ "$rv" -ne 0 ]; then
        :   # request failed -> not ok
    elif [ "$negate" = "!" ]; then
        [ "$count" -eq 0 ] && ok=true
    else
        [ "$count" -eq 1 ] && [ "$value" = "$expected" ] && ok=true
    fi

    if $ok; then
        printf "  PASS  %s -> %s\n" "$desc" "$header"
        PASS=$((PASS + 1))
    else
        if [ "$rv" -ne 0 ]; then
            reason="request failed (curl exit $rv)"
        elif [ "$negate" = "!" ]; then
            reason="unexpected ${header} present (x${count})"
        elif [ "$count" -ne 1 ]; then
            reason="${header} matched x${count}, expected exactly 1"
        else
            reason="${header}: '${value}' != '${expected}'"
        fi
        printf "  FAIL  %s (%s)\n" "$desc" "$reason"
        FAIL=$((FAIL + 1))
    fi
}

# HEAD request: assert status within a timeout. Doubles as a hang guard --
# header delay must be skipped for header-only responses (no body, no EOS),
# so a HEAD must return promptly rather than block waiting for phase 4.
check_head() {
    desc="$1"
    url="$2"
    expected="$3"

    code=$(curl -s -o /dev/null -I --max-time 10 -w "%{http_code}" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# Like check, but forwards extra curl args (e.g. --http1.0) so a test can
# control the request line. desc/url/expected first; remaining args go to curl.
check_curl() {
    desc="$1"
    url="$2"
    expected="$3"
    shift 3

    code=$(curl -s -o /dev/null -w "%{http_code}" "$@" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# Source-contract check: assert a pattern in a module source file. The suite
# runs from the repository (test.sh sits at its root), so this pins things the
# black-box tests cannot observe, such as a freed string. \"!\" negates.
SRC_DIR=$(dirname "$0")/src
check_source() {
    desc="$1"
    file="$2"
    pattern="$3"
    negate="$4"

    if [ "$negate" = "!" ]; then
        if ! grep -qE "$pattern" "$SRC_DIR/$file"; then ok=true; else ok=false; fi
    else
        if grep -qE "$pattern" "$SRC_DIR/$file"; then ok=true; else ok=false; fi
    fi
    if $ok; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' %sin %s)\n" "$desc" "$pattern" "$([ "$negate" = "!" ] && echo "found " || echo "not ")" "$file"
        FAIL=$((FAIL + 1))
    fi
}

# Send a raw request line and return the status code. curl cannot emit an
# arbitrary HTTP version, so this speaks to the socket directly: nc where
# available, bash's /dev/tcp otherwise. The request is piped straight in --
# command substitution would strip the CRLFs that terminate it.
raw_status() {
    path="$1"
    proto="$2"
    hostport=${URL#http://}
    hostport=${hostport%%/*}
    host=${hostport%%:*}
    port=${hostport##*:}
    [ "$host" = "$port" ] && port=80

    if command -v nc >/dev/null 2>&1; then
        printf 'GET %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n' \
            "$path" "$proto" "$host" | nc -w 5 "$host" "$port" 2>/dev/null | head -1 | awk '{print $2}'
    elif command -v bash >/dev/null 2>&1; then
        bash -c 'exec 3<>"/dev/tcp/$1/$2"
                 printf "GET %s %s\r\nHost: %s\r\nConnection: close\r\n\r\n" "$3" "$4" "$1" >&3
                 timeout 5 head -1 <&3' _ "$host" "$port" "$path" "$proto" 2>/dev/null | awk '{print $2}'
    else
        echo "no-raw-client"
    fi
}

# Assert the status of a raw request line, e.g. a protocol version curl cannot send.
check_raw() {
    desc="$1"
    path="$2"
    proto="$3"
    expected="$4"

    code=$(raw_status "$path" "$proto")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "${code:-none}" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# Crash and worker-health sweep. Apache logs to the container's stderr
# (ErrorLog /proc/self/fd/2), so a dying worker shows up in `docker logs` as
# the MPM's "AH00052: child pid N exit signal ..." line, and a sanitizer
# build prints its report there too. A test that kills a worker and gets its
# 200 from the next one would otherwise pass unnoticed, so this runs after
# every section. `docker logs` is cumulative: only lines that appeared since
# the previous sweep are reported, which points at the section that caused
# them. Also probes /server-info so a wedged server is caught, not just a
# crashed one. No-op without --container (nothing to read).
CRASH_SEEN=0
# Returns non-zero only when `docker logs` itself fails (wrong name, daemon
# down): /bin/sh has no pipefail, so a plain pipeline would let grep turn a
# failed read into "zero matching lines" and every sweep would pass vacuously.
crash_lines() {
    logs=$(docker logs "$CONTAINER" 2>&1) || return 1
    printf '%s\n' "$logs" \
        | grep -E 'exit signal|AH00052|AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer'
    return 0
}
# Baseline: `docker logs` keeps everything since the container started, including
# the line the self-test injects, so a second run against the same container
# (the graceful-restart scenario in TESTS.md) must not re-report it. Each run
# only reports what it caused itself.
if [ -n "$CONTAINER" ]; then
    if ! lines=$(crash_lines); then
        echo "ERROR: cannot read docker logs for container '$CONTAINER'; the crash sweep would be vacuous" >&2
        exit 2
    fi
    CRASH_SEEN=$(printf '%s' "$lines" | grep -c .)
fi
check_no_crash() {
    desc="$1"
    [ -n "$CONTAINER" ] || return 0

    if ! lines=$(crash_lines); then
        printf "  FAIL  Crash sweep: %s (docker logs unreadable for '%s')\n" "$desc" "$CONTAINER"
        FAIL=$((FAIL + 1))
        return
    fi
    count=$(printf '%s' "$lines" | grep -c .)
    health=$(curl -s -o /dev/null --max-time 10 -w "%{http_code}" "$URL/server-info")

    if [ "$count" -le "$CRASH_SEEN" ] && [ "$health" = "200" ]; then
        printf "  PASS  Crash sweep: %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        reason=""
        [ "$count" -gt "$CRASH_SEEN" ] && reason="worker exit/sanitizer: $(printf '%s\n' "$lines" | tail -n +$((CRASH_SEEN + 1)) | head -1 | cut -c1-100)"
        [ "$health" != "200" ] && { [ -n "$reason" ] && reason="$reason; "; reason="${reason}server-info returned ${health:-nothing}"; }
        printf "  FAIL  Crash sweep: %s (%s)\n" "$desc" "$reason"
        FAIL=$((FAIL + 1))
    fi
    CRASH_SEEN=$count
}

# Same, scoped to one function: the body runs from the line that starts with
# the function name (K&R style, return type on the previous line) to the next
# closing brace in column 0. Binds an assertion to the function that must
# contain it, so a call moved elsewhere in the file no longer satisfies it.
check_source_in_func() {
    desc="$1"
    file="$2"
    func="$3"
    pattern="$4"

    if awk -v fn="$func" 'index($0, fn "(") == 1 {f=1} f {print} f && /^}$/ {exit}' "$SRC_DIR/$file" \
        | grep -qE "$pattern"; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' not in %s() of %s)\n" "$desc" "$pattern" "$func" "$file"
        FAIL=$((FAIL + 1))
    fi
}

# Fetch a streaming endpoint with a short timeout and assert whether a pattern
# arrived. "present" = the stream reached the client (header delay was skipped);
# "absent" = nothing streamed within the window (still buffered/delayed).
check_stream() {
    desc="$1"
    url="$2"
    pattern="$3"
    expect="$4"   # present | absent

    # Capture body + final HTTP code. A streamed response yields the pattern
    # (code 200); a delayed/buffered response sends no headers and curl times
    # out with code 000. An actual error (4xx/5xx) is neither -- so "absent"
    # requires the timeout (000), not merely an empty body, to avoid an HTTP
    # error masquerading as a correctly-delayed stream.
    out=$(curl -sN --max-time 4 -w '\n%{http_code}' "$url" 2>/dev/null)
    code=$(printf '%s\n' "$out" | tail -1)
    body=$(printf '%s\n' "$out" | sed '$d')

    if printf '%s' "$body" | grep -q "$pattern"; then
        got=present
    elif [ "$code" = "000" ]; then
        got=absent           # held/delayed: no headers arrived within the window
    else
        got="error(code=$code)"
    fi

    if [ "$got" = "$expect" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$got"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$got" "$expect"
        FAIL=$((FAIL + 1))
    fi
}

# Assert the number of body bytes downloaded (e.g. a large response arrives
# intact through the delayed-buffering cap, not truncated).
check_size() {
    desc="$1"
    url="$2"
    expected="$3"

    result=$(curl -s -o /dev/null -w "%{http_code} %{size_download}" --max-time 20 "$url") || {
        printf "  FAIL  %s -> curl failed\n" "$desc"
        FAIL=$((FAIL + 1))
        return
    }
    code=${result%% *}
    size=${result#* }
    if [ "$code" = "200" ] && [ "$size" = "$expected" ]; then
        printf "  PASS  %s -> %s (%s bytes)\n" "$desc" "$code" "$size"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (%s bytes, expected 200/%s)\n" "$desc" "$code" "$size" "$expected"
        FAIL=$((FAIL + 1))
    fi
}

# Assert a pattern appears in the container's stderr log (Apache error_log).
# Validate a configuration with httpd -t inside the container. The config is
# the image's own httpd.conf minus the include that carries the rules, plus
# whatever directives the test appends, so each case is exactly one delta.
check_config_validation() {
    desc="$1"
    extra="$2"
    expected_rc="$3"
    pattern="$4"

    out=$(docker exec "$CONTAINER" sh -c '
        grep -v "conf/extra/coraza.conf" /usr/local/apache2/conf/httpd.conf > /tmp/validate.conf
        printf "LoadModule coraza_module modules/mod_coraza.so\n%s\n" "$1" >> /tmp/validate.conf
        httpd -t -f /tmp/validate.conf 2>&1; echo "rc=$?"' sh "$extra" 2>&1)
    rc=$(printf '%s\n' "$out" | sed -n 's/^rc=//p' | tail -1)

    if [ "$rc" = "$expected_rc" ] && printf '%s\n' "$out" | grep -q "$pattern"; then
        printf "  PASS  %s -> rc=%s\n" "$desc" "$rc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> rc=%s (expected %s, pattern '%s'): %s\n" "$desc" "${rc:-none}" "$expected_rc" "$pattern" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-140)"
        FAIL=$((FAIL + 1))
    fi
}

check_container_log() {
    desc="$1"
    pattern="$2"

    if docker logs "$CONTAINER" 2>&1 | grep -q "$pattern"; then
        printf "  PASS  %s\n" "$desc"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s (pattern '%s' not in container log)\n" "$desc" "$pattern"
        FAIL=$((FAIL + 1))
    fi
}

echo "Coraza WAF test suite"
echo "Target: $URL"

# If --mpm is set, verify the server is running the expected MPM
if [ -n "$MPM" ]; then
    actual_mpm=$(curl -s "$URL/server-info?list" | grep -oE '>(event|prefork|worker)\.c<' | grep -oE '(event|prefork|worker)' | head -1)
    if [ "$actual_mpm" = "$MPM" ]; then
        printf "  PASS  MPM check: %s confirmed\n" "$MPM"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  MPM check: expected %s, got %s\n" "$MPM" "${actual_mpm:-empty}"
        FAIL=$((FAIL + 1))
    fi
    echo ""
fi

echo "--- Normal requests (expect 200) ---"
check "GET /"                          "$URL/"              200
check "GET /hello"                     "$URL/hello"         200
check "GET /page?name=john"            "$URL/page?name=john" 200
check_no_crash "Normal requests (expect 200)"
echo ""

echo "--- SQL injection (expect 403) ---"
check "SQLi: OR 1=1"                  "$URL/?id=1%20OR%201=1"                    403
check "SQLi: UNION SELECT"            "$URL/?id=1%20UNION%20SELECT%201,2,3"      403
check "SQLi: single quote"            "$URL/?name=admin%27%20OR%20%271%27=%271"  403
check "SQLi: DROP TABLE"              "$URL/?q=1;DROP%20TABLE%20users"            403
check_no_crash "SQL injection (expect 403)"
echo ""

echo "--- XSS (expect 403) ---"
check "XSS: script tag"               "$URL/?q=<script>alert(1)</script>"        403
check "XSS: img onerror"              "$URL/?q=<img%20src=x%20onerror=alert(1)>" 403
check "XSS: svg onload"               "$URL/?q=<svg%20onload=alert(1)>"          403
check_no_crash "XSS (expect 403)"
echo ""

echo "--- Path traversal / LFI (expect 403) ---"
check "LFI: etc/passwd"               "$URL/?file=../../../etc/passwd"           403
check "LFI: encoded dots"             "$URL/?file=..%2f..%2f..%2fetc%2fpasswd"  403
check_no_crash "Path traversal / LFI (expect 403)"
echo ""

echo "--- Remote command execution (expect 403) ---"
check "RCE: shell command"            "$URL/?cmd=;cat%20/etc/passwd"             403
check "RCE: pipe command"             "$URL/?cmd=|ls%20-la"                      403
check_no_crash "Remote command execution (expect 403)"
echo ""

echo "--- POST normal requests (expect 200) ---"
check_post "POST normal form"         "$URL/api" "name=john&age=30"              200
check_post "POST normal JSON"         "$URL/api" '{"user":"john","action":"login"}' 200
check_no_crash "POST normal requests (expect 200)"
echo ""

echo "--- POST SQL injection (expect 403) ---"
check_post "POST SQLi: OR 1=1"        "$URL/api" "id=1 OR 1=1"                  403
check_post "POST SQLi: UNION SELECT"  "$URL/api" "id=1 UNION SELECT 1,2,3"      403
check_post "POST SQLi: DROP TABLE"    "$URL/api" "q=1;DROP TABLE users"          403
check_no_crash "POST SQL injection (expect 403)"
echo ""

echo "--- POST XSS (expect 403) ---"
check_post "POST XSS: script tag"     "$URL/api" "q=<script>alert(1)</script>"   403
check_post "POST XSS: img onerror"    "$URL/api" "q=<img src=x onerror=alert(1)>" 403
check_no_crash "POST XSS (expect 403)"
echo ""

echo "--- POST RCE (expect 403) ---"
check_post "POST RCE: shell cmd"      "$URL/api" "cmd=;cat /etc/passwd"          403
check_post "POST RCE: pipe cmd"       "$URL/api" "cmd=|ls -la"                   403
check_no_crash "POST RCE (expect 403)"
echo ""

echo "--- PUT body tests (clean=405: WAF passes, Apache rejects method) ---"
check_method "PUT normal form"              "PUT" "$URL/api" "name=john&age=30"              405
check_method "PUT SQLi: OR 1=1"             "PUT" "$URL/api" "id=1 OR 1=1"                  403
check_method "PUT XSS: script tag"          "PUT" "$URL/api" "q=<script>alert(1)</script>"   403
check_method "PUT RCE: shell cmd"           "PUT" "$URL/api" "cmd=;cat /etc/passwd"          403
check_method "PUT Phase 2: deny body"       "PUT" "$URL/phase2" "PHASE2ATTACK"               403
check_method "PUT Phase 2: pass clean"      "PUT" "$URL/phase2" "cleandata"                  405
check_method_large "PUT body limit reject"  "PUT" "$URL/bodylimit-reject/" 200               413
check_method "PUT body limit partial"       "PUT" "$URL/bodylimit-partial/" "id=1 OR 1=1"    403
check_no_crash "PUT body tests (clean=405: WAF passes, Apache rejects method)"
echo ""

echo "--- DELETE body tests (clean=405: WAF passes, Apache rejects method) ---"
check_method "DELETE normal form"           "DELETE" "$URL/api" "name=john&age=30"            405
check_method "DELETE SQLi: OR 1=1"          "DELETE" "$URL/api" "id=1 OR 1=1"                403
check_method "DELETE XSS: script tag"       "DELETE" "$URL/api" "q=<script>alert(1)</script>" 403
check_method "DELETE RCE: shell cmd"        "DELETE" "$URL/api" "cmd=;cat /etc/passwd"        403
check_method "DELETE Phase 2: deny body"    "DELETE" "$URL/phase2" "PHASE2ATTACK"             403
check_method "DELETE Phase 2: pass clean"   "DELETE" "$URL/phase2" "cleandata"                405
check_method_large "DELETE body limit reject" "DELETE" "$URL/bodylimit-reject/" 200           413
check_method "DELETE body limit partial"    "DELETE" "$URL/bodylimit-partial/" "id=1 OR 1=1"  403
check_no_crash "DELETE body tests (clean=405: WAF passes, Apache rejects method)"
echo ""

echo "--- <Directory> tests ---"
check "Dir: normal allowed"           "$URL/dir-protected/"                       200
check "Dir: custom rule blocks"       "$URL/dir-protected/?block=yes"             403
check "Dir: custom rule allows"       "$URL/dir-protected/?block=no"              200
check "Dir: Coraza Off normal"        "$URL/dir-disabled/"                        200
check "Dir: Coraza Off SQLi pass"     "$URL/dir-disabled/?id=1%20OR%201=1"        200
check_no_crash "<Directory> tests"
echo ""

echo "--- .htaccess tests ---"
check "htaccess: normal allowed"      "$URL/htaccess-protected/"                  200
check "htaccess: custom rule blocks"  "$URL/htaccess-protected/?block=yes"        403
check "htaccess: Coraza Off normal"   "$URL/htaccess-disabled/"                   200
check "htaccess: Coraza Off SQLi"     "$URL/htaccess-disabled/?id=1%20OR%201=1"   200
check_no_crash ".htaccess tests"
echo ""

echo "--- Config inheritance (CRS rules in Directory/.htaccess) ---"
check "Dir: CRS SQLi inherited"       "$URL/dir-protected/?id=1%20OR%201=1"       403
check "htaccess: CRS SQLi inherited"  "$URL/htaccess-protected/?id=1%20OR%201=1"  403
check_post "Dir: POST body RCE"       "$URL/dir-protected/" "cmd=;cat /etc/passwd" 403
check_no_crash "Config inheritance (CRS rules in Directory/.htaccess)"
echo ""

echo "--- Per-phase tests (1+2) ---"
check "Phase 1: deny on ARGS"         "$URL/phase1?action=block403"               403
check "Phase 1: pass clean"           "$URL/phase1?action=safe"                   200
check_post "Phase 2: deny on body"    "$URL/phase2" "PHASE2ATTACK"                403
check_post "Phase 2: pass clean"      "$URL/phase2" "cleandata"                   200
check_no_crash "Per-phase tests (1+2)"
echo ""

echo "--- Source contract: libcoraza strings are released through libcoraza ---"
# coraza_new_waf() hands back a Go-allocated reason string on failure. Both
# call sites must release it with coraza_free_string() (never libc free(),
# allocator mismatch), and the symbol must be bound as required.
check_source "coraza_free_string is bound as a required symbol" mod_coraza_dl.c 'DL_SYM\(dl_free_string, *coraza_free_string\)'
check_source_in_func "build_waf releases the coraza_new_waf error string" mod_coraza.c coraza_build_waf 'coraza_free_string\(error\)'
check_source_in_func "empty-WAF fallback releases the coraza_new_waf error string" mod_coraza.c coraza_child_init 'coraza_free_string\(err\)'
check_source "no libc free() on a libcoraza string" mod_coraza.c '(^|[^[:alnum:]_])free[[:space:]]*\([[:space:]]*(error|err)[[:space:]]*\)' !
echo ""

echo "--- Request protocol tests ---"
# REQUEST_PROTOCOL must reach Coraza slash-delimited ("HTTP/1.1"), not bare "1.1".
check_curl "Protocol: HTTP/1.1 matches REQUEST_PROTOCOL" "$URL/protocol-check" 403
check_curl "Protocol: HTTP/1.0 does not match"           "$URL/protocol-check" 200 --http1.0
# A version Apache does not recognise must reach REQUEST_PROTOCOL as it arrived.
# Before the fix r->proto_num was mapped through an enum whose default is
# HTTP/1.1, so HTTP/4.0 was indistinguishable from a normal request: the raw
# rule could not match (200 instead of 406) and CRS 920430 could not enforce
# the version policy on / (200 instead of 403).
check_raw "Protocol: HTTP/4.0 reaches REQUEST_PROTOCOL verbatim" "/protocol-raw" "HTTP/4.0" 406
check_raw "Protocol: HTTP/1.1 does not trip the raw rule"       "/protocol-raw" "HTTP/1.1" 200
check_raw "Protocol: CRS 920430 rejects HTTP/4.0 on /"          "/"             "HTTP/4.0" 403
check_no_crash "Request protocol tests"
echo ""

echo "--- Large header inspection (length-narrowing guard) ---"
# A large but legal header must still reach the engine in full: the trigger sits
# at the very end of ~6 KB of padding, so a clipped length would miss it.
big_hdr="$(printf 'A%.0s' $(seq 1 6000))BOOMHEADER"
pad_hdr="$(printf 'A%.0s' $(seq 1 6000))"
check_curl "Large header: trigger at end is inspected" "$URL/header-check" 403 -H "X-Test: $big_hdr"
check_curl "Large header: padding only is not clipped" "$URL/header-check" 200 -H "X-Test: $pad_hdr"
check_no_crash "Large header inspection (length-narrowing guard)"
echo ""

echo "--- Response phase tests (3+4) ---"
check "Phase 3: deny on Content-Type"       "$URL/phase3"                          403
check "Phase 3: pass no match"              "$URL/phase3-pass"                     200
check "Phase 4: deny on body content"       "$URL/phase4"                          403
check "Phase 4: pass no match"              "$URL/phase4-pass"                     200
check_no_crash "Response phase tests (3+4)"
echo ""

echo "--- SSE streaming (header-delay skip) ---"
# text/event-stream never sends EOS; the header delay must be skipped or the
# client receives nothing. Near-miss media types must stay delayed, and a
# phase-1 rule must still block (the exemption must not become a WAF bypass).
check_stream "SSE: stream reaches client (not delayed)"   "$URL/sse-stream"          "data: tick" present
check_stream "SSE near-miss: text/event-streamx delayed"  "$URL/sse-nearmiss"        "data: tick" absent
check_curl   "SSE: phase-1 rule still blocks (no bypass)" "$URL/sse-stream?attack=1" 403 --max-time 5
check_no_crash "SSE streaming (header-delay skip)"
echo ""

echo "--- Delayed response cap (bound worker memory) ---"
# A large delayed response must arrive intact: the cap flushes headers early
# and streams the rest rather than buffering the whole body (or truncating it).
check      "Large delayed response: completes 200"    "$URL/bulk-delayed"  200
check_size "Large delayed response: full 4 MiB body"  "$URL/bulk-delayed"  4194304
check_no_crash "Delayed response cap (bound worker memory)"
echo ""

echo "--- Config merging tests ---"
check "Engine off: SQLi passes"       "$URL/merge-engine-off/?id=1%20OR%201=1"    200
check "Engine off: normal passes"     "$URL/merge-engine-off/"                    200
check_post "Body off: SQLi passes"    "$URL/merge-bodyaccess-off/" "id=1 OR 1=1"  200
check "Inherited: CRS blocks SQLi"    "$URL/merge-inherited/?id=1%20OR%201=1"     403
check "Inherited: local rule blocks"  "$URL/merge-inherited/?localonly=yes"        403
check "Inherited: local rule passes"  "$URL/merge-inherited/?localonly=no"         200
check_no_crash "Config merging tests"
echo ""

echo "--- Request body limit tests ---"
check_post "Reject: small body OK"    "$URL/bodylimit-reject/" "short"            200
check_post_large "Reject: large body" "$URL/bodylimit-reject/" 200               413
check_post_large "Reject: at-limit"   "$URL/bodylimit-reject/" 127               200
check_post "Partial: small body OK"   "$URL/bodylimit-partial/" "short"           200
check_post_large "Partial: large OK"  "$URL/bodylimit-partial/" 200              200
check_post "Partial: attack found"    "$URL/bodylimit-partial/" "id=1 OR 1=1"     403
check_no_crash "Request body limit tests"
echo ""

echo "--- Inherited body limit tests ---"
check_method_large "Inherited: GET large blocked"    "GET"    "$URL/bodylimit-inherited/" 200 413
check_method_large "Inherited: POST large blocked"   "POST"   "$URL/bodylimit-inherited/" 200 413
check_method_large "Inherited: PUT large blocked"    "PUT"    "$URL/bodylimit-inherited/" 200 413
check_method_large "Inherited: DELETE large blocked"  "DELETE" "$URL/bodylimit-inherited/" 200 413
check_method_large "Override: larger limit passes"   "POST"   "$URL/bodylimit-override/" 200  200
check_no_crash "Inherited body limit tests"
echo ""

echo "--- Scoring tests ---"
check "Score abs: 1 arg pass"         "$URL/scoring-absolute?what=badarg1"        200
check "Score abs: 2 arg block"        "$URL/scoring-absolute?what=badarg2"        403
check "Score iter: 1 arg pass"        "$URL/scoring-iterative?a=badarg1"          200
check "Score iter: 2 args pass"       "$URL/scoring-iterative?a=badarg1&b=badarg2" 200
check "Score iter: 3 args block"      "$URL/scoring-iterative?a=badarg1&b=badarg2&c=badarg3" 403
check_no_crash "Scoring tests"
echo ""

echo "--- Transaction ID tests ---"
check "TxID: block works"             "$URL/txid-test?action=block"               403
check "TxID: pass works"              "$URL/txid-test?action=safe"                200
check_no_crash "Transaction ID tests"
echo ""

echo "--- Non-403 status code tests ---"
check "401: deny blocks"                "$URL/deny-401?action=block"               401
check "401: pass clean"                 "$URL/deny-401?action=safe"                200
check "401: CRS SQLi still 403"         "$URL/deny-401?id=1%20OR%201=1"            403
check_no_crash "Non-403 status code tests"
echo ""

echo "--- Location rule isolation tests ---"
check "Isolated-A: trigger=a blocks"    "$URL/isolated-a?trigger=a"                403
check "Isolated-A: trigger=b passes"    "$URL/isolated-a?trigger=b"                200
check "Isolated-A: clean passes"        "$URL/isolated-a?trigger=x"                200
check "Isolated-B: trigger=b blocks"    "$URL/isolated-b?trigger=b"                403
check "Isolated-B: trigger=a passes"    "$URL/isolated-b?trigger=a"                200
check "Isolated-B: clean passes"        "$URL/isolated-b?trigger=x"                200
check_no_crash "Location rule isolation tests"
echo ""

echo "--- Custom error page tests ---"
check_body "Error page: 403 body"       "$URL/errorpage-test?action=block"         403 "CORAZA_CUSTOM_ERROR_PAGE"
check_body "Error page: 401 body"       "$URL/errorpage-401?action=block"          401 "CORAZA_CUSTOM_ERROR_PAGE"
check_body "Error page: CRS block body" "$URL/?id=1%20OR%201=1"                    403 "CORAZA_CUSTOM_ERROR_PAGE"
check_body "Error page: pass no error"  "$URL/errorpage-test?action=safe"          200 "CORAZA_CUSTOM_ERROR_PAGE" "!"
check_body "Error page: clean 200 body" "$URL/"                                    200 "OK"
# The error page location carries a phase-4 rule matching the page's own body.
# Served for a request this transaction already denied, the page must come
# back untouched (the transaction is reused across the internal redirect and
# does not deny twice); requested directly, the rule must fire -- proving it is
# live and only the error-document path is exempt.
check_body "Error page: served untouched though a phase-4 rule matches its body (issue #40)" \
    "$URL/errorpage-test?action=block&tag=errdoc" 403 "CORAZA_CUSTOM_ERROR_PAGE"
check "Error page: the same phase-4 rule fires on a direct request (control)" \
    "$URL/custom-error.html" 500
check_no_crash "Custom error page tests"
echo ""

echo "--- Redirect tests ---"
check_redirect "302 redirect: status + Location"  "$URL/redirect-302?target=redirect"  302 "http://www.coraza.io"
check_redirect "301 redirect: status + Location"  "$URL/redirect-301?target=redirect"  301 "http://www.coraza.io"
check "302 redirect: clean passes"                 "$URL/redirect-302?target=safe"      200
check "301 redirect: clean passes"                 "$URL/redirect-301?target=safe"      200
check_no_crash "Redirect tests"
echo ""

echo "--- Response header guards ---"
# Regression guards for the response-header hardening series (#72/#77):
#   - HEAD must not be held waiting for phase 4 (no body/EOS) -- returns promptly.
#   - A clean redirect emits exactly the intended Location, nothing smuggled.
check_head   "HEAD /: not delayed, returns 200"          "$URL/"                              200
check_header "Redirect: Location is exactly the target"  "$URL/redirect-302?target=redirect"  "Location" "http://www.coraza.io"
check_header "Redirect: clean path+query preserved"      "$URL/redirect-clean-path?target=redirect" "Location" "http://example.org/clean/path?a=b"
check_header "Clean response: no smuggled Set-Cookie"    "$URL/"                              "Set-Cookie" "" "!"
check_no_crash "Response header guards"
echo ""

echo "--- VirtualHost isolation tests ---"
check_vhost "VHost-off: normal request"      "vhost-off.test"    "$URL/"                              200
check_vhost "VHost-off: SQLi passes"         "vhost-off.test"    "$URL/?id=1%20OR%201=1"              200
check_vhost "VHost-off: XSS passes"          "vhost-off.test"    "$URL/?q=<script>alert(1)</script>"  200
check_vhost "VHost-custom: normal request"   "vhost-custom.test" "$URL/"                              200
check_vhost "VHost-custom: rule blocks"      "vhost-custom.test" "$URL/?vhaction=block"               403
check_vhost "VHost-custom: rule passes"      "vhost-custom.test" "$URL/?vhaction=safe"                200
check_vhost "VHost-custom: CRS SQLi blocked"  "vhost-custom.test" "$URL/?id=1%20OR%201=1"              403
check "Main server: SQLi still blocked"      "$URL/?id=1%20OR%201=1"                                  403
check_no_crash "VirtualHost isolation tests"
echo ""

# Audit log tests (require --container)
# --- Request body reaches the handler (issue #34) ---
# The fixups hook consumes the body to inspect it; CORAZA_IN must replay the
# copy to the handler. The echo CGI reports what it actually received.
echo "--- Request body reaches the handler (issue #34) ---"
check_post_body "POST JSON body is delivered to the handler" \
    "$URL/echo" "application/json" '{"body": "hello"}' 200 'BODY=\[{"body": "hello"}\]'
# A 20 KB body spans several 8 KiB fixups reads: the replay must hand over
# every bucket, in order, and then the EOS. Sent as a form post because CRS's
# default allowed_request_content_type list does not include text/plain.
big="data=$(head -c 20000 /dev/zero | tr '\0' 'A')"
check_post_body "POST 20 KB body is delivered intact" \
    "$URL/echo" "application/x-www-form-urlencoded" "$big" 200 'BODY=\[data=A\{20000\}\]'
# Once the replay is exhausted the filter must delegate, not return APR_EOF:
# ap_discard_request_body() turns any non-success into a 400, which would
# replace the 405 default_handler gives a PUT to a static file.
check_method "PUT static file with body: 405, not 400" \
    PUT "$URL/dir-protected/index.html" 'x=1' 405
# A 300 KB upload crosses CorazaRequestBodyInMemoryLimit (64 KiB on /echo in
# the test config, 128 KiB by default): the head is replayed from memory and
# the tail from the spool file. Markers at both ends prove ordering; the exact
# size check in check_upload_body proves every byte reached the handler.
upload=$(mktemp)
{ printf 'SPOOL-HEAD'; head -c 300000 /dev/zero | tr '\0' 'B'; printf 'SPOOL-TAIL'; } > "$upload"
check_upload_body "POST 300 KB multipart upload is delivered intact (spooled)" \
    "$URL/echo" "$upload" 200 'SPOOL-HEADB*SPOOL-TAIL'
rm -f "$upload"
check_no_crash "Request body reaches the handler (issue #34)"
echo ""

if [ -n "$CONTAINER" ]; then
    echo "--- Config validation: ruleless \"Coraza On\" is rejected (issue #39) ---"
    # "Coraza On" with no rule directive anywhere must fail httpd -t rather
    # than start an empty WAF; one rule anywhere makes it pass, and "Coraza
    # Off" without rules is not an error.
    check_config_validation "Coraza On with no rules fails validation" \
        'Coraza On' 1 'requires at least one rule directive'
    check_config_validation "Coraza On with one rule passes validation" \
        'Coraza On
CorazaRules "SecRuleEngine On"' 0 'Syntax OK'
    check_config_validation "Coraza Off with no rules passes validation" \
        'Coraza Off' 0 'Syntax OK'
    echo ""

    echo "--- Config validation: SecRemoteRules is rejected at httpd -t (issue #62) ---"
    # The engine does not implement SecRemoteRules and rules only reach it in
    # child_init, so without this check httpd -t passes and every child dies.
    # Native directive, CorazaRules text and CorazaRulesFile content are all
    # covered; records are assembled the way coraza's parser does it.
    docker exec "$CONTAINER" sh -c '
        printf "%s\n" "SecRuleEngine On" "# a comment line, then the offending directive" \
            "    secRemoteRules https://example.org/rules.conf" > /tmp/remote.rules
        printf "%s\n" "SecRuleEngine On" "SecRemoteRul\\" "    es https://example.org/rules.conf" > /tmp/split.rules
        { printf "%s\n" "SecRuleEngine On"
          printf "SecRule ARGS \"@rx %s\" \"id:1,phase:1,pass\"\n" "$(head -c 5000 /dev/zero | tr "\0" a)"
          i=0; while [ $i -lt 800 ]; do printf "# filler\n"; i=$((i+1)); done
          printf "SecRemoteRules https://example.org/rules.conf"; } > /tmp/big.rules
        printf "%s\n" "SecRuleEngine On" \
            "# SecRemoteRules https://example.org/rules.conf   -- commented out" \
            "SecRemoteRulesFailAction Abort" \
            "SecRemoteRulesX not-a-real-directive-but-not-ours-to-refuse" \
            "SecRule ARGS \"@rx foo\" \\" \
            "    # a comment inside a continued record is ignored, the record goes on" \
            "" \
            "SecRemoteRules https://example.org/rules.conf is only text in this msg\" \\" \
            "    \"id:2,phase:1,pass\"" \
            "SecRule ARGS \"@rx bar\" \`" \
            "SecRemoteRules https://example.org/rules.conf" \
            "    id:3,phase:1,pass" \
            "\`" > /tmp/ok.rules
        printf "%s\n" "SecRuleEngine On" "SecRemoteRules https://example.org/rules.conf \`" "  id:4" > /tmp/open.rules
        cp /tmp/remote.rules /usr/local/apache2/conf/remote-rel.rules'
    check_config_validation "native SecRemoteRules directive fails validation" \
        'Coraza On
SecRemoteRules https://example.org/rules.conf' 1 '"SecRemoteRules" is not implemented by the Coraza engine'
    check_config_validation "SecRemoteRules inside CorazaRules text fails validation" \
        'Coraza On
CorazaRules "SecRemoteRules https://example.org/rules.conf"' 1 '"SecRemoteRules" is not implemented'
    check_config_validation "SecRemoteRules in a rules file fails validation, with file and line" \
        'Coraza On
CorazaRulesFile /tmp/remote.rules' 1 '"SecRemoteRules" (/tmp/remote.rules:3) is not implemented'
    check_config_validation "SecRemoteRules split by a line continuation is still caught" \
        'Coraza On
CorazaRulesFile /tmp/split.rules' 1 '"SecRemoteRules" (/tmp/split.rules:2) is not implemented'
    check_config_validation "SecRemoteRules past the 4 KiB read buffer, no trailing newline" \
        'Coraza On
CorazaRulesFile /tmp/big.rules' 1 '"SecRemoteRules" (/tmp/big.rules:803) is not implemented'
    check_config_validation "SecRemoteRules opening an unclosed backtick list is still caught" \
        'Coraza On
CorazaRulesFile /tmp/open.rules' 1 '"SecRemoteRules" (/tmp/open.rules:2) is not implemented'
    check_config_validation "relative rules file path resolves against ServerRoot" \
        'Coraza On
CorazaRulesFile conf/remote-rel.rules' 1 '(/usr/local/apache2/conf/remote-rel.rules:3) is not implemented'
    check_config_validation "commented, continued and backtick-quoted SecRemoteRules text passes" \
        'Coraza On
CorazaRulesFile /tmp/ok.rules' 0 'Syntax OK'
    check_config_validation "SecRemoteRulesFailAction is still accepted" \
        'Coraza On
SecRemoteRulesFailAction Abort' 0 'Syntax OK'
    echo ""

    echo "--- Delayed response cap log ---"
    # The large delayed response above must have tripped the cap's early flush.
    check_container_log "Cap: flushed delayed headers early"  "flushing headers early"
    check_no_crash "Delayed response cap log"
    echo ""

    echo "--- Audit log tests ---"
    # Generate a blocked request that will appear in audit log
    clear_audit_log
    curl -s -o /dev/null "$URL/?audit_test=1%20OR%201=1"
    # Give Apache a moment to flush the log
    sleep 1
    check_audit_log "Blocked request logged"   "audit_test"
    check_audit_log "Contains request URI"     "GET /"
    check_audit_log "Contains section A"       "\-A\-\-"
    check_audit_log "Contains section B"       "\-B\-\-"
    check_audit_log "Contains section H"       "\-H\-\-"
    check_no_crash "Audit log tests"
    echo ""

    echo "--- Error page audit (issue #40) ---"
    # One client request, denied, served an ErrorDocument through an internal
    # redirect: one transaction, one audit entry -- not one per request_rec.
    # The log is cleared first, so the count is of entries, not of a tag.
    clear_audit_log
    curl -s -o /dev/null "$URL/errorpage-test?action=block&tag=errdoc-once"
    sleep 1
    check_audit_count "Error page: exactly one audit entry for the denied request" "^GET " 1
    check_no_crash "Error page audit"
    echo ""

    echo "--- Transaction ID audit log tests ---"
    clear_audit_log
    curl -s -o /dev/null "$URL/txid-test?action=block"
    sleep 1
    check_audit_log "TxID: ID in audit log"    "TESTID-APACHE-001"
    check_audit_log "TxID: URI in audit log"   "txid-test"
    check_no_crash "Transaction ID audit log tests"
    echo ""

    echo "--- Debug log per-location isolation tests ---"
    clear_debug_logs
    curl -s -o /dev/null "$URL/debuglog-root?what=root"
    curl -s -o /dev/null "$URL/debuglog-sub1?what=sub1"
    curl -s -o /dev/null "$URL/debuglog-sub2?what=sub2"
    sleep 1
    check_debug_log "DebugLog: root.log written" "/var/log/coraza/debug/root.log" "30001"
    check_debug_log "DebugLog: sub1.log written" "/var/log/coraza/debug/sub1.log" "30002"
    check_debug_log "DebugLog: sub2.log written" "/var/log/coraza/debug/sub2.log" "30003"
    check_no_crash "Debug log per-location isolation tests"
    echo ""

    echo "--- Per-location audit log isolation tests ---"
    clear_perloc_audit_logs
    curl -s -o /dev/null "$URL/auditlog-root?what=root"
    curl -s -o /dev/null "$URL/auditlog-sub1?what=sub1"
    curl -s -o /dev/null "$URL/auditlog-sub1/sub2?what=sub2"
    curl -s -o /dev/null "$URL/auditlog-sub1/sub2?what=sub1"
    curl -s -o /dev/null "$URL/auditlog-sub3?what=sub3"
    curl -s -o /dev/null "$URL/auditlog-sub3/sub4?what=sub4"
    curl -s -o /dev/null "$URL/auditlog-sub3/sub4?what=sub3"
    curl -s -o /dev/null "$URL/auditlog-sub3/sub4?what=sub4withE"
    sleep 1
    check_perloc_audit_log "AuditLog: root.log has root req"        "/var/log/coraza/audit/root.log" "what=root"
    check_perloc_audit_log "AuditLog: sub1.log has sub1 req"        "/var/log/coraza/audit/sub1.log" "what=sub1"
    check_perloc_audit_log "AuditLog: sub2.log has sub2 req"        "/var/log/coraza/audit/sub2.log" "what=sub2"
    check_perloc_audit_log "AuditLog: sub2.log has inherited sub1"  "/var/log/coraza/audit/sub2.log" "what=sub1"
    check_perloc_audit_log "AuditLog: sub3.log has sub3 req"        "/var/log/coraza/audit/sub3.log" "what=sub3"
    check_perloc_audit_log "AuditLog: sub4.log has sub4 req"        "/var/log/coraza/audit/sub4.log" "what=sub4"
    check_perloc_audit_log "AuditLog: sub4.log has inherited sub3"  "/var/log/coraza/audit/sub4.log" "what=sub3"
    check_perloc_audit_log "AuditLog: sub4.log has sub4withE req"   "/var/log/coraza/audit/sub4.log" "what=sub4withE"
    check_perloc_audit_log "AuditLog: sub4.log has E section"       "/var/log/coraza/audit/sub4.log" "\-E\-\-"
    check_no_crash "Per-location audit log isolation tests"
    echo ""

    echo "--- auditlog action with RelevantOnly tests ---"
    clear_perloc_audit_logs
    # trigger=yes should match the rule and set auditlog flag
    curl -s -o /dev/null "$URL/auditlog-relevant?trigger=yes"
    # trigger=no should NOT match the rule, no auditlog flag
    curl -s -o /dev/null "$URL/auditlog-relevant?trigger=no"
    # noauditlog: trigger=yes matches but auditlog flag is cleared
    curl -s -o /dev/null "$URL/auditlog-relevant-nolog?trigger=yes"
    sleep 1
    check_perloc_audit_log "RelevantOnly: trigger=yes logged"          "/var/log/coraza/audit/relevant.log" "trigger=yes"
    check_perloc_audit_log_absent "RelevantOnly: trigger=no NOT logged"    "/var/log/coraza/audit/relevant.log" "trigger=no"
    check_perloc_audit_log_absent "noauditlog: trigger=yes NOT logged"     "/var/log/coraza/audit/relevant-nolog.log" "trigger=yes"
    check_no_crash "auditlog action with RelevantOnly tests"
    echo ""

    echo "--- Crash sweep self-test ---"
    # The sweep is only worth having if it actually fires: write a fake MPM
    # worker-exit line to httpd's stderr (PID 1's fd 2 is the ErrorLog) and
    # require the next sweep to report it. The counter is then advanced so the
    # injected line does not fail any later sweep.
    docker exec "$CONTAINER" sh -c 'echo "[$(date)] [mpm_event:notice] [pid 1] AH00052: child pid 99999 exit signal Segmentation fault (11) (injected by test.sh self-test)" > /proc/1/fd/2'
    sleep 1
    if ! lines=$(crash_lines); then
        printf "  FAIL  Crash sweep self-test: docker logs unreadable\n"
        FAIL=$((FAIL + 1))
    elif [ "$(printf '%s' "$lines" | grep -c .)" -gt "$CRASH_SEEN" ]; then
        printf "  PASS  Crash sweep self-test: injected worker-exit line is detected\n"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  Crash sweep self-test: injected worker-exit line NOT detected\n"
        FAIL=$((FAIL + 1))
    fi
    CRASH_SEEN=$(printf '%s' "$lines" | grep -c .)
    echo ""
else
    echo "--- Config validation tests (skipped: use --container=NAME) ---"
    echo "--- Audit log tests (skipped: use --container=NAME) ---"
    echo "--- Error page audit (skipped: use --container=NAME) ---"
    echo "--- Transaction ID audit log tests (skipped: use --container=NAME) ---"
    echo "--- Debug log per-location isolation tests (skipped: use --container=NAME) ---"
    echo "--- Per-location audit log isolation tests (skipped: use --container=NAME) ---"
    echo "--- auditlog action with RelevantOnly tests (skipped: use --container=NAME) ---"
    echo ""
fi

echo "=============================="
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && echo "All tests passed." || echo "Some tests FAILED."
exit "$FAIL"
