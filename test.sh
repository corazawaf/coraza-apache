#!/bin/sh

# Parse arguments
URL=""
MPM=""
for arg in "$@"; do
    case "$arg" in
        --mpm=*) MPM="${arg#--mpm=}" ;;
        *)       URL="$arg" ;;
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

check_post() {
    desc="$1"
    url="$2"
    body="$3"
    expected="$4"

    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "$body" "$url")
    if [ "$code" = "$expected" ]; then
        printf "  PASS  %s -> %s\n" "$desc" "$code"
        PASS=$((PASS + 1))
    else
        printf "  FAIL  %s -> %s (expected %s)\n" "$desc" "$code" "$expected"
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
echo ""

echo "--- SQL injection (expect 403) ---"
check "SQLi: OR 1=1"                  "$URL/?id=1%20OR%201=1"                    403
check "SQLi: UNION SELECT"            "$URL/?id=1%20UNION%20SELECT%201,2,3"      403
check "SQLi: single quote"            "$URL/?name=admin%27%20OR%20%271%27=%271"  403
check "SQLi: DROP TABLE"              "$URL/?q=1;DROP%20TABLE%20users"            403
echo ""

echo "--- XSS (expect 403) ---"
check "XSS: script tag"               "$URL/?q=<script>alert(1)</script>"        403
check "XSS: img onerror"              "$URL/?q=<img%20src=x%20onerror=alert(1)>" 403
check "XSS: svg onload"               "$URL/?q=<svg%20onload=alert(1)>"          403
echo ""

echo "--- Path traversal / LFI (expect 403) ---"
check "LFI: etc/passwd"               "$URL/?file=../../../etc/passwd"           403
check "LFI: encoded dots"             "$URL/?file=..%2f..%2f..%2fetc%2fpasswd"  403
echo ""

echo "--- Remote command execution (expect 403) ---"
check "RCE: shell command"            "$URL/?cmd=;cat%20/etc/passwd"             403
check "RCE: pipe command"             "$URL/?cmd=|ls%20-la"                      403
echo ""

echo "--- POST normal requests (expect 200) ---"
check_post "POST normal form"         "$URL/api" "name=john&age=30"              200
check_post "POST normal JSON"         "$URL/api" '{"user":"john","action":"login"}' 200
echo ""

echo "--- POST SQL injection (expect 403) ---"
check_post "POST SQLi: OR 1=1"        "$URL/api" "id=1 OR 1=1"                  403
check_post "POST SQLi: UNION SELECT"  "$URL/api" "id=1 UNION SELECT 1,2,3"      403
check_post "POST SQLi: DROP TABLE"    "$URL/api" "q=1;DROP TABLE users"          403
echo ""

echo "--- POST XSS (expect 403) ---"
check_post "POST XSS: script tag"     "$URL/api" "q=<script>alert(1)</script>"   403
check_post "POST XSS: img onerror"    "$URL/api" "q=<img src=x onerror=alert(1)>" 403
echo ""

echo "--- POST RCE (expect 403) ---"
check_post "POST RCE: shell cmd"      "$URL/api" "cmd=;cat /etc/passwd"          403
check_post "POST RCE: pipe cmd"       "$URL/api" "cmd=|ls -la"                   403
echo ""

echo "--- <Directory> tests ---"
check "Dir: normal allowed"           "$URL/dir-protected/"                       200
check "Dir: custom rule blocks"       "$URL/dir-protected/?block=yes"             403
check "Dir: custom rule allows"       "$URL/dir-protected/?block=no"              200
check "Dir: Coraza Off normal"        "$URL/dir-disabled/"                        200
check "Dir: Coraza Off SQLi pass"     "$URL/dir-disabled/?id=1%20OR%201=1"        200
echo ""

echo "--- .htaccess tests ---"
check "htaccess: normal allowed"      "$URL/htaccess-protected/"                  200
check "htaccess: custom rule blocks"  "$URL/htaccess-protected/?block=yes"        403
check "htaccess: Coraza Off normal"   "$URL/htaccess-disabled/"                   200
check "htaccess: Coraza Off SQLi"     "$URL/htaccess-disabled/?id=1%20OR%201=1"   200
echo ""

echo "--- Config inheritance (CRS rules in Directory/.htaccess) ---"
check "Dir: CRS SQLi inherited"       "$URL/dir-protected/?id=1%20OR%201=1"       403
check "htaccess: CRS SQLi inherited"  "$URL/htaccess-protected/?id=1%20OR%201=1"  403
check_post "Dir: POST body RCE"       "$URL/dir-protected/" "cmd=;cat /etc/passwd" 403
echo ""

echo "=============================="
printf "Results: %d passed, %d failed\n" "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && echo "All tests passed." || echo "Some tests FAILED."
exit "$FAIL"
