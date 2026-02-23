#!/bin/bash
set -e

httpd -k start
sleep 1

echo "=== Test 1: Normal request (expect 200) ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/)
if [ "$STATUS" = "200" ]; then
    echo "PASS: Got $STATUS"
else
    echo "FAIL: Expected 200, got $STATUS"
    exit 1
fi

echo "=== Test 2: Blocked URI (expect 403) ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/blocked)
if [ "$STATUS" = "403" ]; then
    echo "PASS: Got $STATUS"
else
    echo "FAIL: Expected 403, got $STATUS"
    exit 1
fi

echo "=== Test 3: Body inspection (expect 403) ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "this is an attack" http://localhost/body-test)
if [ "$STATUS" = "403" ]; then
    echo "PASS: Got $STATUS"
else
    echo "FAIL: Expected 403, got $STATUS"
    exit 1
fi

echo "=== Test 4: Clean body (expect 200/404) ==="
STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "hello world" http://localhost/body-test)
if [ "$STATUS" = "200" ] || [ "$STATUS" = "404" ]; then
    echo "PASS: Got $STATUS (not blocked)"
else
    echo "FAIL: Expected 200 or 404, got $STATUS"
    exit 1
fi

echo ""
echo "All tests passed!"
httpd -k stop
