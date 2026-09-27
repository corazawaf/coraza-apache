#!/bin/sh
# Image entrypoint. In a SANITIZE=1 build the module carries ASan + UBSan but
# httpd does not, so the sanitizer runtime has to be the first library in the
# server process: preload it, with leak detection off (every CGI child would
# otherwise report at exit) and reports on stderr, where `docker logs` and the
# suite's crash sweep read them (issue #55).
if [ "${CORAZA_SANITIZE:-0}" = "1" ]; then
    asan=$(ls /usr/lib/*-linux-gnu/libasan.so.* 2>/dev/null | head -1)
    [ -n "$asan" ] && export LD_PRELOAD="$asan"
    export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=0:verify_asan_link_order=0:halt_on_error=1:abort_on_error=0}"
    export UBSAN_OPTIONS="${UBSAN_OPTIONS:-print_stacktrace=1:halt_on_error=0}"
fi
exec "$@"
