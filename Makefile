APXS ?= apxs

SRC = src/mod_coraza.c src/mod_coraza_dl.c src/mod_coraza_phase1.c \
      src/mod_coraza_body_in.c src/mod_coraza_filter_out.c src/mod_coraza_log.c

# make SANITIZE=1: build the module with ASan + UBSan (issue #55). ASan errors
# are fatal, UBSan reports and recovers; nullability checks are off, as in
# coraza-nginx, because APR/httpd trip benign memcpy(dst, NULL, 0) cases that
# are not ours. httpd itself is not instrumented, so the runtime must be
# preloaded into the server process (the Docker image does that when built
# with --build-arg SANITIZE=1).
# The Docker build exports SANITIZE as an environment variable (0 or 1), so
# test for the value, not for non-emptiness.
SANITIZE ?= 0
ifeq ($(SANITIZE),1)
SAN_CC = -Wc,-fsanitize=address,undefined -Wc,-fno-sanitize=nonnull-attribute,null \
         -Wc,-fno-sanitize-recover=address -Wc,-fno-omit-frame-pointer -Wc,-g -Wc,-O1
SAN_LD = -Wl,-fsanitize=address,undefined
endif

all:
	$(APXS) -c -Isrc -I/usr/local/include -Wc,-std=c99 $(SAN_CC) -Wl,-ldl $(SAN_LD) $(SRC)

install: all
	$(APXS) -i -n coraza src/mod_coraza.la

clean:
	rm -rf src/.libs src/*.la src/*.lo src/*.o src/*.slo

.PHONY: all install clean
