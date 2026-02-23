APXS ?= apxs

SRC = src/mod_coraza.c src/mod_coraza_dl.c src/mod_coraza_phase1.c \
      src/mod_coraza_body_in.c src/mod_coraza_filter_out.c src/mod_coraza_log.c

all:
	$(APXS) -c -Isrc -I/usr/local/include -Wc,-std=c99 -Wl,-ldl $(SRC)

install: all
	$(APXS) -i -n coraza src/mod_coraza.la

clean:
	rm -rf src/.libs src/*.la src/*.lo src/*.o src/*.slo

.PHONY: all install clean
