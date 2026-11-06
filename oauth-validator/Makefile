MODULES = pg_appsec_oauth
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs 2>/dev/null)

# Always use the vendored ABI shim so we do not pull GSSAPI via libpq/oauth.h.
PG_CPPFLAGS += -I. -DUSE_OAUTH_ABI_HEADER
SHLIB_LINK += -lssl -lcrypto

ifdef PGXS
include $(PGXS)
else
CC ?= gcc
CFLAGS ?= -fPIC -Wall -O2 -fvisibility=hidden
pg_appsec_oauth.so: pg_appsec_oauth.c oauth_abi.h
	$(CC) $(CFLAGS) -shared -o $@ pg_appsec_oauth.c $(PG_CPPFLAGS) $(SHLIB_LINK)
clean:
	rm -f pg_appsec_oauth.so *.o oauth_client
endif
