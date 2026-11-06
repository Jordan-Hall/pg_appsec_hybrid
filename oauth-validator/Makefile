MODULES = pg_appsec_oauth
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs 2>/dev/null)

# Prefer in-tree ABI shim only when server oauth.h is unavailable.
HAVE_OAUTH_H := $(shell test -f $$($(PG_CONFIG) --includedir-server)/libpq/oauth.h && echo yes || echo no)
ifeq ($(HAVE_OAUTH_H),yes)
PG_CPPFLAGS += -I.
else
PG_CPPFLAGS += -I. -DUSE_OAUTH_ABI_HEADER
endif

SHLIB_LINK += -lssl -lcrypto

ifdef PGXS
include $(PGXS)
else
CC ?= gcc
CFLAGS ?= -fPIC -Wall -O2
pg_appsec_oauth.so: pg_appsec_oauth.c oauth_abi.h
	$(CC) $(CFLAGS) -shared -fvisibility=hidden -o $@ pg_appsec_oauth.c $(PG_CPPFLAGS) $(SHLIB_LINK)
clean:
	rm -f pg_appsec_oauth.so *.o oauth_client
endif
