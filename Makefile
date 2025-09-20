# contrib/pg_oauth/Makefile

OBJS = \
	src/pg_oauth.o \
	src/http_client.o \
	src/jwk.o

MODULE_big = pg_oauth

EXTENSION = pg_oauth
PGFILEDESC = "pg_oauth - OAuth token validation for PostgreSQL"

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_oauth
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

override CXXFLAGS += -std=c++23

override PG_CPPFLAGS += -Ijwt-cpp/include

SHLIB_LINK += -ljwt -lcurl

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<
