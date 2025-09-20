# contrib/pg_oidc_validator/Makefile

OBJS = \
	src/pg_oidc_validator.o \
	src/http_client.o \
	src/jwk.o

MODULE_big = pg_oidc_validator

EXTENSION = pg_oidc_validator
PGFILEDESC = "pg_oidc_validator - OAuth token validation for PostgreSQL"

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_oidc_validator
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif

override CXXFLAGS += -std=c++23

override PG_CPPFLAGS += -Ijwt-cpp/include

SHLIB_LINK += -ljwt -lcurl

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<
