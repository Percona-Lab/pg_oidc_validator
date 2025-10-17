# contrib/pg_oidc_validator/Makefile

OBJS = \
	src/pg_oidc_validator.o \
	src/http_client.o \
	src/jwk.o

MODULE_big = pg_oidc_validator

EXTENSION = pg_oidc_validator
PGFILEDESC = "pg_oidc_validator - OAuth token validation for PostgreSQL"

PG_CPPFLAGS = -Ijwt-cpp/include -std=c++23

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

override SHLIB_LINK += -lcurl

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(PG_CPPFLAGS) -c -o $@ $<
