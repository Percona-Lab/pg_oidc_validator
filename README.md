# pg\_oauth

Experimental OAuth validator library for PostgreSQL 18

This library should support any providers that implement OIDC and provide a valid JWT as an access token.

## Usage

To configure this validator for a PostgreSQL instance:

1. build it with the required postgres version
  ```
  export USE_PGXS=1
  export PG_CONFIG=/usr/local/pgsql/bin/pg_config
  make -j
  ```

  > **__NOTE__:** the build requires a C++23 compiler and standard library.
  > An easy setup available anywhere is a modern version of Clang with LibC++
2. Configure `postgresql.conf`:
  ```
  oauth_validator_libraries=pg_oidc_validator
  ```
3. Configure `pg_hba.conf`, for example:
  ```
  host    all             all             127.0.0.1/32            oauth	scope="openid testScope",issuer=https://url.to.the.oidc.issuer,map=pgident-map-name-if-needed
  ```
4. If using a map file (most providers return email addresses as identity), add the required entries into `pg_ident.conf`
5. Restart the server

To connect to the server with OIDC/psql:

```
bin/psql -h 127.0.0.1 'dbname=name oauth_issuer=https://url.to.the.oidc.issuer oauth_client_id=... oauth_client_secret=...'
```
  > **__NOTE__:** `oauth_client_secret` is optional, it is only required if the provider is configured to require it.

Registering the client ID and retrieving the secret is outside of the scope of this readme, as that's specific to the choosen OAuth provider.


## Special notes

### Microsoft / Entra ID

* `oauth_issuer` for postgres should be `https://login.microsoftonline.com/<tenant_id>/v2.0`
* It generates different JWTs for providers without custom scopes and with custom scopes.
  The library can only validate JWTs with custom scopes, even that requires a custom login internally.
