
#include <jwt-cpp/jwt.h>

#include <ranges>
#include <string>

#include "http_client.hpp"
#include "jwk.hpp"

extern "C" {

#include "postgres.h"
//
#include "fmgr.h"
#include "libpq/oauth.h"
#include "miscadmin.h"
#include "utils/guc.h"

PG_MODULE_MAGIC;
}

bool validate_token(const ValidatorModuleState* state, const char* token, const char* role,
                    ValidatorModuleResult* result);

static const OAuthValidatorCallbacks validator_callbacks = {PG_OAUTH_VALIDATOR_MAGIC, nullptr, nullptr, validate_token};

extern "C" {
const OAuthValidatorCallbacks* _PG_oauth_validator_module_init(void) { return &validator_callbacks; }
}

static char* authn_field = NULL;

extern "C" void _PG_init() {
  DefineCustomStringVariable("pg_oauth.authn_field", gettext_noop("OAuth field used for matching PostgreSQL users"),
                             NULL, &authn_field, "sub", PGC_POSTMASTER, 0, NULL, NULL, NULL);
}

bool validate_token(const ValidatorModuleState* state, const char* token, const char* role,
                    ValidatorModuleResult* res) try {
  // initialize return values to deny
  res->authn_id = nullptr;
  res->authorized = false;

  const auto required_scopes =
      std::string(MyProcPort->hba->oauth_scope) | std::views::split(' ') | std::ranges::to<scopes_t>();
  const std::string issuer = MyProcPort->hba->oauth_issuer;

  http_client http;
  const auto issuer_info = http.get_json(issuer_info_url(issuer));

  if (!issuer_info.is<picojson::object>()) {
    elog(WARNING, "OpenID configuration from issuer is not a JSON object");
    return false;
  }

  const auto& issuer_object = issuer_info.get<picojson::object>();
  const auto jwks_uri = issuer_object.at("jwks_uri").to_str();

  if (jwks_uri.empty()) {
    elog(WARNING, "Could not parse JWKS URI from issuer configuration");
    return false;
  }

  const auto jwks_info = http.get_json(jwks_uri);
  const auto decoded_token = jwt::decode(token);
  const std::string jwt_kid = decoded_token.get_header_claim("kid").as_string();
  const auto verifier = configure_verifier_with_jwks(issuer, jwks_info, jwt_kid);
  verifier.verify(decoded_token);
  const auto json_scopes = decoded_token.get_payload_json()["scp"];
  const scopes_t received_scopes = parse_jwt_scopes(json_scopes);
  const auto payload = decoded_token.get_payload_json();

  PG_TRY();
  {
  	res->authn_id = pstrdup(payload.at(authn_field).to_str().c_str());
  }
  PG_CATCH();
  {
	  elog(WARNING, "OAuth failed: out of memory");
	  return false;
  }
  PG_END_TRY();

  if (issuer_is_azure(issuer)) {
    if (strcmp(authn_field, "sub") == 0) {
      elog(WARNING,
           "sub field is not guaranteed to be unique with Entra ID, consider using a different field for user "
           "matching.");
    }
    // Azure is broken: it expects us to provide full tenant-id
    // qualified scopes for the request, but then it returns the simple name
    // in the JWT instead. This requires a custom matching code.
    res->authorized = azure_scopes_match(required_scopes, received_scopes);
  } else {
    res->authorized = std::ranges::includes(received_scopes, required_scopes);
  }

  return true;

} catch (const std::exception& ex) {
  elog(WARNING, "OAuth validation failed with exception: %s", ex.what());
  return false;
} catch (...) {
  elog(WARNING, "OAuth validation failed with unknown internal error");
  return false;
}
