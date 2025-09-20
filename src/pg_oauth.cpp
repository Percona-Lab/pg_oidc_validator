
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

PG_MODULE_MAGIC;
}

bool validate_token(const ValidatorModuleState* state, const char* token, const char* role,
                    ValidatorModuleResult* result);

static const OAuthValidatorCallbacks validator_callbacks = {PG_OAUTH_VALIDATOR_MAGIC, nullptr, nullptr, validate_token};

extern "C" {
const OAuthValidatorCallbacks* _PG_oauth_validator_module_init(void) { return &validator_callbacks; }
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
    elog(ERROR, "OpenID configuration from issuer is not a JSON object");
    return false;
  }

  const auto& issuer_object = issuer_info.get<picojson::object>();
  const auto jwks_uri = issuer_object.at("jwks_uri").to_str();

  if (jwks_uri.empty()) {
    elog(ERROR, "Could not parse JWKS URI from issuer configuration");
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

  if (issuer_is_azure(issuer)) {
    // Azure doesn't put email in 'sub', but in 'email' field
    // sub for whatever reason is a uuid instead
    res->authn_id = pstrdup(payload.at("email").to_str().c_str());
    // Azure is again broken: it expects us to provide full tenant-id
    // qualified scopes for the request, but then it returns the simple name
    // in the JWT instead. This requires a custom matching code.
    res->authorized = azure_scopes_match(required_scopes, received_scopes);
  } else {
    res->authn_id = pstrdup(payload.at("sub").to_str().c_str());
    res->authorized = std::ranges::includes(received_scopes, required_scopes);
  }

  return true;

} catch (const std::exception& ex) {
  elog(ERROR, "OAuth validation failed with exception: %s", ex.what());
  return false;
} catch (...) {
  elog(ERROR, "OAuth validation failed with unknown internal error");
  return false;
}
