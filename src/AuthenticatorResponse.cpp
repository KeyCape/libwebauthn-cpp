#include "AuthenticatorResponse.h"

AuthenticatorResponse::AuthenticatorResponse() {}

AuthenticatorResponse::AuthenticatorResponse(
    std::vector<std::uint8_t> &&clientDataJSON)
    : clientDataJSON{clientDataJSON} {}

AuthenticatorResponse::~AuthenticatorResponse() {}