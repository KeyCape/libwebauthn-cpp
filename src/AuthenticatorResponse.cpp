#include "AuthenticatorResponse.h"

AuthenticatorResponse::AuthenticatorResponse(
    std::vector<std::uint8_t> &&clientDataJSON)
    : clientDataJSON{clientDataJSON} {}

AuthenticatorResponse::~AuthenticatorResponse() {}