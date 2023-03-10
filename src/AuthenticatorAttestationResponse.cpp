#include "AuthenticatorAttestationResponse.h"

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse(
    std::vector<uint8_t> &&attObj, std::vector<uint8_t> &&clientDataJSON)
    : attestationObject{attObj}, AuthenticatorResponse{
                                     std::move(clientDataJSON)} {}

AuthenticatorAttestationResponse::~AuthenticatorAttestationResponse() {}