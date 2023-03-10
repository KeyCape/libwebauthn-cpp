#include "AuthenticatorAttestationResponse.h"

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse() {}

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse(
    std::vector<uint8_t> &&attObj, std::vector<uint8_t> &&clientDataJSON)
    : attestationObject{attObj}, AuthenticatorResponse{
                                     std::move(clientDataJSON)} {}

std::shared_ptr<AuthenticatorAttestationResponse>
AuthenticatorAttestationResponse::fromJson(const std::string &json) {
    return std::make_shared<AuthenticatorAttestationResponse>();
}

AuthenticatorAttestationResponse::~AuthenticatorAttestationResponse() {}