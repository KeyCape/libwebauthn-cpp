#pragma once
#include "AuthenticatorResponse.h"
#include <algorithm>
#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief The AuthenticatorAttestationResponse interface represents the
 * authenticator's response to a client’s request for the creation of a new
 * public key credential. See:
 * https://w3c.github.io/webauthn/#iface-authenticatorattestationresponse
 * §5.2.1. Information About Public Key Credential
 *
 */
class AuthenticatorAttestationResponse : public AuthenticatorResponse {
protected:
  std::vector<uint8_t> attestationObject;

public:
  AuthenticatorAttestationResponse() = delete;
  AuthenticatorAttestationResponse(std::vector<uint8_t> &&attObj,
                                   std::vector<uint8_t> &&clientDataJSON);
  ~AuthenticatorAttestationResponse();
};