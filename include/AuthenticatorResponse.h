#pragma once
#include <vector>
#include <cstdint>

/**
 * @brief Authenticators respond to relying party requests by returning an
 * object derived by this class. See:
 * https://w3c.github.io/webauthn/#iface-authenticatorresponse §5.2
 * Authenticator Responses
 *
 */
class AuthenticatorResponse {
protected:
  std::vector<std::uint8_t> clientDataJSON;

public:
  AuthenticatorResponse();
  AuthenticatorResponse(std::vector<std::uint8_t> &&clientDataJSON);
  ~AuthenticatorResponse();
};