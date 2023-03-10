#pragma once
#include "AuthenticatorAttestationResponse.h"
#include "AuthenticatorData.h"
#include "AuthenticatorResponse.h"
#include <exception>
#include <memory>
#include <vector>

/**
 * @brief The AuthenticatorAssertionResponse interface represents an
 * authenticator's response to a client’s request for generation of a new
 * authentication assertion given the WebAuthn Relying Party's challenge and
 * OPTIONAL list of credentials it is aware of. This response contains a
 * cryptographic signature proving possession of the credential private key, and
 * optionally evidence of user consent to a specific transaction.
 *
 * See: https://w3c.github.io/webauthn/#iface-authenticatorassertionresponse
 * §5.2.2
 *
 * Note: The attestationObject is OPTIONAL and not implemented.
 *
 */
class AuthenticatorAssertionResponse : public AuthenticatorResponse {
private:
  std::shared_ptr<AuthenticatorData> authenticatorData;
  std::shared_ptr<std::vector<uint8_t>> signature;
  std::shared_ptr<std::string> userHandle;

public:
  AuthenticatorAssertionResponse();
  AuthenticatorAssertionResponse(
      std::shared_ptr<AuthenticatorData> authenticatorData,
      std::shared_ptr<std::vector<uint8_t>> signature,
      std::shared_ptr<std::string> userHandle);
  const std::shared_ptr<AuthenticatorData> getAuthenticatorData();
  const std::shared_ptr<std::vector<uint8_t>> getSignature();
  const std::shared_ptr<std::string> getUserHandle();
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  ~AuthenticatorAssertionResponse();
};