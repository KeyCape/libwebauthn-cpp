#pragma once
#include "AttestationStatementFormatIdentifier.h"
#include "AuthenticatorData.h"
#include "AuthenticatorResponse.h"
#include "IJsonDeserialize.h"
#include <AttestationStatementFidoU2f.h>
#include <IAttestationStatement.h>
#include <algorithm>
#include <bitset>
#include <cbor.h>
#include <cstdint>
#include <glog/logging.h>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/value.h>
#include <openssl/sha.h>
#include <string>
#include <vector>

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
  std::shared_ptr<AttestationStatementFormatIdentifier>
      fmt; // Format could be "packed" or "none" if no attestation is required
  std::shared_ptr<AuthenticatorData> authData;
  // Attestation statement
  std::shared_ptr<IAttestationStatement> attStmt;

public:
  AuthenticatorAttestationResponse();
  AuthenticatorAttestationResponse(
      std::vector<uint8_t> &&attObj,
      std::shared_ptr<std::string> clientDataJSON);
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  const std::shared_ptr<AuthenticatorData> getAuthData() const;
  const std::shared_ptr<AttestationStatementFormatIdentifier> getFmt() const;
  void verifyAttStmt() const;
  ~AuthenticatorAttestationResponse();
};