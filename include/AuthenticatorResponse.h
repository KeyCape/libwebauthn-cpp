#pragma once
#include "Challenge.h"
#include "IJsonDeserialize.h"
#include <cstdint>
#include <drogon/utils/Utilities.h>
#include <glog/logging.h>
#include <jsoncpp/json/reader.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <vector>

/**
 * @brief Authenticators respond to relying party requests by returning an
 * object derived by this class. See:
 * https://w3c.github.io/webauthn/#iface-authenticatorresponse §5.2
 * Authenticator Responses
 *
 */
class AuthenticatorResponse : IJsonDeserialize {
protected:
  std::shared_ptr<std::string> type;
  std::shared_ptr<Challenge> challenge;
  std::shared_ptr<std::string> origin;
  std::shared_ptr<std::string> clientDataJSON; // Base64 decoded

public:
  AuthenticatorResponse();
  AuthenticatorResponse(std::shared_ptr<std::string> clientDataJSON);
  const std::shared_ptr<std::string> getType();
  const std::shared_ptr<Challenge> getChallenge();
  const std::shared_ptr<std::string> getOrigin();
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  const std::shared_ptr<std::string> getClientDataJSON() const;
  ~AuthenticatorResponse();
};