#pragma once
#include <vector>
#include <cstdint>
#include "IJsonDeserialize.h"
#include "Challenge.h"
#include <drogon/utils/Utilities.h>
#include <jsoncpp/json/reader.h>
#include <glog/logging.h>

/**
 * @brief Authenticators respond to relying party requests by returning an
 * object derived by this class. See:
 * https://w3c.github.io/webauthn/#iface-authenticatorresponse §5.2
 * Authenticator Responses
 *
 */
class AuthenticatorResponse : IJsonDeserialize {
protected:
  std::vector<std::uint8_t> clientDataJSON;
  std::shared_ptr<std::string> type;
  std::shared_ptr<Challenge> challenge;
  std::shared_ptr<std::string> origin;

public:
  AuthenticatorResponse();
  AuthenticatorResponse(std::vector<std::uint8_t> &&clientDataJSON);
  const std::shared_ptr<std::string> getType();
  const std::shared_ptr<Challenge> getChallenge();
  const std::shared_ptr<std::string> getOrigin();
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  ~AuthenticatorResponse();
};