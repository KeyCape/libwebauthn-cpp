#pragma once
#include "AuthenticatorAttestationResponse.h"
#include "IJsonDeserialize.h"
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/reader.h>

class PublicKeyCredential : IJsonDeserialize {
protected:
  std::string id;
  std::string type;
  std::vector<std::uint8_t> rawId;
  std::shared_ptr<AuthenticatorAttestationResponse> response;

public:
  PublicKeyCredential();
  PublicKeyCredential(std::string &&id, std::string &&type,
                      std::vector<std::uint8_t> &&rawId,
                      std::shared_ptr<AuthenticatorAttestationResponse> response);
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  const std::string& getId();
  const std::string& getType();
  const std::vector<std::uint8_t>& getRawId();
  const std::shared_ptr<AuthenticatorAttestationResponse> getResponse();
  ~PublicKeyCredential();
};