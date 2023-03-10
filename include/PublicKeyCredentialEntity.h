#pragma once
#include "IJsonSerialize.h"
#include <memory>
#include <string>

/// @brief https://w3c.github.io/webauthn/#dictionary-pkcredentialentity
class PublicKeyCredentialEntity : public IJsonSerialize {
protected:
  std::string name;

public:
  PublicKeyCredentialEntity() = delete;
  PublicKeyCredentialEntity(std::string &&name);
  virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialEntity();
};