#pragma once
#include "PublicKeyCredentialEntity.h"
#include <drogon/utils/Utilities.h>
#include <string>

/// @brief https://w3c.github.io/webauthn/#dictionary-user-credential-params
class PublicKeyCredentialUserEntity : public PublicKeyCredentialEntity {
protected:
  std::string displayName;
  std::string id;

public:
  PublicKeyCredentialUserEntity() = delete;
  PublicKeyCredentialUserEntity(std::string &&name, std::string &&displayName,
                                std::string &&id);
  virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialUserEntity();
};