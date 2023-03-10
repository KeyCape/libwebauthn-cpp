#pragma once
#include "PublicKeyCredentialEntity.h"
#include <memory>

/// @brief https://w3c.github.io/webauthn/#dictionary-rp-credential-params
class PublicKeyCredentialRpEntity : public PublicKeyCredentialEntity {
protected:
  std::string id;

public:
  PublicKeyCredentialRpEntity() = delete;
  PublicKeyCredentialRpEntity(std::string &&name, std::string &&id);
  virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialRpEntity();
};