#pragma once
#include "Base64Url.h"
#include "IJsonSerialize.h"
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-credential-descriptor
 *
 * This Implementation does not use the transports attribute.
 */
class PublicKeyCredentialDescriptor : public IJsonSerialize {
public:
  std::string type;
  std::string id;

  PublicKeyCredentialDescriptor() = delete;
  PublicKeyCredentialDescriptor(std::string &&type, std::string &&id);
  virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialDescriptor();
};