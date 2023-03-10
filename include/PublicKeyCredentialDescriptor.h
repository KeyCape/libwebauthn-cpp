#pragma once
#include "IJsonSerialize.h"
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-credential-descriptor
 *
 * This Implementation does not use the transports attribute.
 */
class PublicKeyCredentialDescriptor : public IJsonSerialize {
private:
  std::string type;
  std::string id;

public:
  PublicKeyCredentialDescriptor() = delete;
  PublicKeyCredentialDescriptor(std::string &&type, std::string &&id);
  virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialDescriptor();
};