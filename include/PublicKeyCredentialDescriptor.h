#pragma once
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-credential-descriptor
 * 
 * This Implementation does not use the transports attribute.
 */
class PublicKeyCredentialDescriptor {
private:
std::string type;
std::string id;
public:
  PublicKeyCredentialDescriptor() = delete;
  PublicKeyCredentialDescriptor(std::string &&type, std::string &&id);
  ~PublicKeyCredentialDescriptor();
};