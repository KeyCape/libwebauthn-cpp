#pragma once
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-authenticatorSelection
 * 
 */
class AuthenticatorSelectionCriteria {
private:
  std::string authenticatorAttachment;
  std::string residentKey;
  bool requireResidentKey = false;
  std::string userVerification = "preferred";

public:
  AuthenticatorSelectionCriteria() = delete;
  AuthenticatorSelectionCriteria(std::string &&authenticatorAttachment, std::string &&residentKey);
  ~AuthenticatorSelectionCriteria();
};