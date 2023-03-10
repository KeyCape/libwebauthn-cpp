#pragma once
#include "AuthenticatorResponse.h"
#include <memory>
#include <string>
#include <vector>
#include <cstdint>

class PublicKeyCredential {
protected:
  std::string id;
  std::string type;
  std::vector<std::uint8_t> rawId;
  std::shared_ptr<AuthenticatorResponse> response;

public:
  PublicKeyCredential() = delete;
  PublicKeyCredential(std::string &&id, std::string &&type,
                      std::vector<std::uint8_t> &&rawId,
                      std::shared_ptr<AuthenticatorResponse> response);
  ~PublicKeyCredential();
};