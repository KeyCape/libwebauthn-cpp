#include "PublicKeyCredentialDescriptor.h"
#include <drogon/utils/Utilities.h>

PublicKeyCredentialDescriptor::PublicKeyCredentialDescriptor(std::string &&type,
                                                             std::string &&id)
    : type{type}, id{id} {}

std::unique_ptr<Json::Value> PublicKeyCredentialDescriptor::getJson() {
  auto val = std::make_unique<Json::Value>();

  (*val)["id"] = drogon::utils::base64Encode(
      (const unsigned char *)this->id.c_str(), this->id.size());
  (*val)["type"] = this->type;
  return val;
}

PublicKeyCredentialDescriptor::~PublicKeyCredentialDescriptor() {}