#include "PublicKeyCredentialDescriptor.h"

PublicKeyCredentialDescriptor::PublicKeyCredentialDescriptor(std::string &&type,
                                                             std::string &&id)
    : type{type}, id{id} {}

std::unique_ptr<Json::Value> PublicKeyCredentialDescriptor::getJson() {
  auto val = std::make_unique<Json::Value>();
  (*val)["id"] = this->id;
  (*val)["type"] = this->type;
  return val;
}

PublicKeyCredentialDescriptor::~PublicKeyCredentialDescriptor() {}