#include <PublicKeyCredentialEntity.h>
#include <mutex>

#define CLASS_NAME "PublicKeyCredentialEntity"

PublicKeyCredentialEntity::PublicKeyCredentialEntity(std::string &&name)
    : name{name} {}

std::unique_ptr<Json::Value> PublicKeyCredentialEntity::getJson() {
  auto json = std::make_unique<Json::Value>();
  (*json)[CLASS_NAME]["name"] = this->name;

  return json;
}

PublicKeyCredentialEntity::~PublicKeyCredentialEntity() {}