#include <PublicKeyCredentialEntity.h>
#include <mutex>

PublicKeyCredentialEntity::PublicKeyCredentialEntity(std::string &&name)
    : name{name} {}

std::unique_ptr<Json::Value> PublicKeyCredentialEntity::getJson() {
  auto json = std::make_unique<Json::Value>();
  (*json)["name"] = this->name;

  return json;
}

PublicKeyCredentialEntity::~PublicKeyCredentialEntity() {}