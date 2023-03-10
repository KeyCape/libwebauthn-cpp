#include "PublicKeyCredentialUserEntity.h"

PublicKeyCredentialUserEntity::PublicKeyCredentialUserEntity(
    std::string &&name, std::string &&displayName, std::string &&id)
    : PublicKeyCredentialEntity{std::move(name)},
      displayName{displayName}, id{id} {}

std::unique_ptr<Json::Value> PublicKeyCredentialUserEntity::getJson() {
  auto json = std::make_unique<Json::Value>();
  (*json)["user"]["name"] = this->name;
  (*json)["user"]["displayName"] = this->displayName;
  (*json)["user"]["id"] = this->id;

  return json;
}

PublicKeyCredentialUserEntity::~PublicKeyCredentialUserEntity() {}