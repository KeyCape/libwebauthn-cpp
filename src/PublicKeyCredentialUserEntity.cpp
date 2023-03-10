#include "PublicKeyCredentialUserEntity.h"

PublicKeyCredentialUserEntity::PublicKeyCredentialUserEntity(
    std::string &&name, std::string &&displayName, std::string &&id)
    : PublicKeyCredentialEntity{std::move(name)},
      displayName{displayName}, id{id} {}

std::unique_ptr<Json::Value> PublicKeyCredentialUserEntity::getJson() {
  auto json = std::make_unique<Json::Value>();
  (*json)["name"] = this->name;
  (*json)["displayName"] = this->displayName;
  (*json)["id"] = drogon::utils::base64Encode(
      reinterpret_cast<const unsigned char *>(this->id.c_str()),
      this->id.size(), false);

  return json;
}

PublicKeyCredentialUserEntity::~PublicKeyCredentialUserEntity() {}