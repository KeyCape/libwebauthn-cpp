#include "PublicKeyCredentialRpEntity.h"

PublicKeyCredentialRpEntity::PublicKeyCredentialRpEntity(std::string &&name,
                                                         std::string &&id)
    : id{id}, PublicKeyCredentialEntity{std::move(name)} {}

std::unique_ptr<Json::Value> PublicKeyCredentialRpEntity::getJson() {
  auto json = std::make_unique<Json::Value>();

  (*json)["name"] = this->name;
  (*json)["id"] = this->id;

  return json;
}

PublicKeyCredentialRpEntity::~PublicKeyCredentialRpEntity() {}