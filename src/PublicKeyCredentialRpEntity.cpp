#include "PublicKeyCredentialRpEntity.h"

PublicKeyCredentialRpEntity::PublicKeyCredentialRpEntity(std::string &&name,
                                                         std::string &&id)
    : id{id}, PublicKeyCredentialEntity{std::move(name)} {}

std::unique_ptr<Json::Value> PublicKeyCredentialRpEntity::getJson() {
  auto json = std::make_unique<Json::Value>();

  (*json)["rp"]["name"] = this->name;
  (*json)["rp"]["id"] = this->id;

  return json;
}

PublicKeyCredentialRpEntity::~PublicKeyCredentialRpEntity() {}