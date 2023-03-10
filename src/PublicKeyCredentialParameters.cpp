#include "PublicKeyCredentialParameters.h"

PublicKeyCredentialParameters::PublicKeyCredentialParameters(
    COSEAlgorithmIdentifier &&alg, PublicKeyCredentialType &&type)
    : alg{alg} {
  switch (type) {
  case public_key:
    this->type = "public-key";
    break;
  }
}
std::unique_ptr<Json::Value> PublicKeyCredentialParameters::getJson() {
  auto json = std::make_unique<Json::Value>(Json::objectValue);
  (*json)["type"] = this->type;
  (*json)["alg"] = this->alg;

  return json;
}

PublicKeyCredentialParameters::~PublicKeyCredentialParameters() {}