#include "PublicKeyCredentialParameters.h"

PublicKeyCredentialParameters::PublicKeyCredentialParameters() {}

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

COSEAlgorithmIdentifier PublicKeyCredentialParameters::getAlgorithm() const { return this->alg; }

PublicKeyCredentialParameters::~PublicKeyCredentialParameters() {}