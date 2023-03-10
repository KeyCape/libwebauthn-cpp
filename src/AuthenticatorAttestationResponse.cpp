#include "AuthenticatorAttestationResponse.h"

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse() {}

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse(
    std::vector<uint8_t> &&attObj, std::vector<uint8_t> &&clientDataJSON)
    : attestationObject{attObj}, AuthenticatorResponse{
                                     std::move(clientDataJSON)} {}

void AuthenticatorAttestationResponse::fromJson(
    const std::shared_ptr<Json::Value> json) {
  if (json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  if (json->isMember("response")) {
    if (!(*json)["response"].isMember("attestationObject")) {
      throw std::invalid_argument{"Missing key attestationObject"};
    }
  } else {
    throw std::invalid_argument{"Missing key: response"};
  }
  std::string tmp = (*json)["response"]["attestationObject"].asString();

  this->attestationObject.reserve(tmp.size());
  std::transform(tmp.begin(), tmp.end(), this->attestationObject.begin(),
                 [](const auto &t) { return t; });

  AuthenticatorResponse::fromJson(json);
}

AuthenticatorAttestationResponse::~AuthenticatorAttestationResponse() {}