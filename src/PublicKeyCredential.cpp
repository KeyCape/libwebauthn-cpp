#include "PublicKeyCredential.h"

PublicKeyCredential::PublicKeyCredential()
    : id{""}, type{""}, rawId{0}, response{nullptr} {}

PublicKeyCredential::PublicKeyCredential(
    std::string &&id, std::string &&type, std::vector<std::uint8_t> &&rawId,
    std::shared_ptr<AuthenticatorAttestationResponse> response)
    : id{id}, type{type}, rawId{rawId}, response{response} {}

void PublicKeyCredential::fromJson(const std::shared_ptr<Json::Value> json) {
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  if (!json->isMember("id")) {
    throw std::invalid_argument{"Missing key: id"};
  }
  if (!json->isMember("rawId")) {
    throw std::invalid_argument{"Missing key: rawId"};
  }
  if (!json->isMember("type")) {
    throw std::invalid_argument{"Missing key: type"};
  }

  LOG(INFO) << "Device id: "<< this->id << "\ttype: " << this->type;
  this->id = (*json)["id"].asString();
  this->type = (*json)["type"].asString();
  std::string rawIdTemp = (*json)["rawId"].asString();

  this->rawId.resize(rawIdTemp.size());
  std::transform(rawIdTemp.begin(), rawIdTemp.end(), this->rawId.begin(),
                 [](unsigned char c) { return c; });

  if (this->response == nullptr) {
    this->response = std::make_shared<AuthenticatorAttestationResponse>();
  }

  this->response->fromJson(json);
}

const std::string &PublicKeyCredential::getId() { return this->id; }
const std::string &PublicKeyCredential::getType() { return this->type; }
const std::vector<std::uint8_t> &PublicKeyCredential::getRawId() {
  return this->rawId;
}
const std::shared_ptr<AuthenticatorAttestationResponse>
PublicKeyCredential::getResponse() {
  return this->response;
}

PublicKeyCredential::~PublicKeyCredential() {}