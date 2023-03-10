#include "PublicKeyCredential.h"

PublicKeyCredential::PublicKeyCredential()
    : id{""}, type{""}, rawId{0}, response{nullptr} {}

PublicKeyCredential::PublicKeyCredential(
    std::string &&id, std::string &&type, std::vector<std::uint8_t> &&rawId,
    std::shared_ptr<AuthenticatorAttestationResponse> response)
    : id{id}, type{type}, rawId{rawId}, response{response} {}

std::shared_ptr<PublicKeyCredential> PublicKeyCredential::fromJson(const std::string &json) {
  JSONCPP_STRING err;
  Json::Value root;
  Json::CharReaderBuilder builder;
  const std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

  if (!reader->parse(json.c_str(), json.c_str() + json.length(), &root, &err)) {
    throw std::runtime_error{err};
  }

  std::string rawIdTemp = root["id"].asString();
  std::vector<std::uint8_t> rawId(rawIdTemp.length());
  std::transform(rawIdTemp.begin(), rawIdTemp.end(), rawId.begin(),
                 [](unsigned char c) { return c; });

  std::shared_ptr<AuthenticatorAttestationResponse> aatr;

  return std::make_shared<PublicKeyCredential>(root["id"].asString(), root["type"].asString(),
                                 std::move(rawId), aatr);
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