#include "AuthenticatorResponse.h"

AuthenticatorResponse::AuthenticatorResponse() {}

AuthenticatorResponse::AuthenticatorResponse(
    std::vector<std::uint8_t> &&clientDataJSON)
    : clientDataJSON{clientDataJSON} {}

void AuthenticatorResponse::fromJson(const std::shared_ptr<Json::Value> json) {
  if (json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  if (json->isMember("response")) {
    if (!(*json)["response"].isMember("clientDataJSON")) {
      throw std::invalid_argument{"Missing key: clientDataJSON"};
    }
  } else {
    throw std::invalid_argument{"Missing key: response"};
  }
  std::string tmp = (*json)["response"]["clientDataJSON"].asString();

  this->clientDataJSON.reserve(tmp.size());
  std::transform(tmp.begin(), tmp.end(), this->clientDataJSON.begin(),
                 [](const auto &t) { return t; });

  // Decode clientDataJSON
  std::string decodedJson = drogon::utils::base64Decode(tmp);

  std::string err;
  Json::Value clientDataJSON;
  Json::CharReaderBuilder builder;
  std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

  if (!reader->parse(decodedJson.c_str(),
                     decodedJson.c_str() + decodedJson.length(),
                     &clientDataJSON, &err)) {
    throw std::invalid_argument{err};
  }

  if(!this->type) {
    this->type = std::make_shared<std::string>();
  }

  if(!this->challenge) {
    this->challenge = std::make_shared<std::string>();
  }

  if(!this->origin) {
    this->origin = std::make_shared<std::string>();
  }

  *this->type = clientDataJSON["type"].asString();
  *this->challenge = clientDataJSON["challenge"].asString();
  *this->origin = clientDataJSON["origin"].asString();
}
const std::shared_ptr<std::string> AuthenticatorResponse::getType() {
  return this->type;
}
const std::shared_ptr<std::string> AuthenticatorResponse::getChallenge() {
  return this->challenge;
}
const std::shared_ptr<std::string> AuthenticatorResponse::getOrigin() {
  return this->origin;
}
AuthenticatorResponse::~AuthenticatorResponse() {}