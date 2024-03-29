#include "AuthenticatorResponse.h"

AuthenticatorResponse::AuthenticatorResponse() {}

AuthenticatorResponse::AuthenticatorResponse(
    std::shared_ptr<std::string> clientDataJSON)
    : clientDataJSON{clientDataJSON} {}

void AuthenticatorResponse::fromJson(const std::shared_ptr<Json::Value> json) {
  LOG(INFO) << "Parse AuthenticatorResponse";
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  // Check if the following json structure exists: {"response":
  // {"clientDataJSON": "", ..}}
  if (json->isMember("response")) {
    if (!(*json)["response"].isMember("clientDataJSON")) {
      throw std::invalid_argument{"Missing key: clientDataJSON"};
    }
  } else {
    throw std::invalid_argument{"Missing key: response"};
  }

  if (this->clientDataJSON) {
    this->clientDataJSON.reset(new std::string{});
    LOG(INFO) << "clientDataJSON already exists";
  } else {
    this->clientDataJSON = std::make_shared<std::string>();
  }

  // Decode clientDataJSON
  std::string decodedJson = drogon::utils::base64Decode(
      (*json)["response"]["clientDataJSON"].asString());

  std::transform(decodedJson.cbegin(), decodedJson.cend(),
                 std::back_inserter(*this->clientDataJSON),
                 [](const auto &t) { return t; });

  LOG(INFO) << "Parse the decoded object to JSON";
  std::string err;
  Json::Value clientDataJSON;
  Json::CharReaderBuilder builder;
  std::unique_ptr<Json::CharReader> reader{builder.newCharReader()};

  if (!reader->parse(decodedJson.c_str(),
                     decodedJson.c_str() + decodedJson.length(),
                     &clientDataJSON, &err)) {
    throw std::invalid_argument{err};
  }

  if (!this->type) {
    this->type = std::make_shared<std::string>();
  }

  std::string tmpChallengeStr = clientDataJSON["challenge"].asString();
  if (this->challenge) {
    this->challenge.reset(new Challenge{std::make_shared<std::vector<uint8_t>>(
        tmpChallengeStr.begin(), tmpChallengeStr.end())});
  } else {
    this->challenge =
        std::make_shared<Challenge>(std::make_shared<std::vector<uint8_t>>(
            tmpChallengeStr.begin(), tmpChallengeStr.end()));
  }

  if (!this->origin) {
    this->origin = std::make_shared<std::string>();
  }

  *this->type = clientDataJSON["type"].asString();
  *this->origin = clientDataJSON["origin"].asString();
  DLOG(INFO) << "type: " << *this->type << "\tchallenge: " << *this->challenge
             << "\torigin: " << *this->origin;
}
const std::shared_ptr<std::string> AuthenticatorResponse::getType() {
  return this->type;
}
const std::shared_ptr<Challenge> AuthenticatorResponse::getChallenge() {
  return this->challenge;
}
const std::shared_ptr<std::string> AuthenticatorResponse::getOrigin() {
  return this->origin;
}
const std::shared_ptr<std::string>
AuthenticatorResponse::getClientDataJSON() const {
  return this->clientDataJSON;
}
AuthenticatorResponse::~AuthenticatorResponse() {}