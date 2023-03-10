#include "AuthenticatorAssertionResponse.h"

AuthenticatorAssertionResponse::AuthenticatorAssertionResponse(
    std::shared_ptr<AuthenticatorData> authenticatorData,
    std::shared_ptr<std::vector<uint8_t>> signature,
    std::shared_ptr<std::string> userHandle)
    : userHandle{userHandle} {
  if (!(authenticatorData && signature)) {
    throw std::invalid_argument{
        "Either authenticatorData, signature or userHanlde is NULL"};
  }
  this->authenticatorData = authenticatorData;
  this->signature = signature;
}

const std::shared_ptr<AuthenticatorData>
AuthenticatorAssertionResponse::getAuthenticatorData() {
  return this->authenticatorData;
}

const std::shared_ptr<std::vector<uint8_t>>
AuthenticatorAssertionResponse::getSignature() {
  return this->signature;
}

/**
 * @brief Parse and verify json
 *
 * @param json
 */
void AuthenticatorAssertionResponse::fromJson(
    const std::shared_ptr<Json::Value> json) {
  LOG(INFO) << "Parsing AuthenticatorAssertionResponse";
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }

  if (!json->isMember("response")) {
    throw std::invalid_argument{"Missing key: response"};
  }

  if (!(*json)["response"].isMember("signature")) {
    throw std::invalid_argument{"Missing key: signature"};
  }
  std::string tmp =
      drogon::utils::base64Decode((*json)["response"]["signature"].asString());
  this->signature =
      std::make_shared<std::vector<uint8_t>>(tmp.begin(), tmp.end());

  if ((*json)["response"].isMember("userHandle")) {
    DLOG(INFO) << "UserHandle is present";
    this->userHandle = std::make_shared<std::string>((*json)["response"]["userHandle"].asString());
    /*tmp.resize(0);
    tmp = drogon::utils::base64Decode(
        (*json)["response"]["userHandle"].asString());
    this->userHandle =
        std::make_shared<std::vector<uint8_t>>(tmp.begin(), tmp.end());*/
  }

  if (!(*json)["response"].isMember("authenticatorData")) {
    throw std::invalid_argument{"Missing key: authenticatorData"};
  }
  tmp.resize(0);
  tmp = drogon::utils::base64Decode(
      (*json)["response"]["authenticatorData"].asString());
  std::vector<uint8_t> tmpVec(tmp.begin(), tmp.end());
  this->authenticatorData = std::make_shared<AuthenticatorData>(tmpVec);

  AuthenticatorResponse::fromJson(json);
}

AuthenticatorAssertionResponse::~AuthenticatorAssertionResponse() {}