#include "PublicKeyCredentialRequestOptions.h"

PublicKeyCredentialRequestOptions::PublicKeyCredentialRequestOptions(
    std::shared_ptr<Challenge> challenge,
    std::shared_ptr<unsigned long> timeout, std::shared_ptr<std::string> rpId,
    std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
        allowCredentials,
    std::shared_ptr<UserVerificationRequirement> userVerification,
    std::shared_ptr<AttestationConveyancePreference> attestation,
    std::shared_ptr<std::forward_list<std::string>> attestationFormats)
    : challenge{challenge}, rpId{rpId}, allowCredentials{allowCredentials},
      userVerification{userVerification}, attestation{attestation},
      attestationFormats{attestationFormats} {}

std::unique_ptr<Json::Value> PublicKeyCredentialRequestOptions::getJson() {
  auto val = std::make_unique<Json::Value>();
  if (this->challenge) {
    (*val)["challenge"] = *this->challenge->getJson();
  }
  if (this->timeout) {
    (*val)["timeout"] = *this->timeout;
  }
  if (this->rpId) {
    (*val)["rpId"] = *this->rpId;
  }
  if (this->allowCredentials) {
    Json::Value jsonCred(Json::arrayValue);

    for (auto i : *this->allowCredentials) {
      jsonCred.append(*i.getJson());
    }
    (*val)["allowCredentials"] = std::move(jsonCred);
  }

  return val;
}
std::shared_ptr<PublicKeyCredentialRequestOptions>
PublicKeyCredentialRequestOptions::fromJson(
    const std::shared_ptr<Json::Value> json) {
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  if (!json->isMember("challenge")) {
    throw std::invalid_argument{"Missing key: challenge"};
  }
  if (!json->isMember("rpId")) {
    throw std::invalid_argument{"Missing key: rpId"};
  }

  std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
      allowCredentials = nullptr;
  if (json->isMember("allowCredentials")) {
    allowCredentials =
        std::make_shared<std::forward_list<PublicKeyCredentialDescriptor>>();
    auto jsonAllowCredentials = (*json)["allowCredentials"];
    for (auto &i : jsonAllowCredentials) {
      if (!i.isMember("id")) {
        throw std::invalid_argument{"Missing key: allowCredentials.id"};
      }
      if (!i.isMember("type")) {
        throw std::invalid_argument{"Missing key: allowCredentials.type"};
      }
      allowCredentials->emplace_front(PublicKeyCredentialDescriptor{
          i["id"].asString(), i["type"].asString()});
    }
  }

  std::shared_ptr<unsigned long> timeout = nullptr;
  if (json->isMember("timeout")) {
    timeout =
        std::make_shared<unsigned long>((*json)["timeout"].as<unsigned long>());
  }

  std::shared_ptr<UserVerificationRequirement> userVerification = nullptr;
  if (json->isMember("userVerification")) {
    auto tmpStr = (*json)["userVerification"].as<std::string>();
    if (tmpStr.compare("required") == 0) {
      userVerification = std::make_shared<UserVerificationRequirement>(
          UserVerificationRequirement::required);
    } else if (tmpStr.compare("preferred") == 0) {
      userVerification = std::make_shared<UserVerificationRequirement>(
          UserVerificationRequirement::preferred);
    } else if (tmpStr.compare("discouraged") == 0) {
      userVerification = std::make_shared<UserVerificationRequirement>(
          UserVerificationRequirement::discouraged);
    }
  }

  std::shared_ptr<AttestationConveyancePreference> attestation = nullptr;
  if (json->isMember("attestation")) {
    auto tmpStr = (*json)["attestation"].as<std::string>();
    if (tmpStr.compare("none") == 0) {
      attestation = std::make_shared<AttestationConveyancePreference>(
          AttestationConveyancePreference::none);
    } else if (tmpStr.compare("indirect") == 0) {
      attestation = std::make_shared<AttestationConveyancePreference>(
          AttestationConveyancePreference::indirect);
    } else if (tmpStr.compare("direct") == 0) {
      attestation = std::make_shared<AttestationConveyancePreference>(
          AttestationConveyancePreference::direct);
    } else if (tmpStr.compare("enterprise") == 0) {
      attestation = std::make_shared<AttestationConveyancePreference>(
          AttestationConveyancePreference::enterprise);
    }
  }

  std::shared_ptr<std::forward_list<std::string>> attestationFormats;
  if (json->isMember("attestationFormats")) {
    if ((*json)["attestationFormats"].isArray()) {
      attestationFormats = std::make_shared<std::forward_list<std::string>>();
      for (auto &i : (*json)["attestationFormats"]) {
        attestationFormats->emplace_front(i.as<std::string>());
      }
    }
  }

  auto challengeJson = (*json)["challenge"].asString();
  std::shared_ptr<Challenge> challenge(
      new Challenge{std::make_shared<std::vector<unsigned char>>(
          challengeJson.begin(), challengeJson.end())});

  auto rpId = std::make_shared<std::string>((*json)["rpId"].as<std::string>());

  return std::make_shared<PublicKeyCredentialRequestOptions>(
      challenge, timeout, rpId, allowCredentials, userVerification, attestation,
      attestationFormats);
}

const std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
PublicKeyCredentialRequestOptions::getAllowedCredentials() {
  return this->allowCredentials;
}

const std::shared_ptr<Challenge>
PublicKeyCredentialRequestOptions::getChallenge() {
  return this->challenge;
}

bool PublicKeyCredentialRequestOptions::hasCredential(
    const std::string &id) const {
  for (const auto &i : *this->allowCredentials) {
    if (i.id.compare(id)) {
      return true;
    }
  }
  return false;
}

PublicKeyCredentialRequestOptions::~PublicKeyCredentialRequestOptions() {}