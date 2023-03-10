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

PublicKeyCredentialRequestOptions::~PublicKeyCredentialRequestOptions() {}