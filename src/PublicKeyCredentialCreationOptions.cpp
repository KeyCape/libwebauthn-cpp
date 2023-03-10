#include "PublicKeyCredentialCreationOptions.h"
#include <jsoncpp/json/value.h>

PublicKeyCredentialCreationOptions::PublicKeyCredentialCreationOptions(
    std::shared_ptr<PublicKeyCredentialRpEntity> rp,
    std::shared_ptr<PublicKeyCredentialUserEntity> user,
    std::shared_ptr<Challenge> challenge,
    std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
        pubKeyCredParams,
    std::shared_ptr<std::forward_list<AttestationStatementFormatIdentifier>>
        attestationFormats,
    std::shared_ptr<AttestationConveyancePreference> attestation)
    : rp{rp}, user{user}, challenge{challenge},
      pubKeyCredParams{pubKeyCredParams},
      attestationFormats{attestationFormats}, attestation{attestation} {}

std::unique_ptr<Json::Value> PublicKeyCredentialCreationOptions::getJson() {
  auto ret = std::make_unique<Json::Value>(Json::objectValue);

  (*ret)["rp"] = *this->rp->getJson();
  (*ret)["user"] = *this->user->getJson();
  (*ret)["challenge"] = *this->challenge->getJson();

  auto jsonPubKeyCredParams = Json::Value{Json::arrayValue};
  for (auto param : *this->pubKeyCredParams) {
    jsonPubKeyCredParams.append(*param.getJson());
  }
  (*ret)["pubKeyCredParams"] = jsonPubKeyCredParams;

  if (this->attestation) {
    (*ret)["attestation"] = *this->attestation->getString();
  } else {
    // Defaulting to none
    (*ret)["attestation"] = "none";
  }

  auto jsonAttestationFormats = Json::Value{Json::arrayValue};
  if (this->attestationFormats) {
    for (auto &fmt : *this->attestationFormats) {
      jsonAttestationFormats.append(*fmt.getString());
    }
  }
  (*ret)["attestationFormats"] = jsonAttestationFormats;
  return ret;
}
std::shared_ptr<PublicKeyCredentialCreationOptions>
PublicKeyCredentialCreationOptions::fromJson(
    std::shared_ptr<Json::Value> json) {

  if (!json) {
    throw std::invalid_argument{"The parameter must NOT be null"};
  }

  // Extract the relying party entity
  auto rpJson = (*json)["rp"];
  std::shared_ptr<PublicKeyCredentialRpEntity> pubKeyCredRp(
      new PublicKeyCredentialRpEntity{rpJson["id"].asString(),
                                      rpJson["name"].asString()});

  // Extract the user entity
  auto userJson = (*json)["user"];
  std::shared_ptr<PublicKeyCredentialUserEntity> pubKeyCredUser(
      new PublicKeyCredentialUserEntity{
          userJson["name"].asString(), userJson["displayName"].asString(),
          drogon::utils::base64Decode(userJson["id"].asString())});

  // Extract the challenge
  auto challengeJson = (*json)["challenge"].asString();
  std::shared_ptr<Challenge> challenge(
      new Challenge{std::make_shared<std::vector<unsigned char>>(
          challengeJson.begin(), challengeJson.end())});

  // Extract the algorithms
  auto pubKeyCredParamsJson = (*json)["pubKeyCredParams"];
  std::forward_list<PublicKeyCredentialParameters> pubKeyCredParams{
      pubKeyCredParamsJson.size()};
  std::transform(
      pubKeyCredParamsJson.begin(), pubKeyCredParamsJson.end(),
      pubKeyCredParams.begin(), [](const auto &t) {
        return PublicKeyCredentialParameters{
            static_cast<COSEAlgorithmIdentifier>(t["alg"].asInt()),
            PublicKeyCredentialType::public_key}; // Only "public-key"
                                                  // is defined by now
      });

  // Extract the attestation
  auto attestationJson = (*json)["attestation"].asString();
  std::shared_ptr<AttestationConveyancePreference> attestation(
      new AttestationConveyancePreference{attestationJson});

  // Extract the attestationFormats
  DLOG(INFO) << "Extract the attestationFormats";
  auto attStmtFmtsJson = (*json)["attestationFormats"];
  std::forward_list<AttestationStatementFormatIdentifier> attStmtFmts;
  std::transform(attStmtFmtsJson.begin(), attStmtFmtsJson.end(),
                 std::front_inserter(attStmtFmts), [](const auto &t) {
                   return AttestationStatementFormatIdentifier{t.asString()};
                 });

  return std::make_shared<PublicKeyCredentialCreationOptions>(
      pubKeyCredRp, pubKeyCredUser, challenge,
      std::make_shared<std::forward_list<PublicKeyCredentialParameters>>(
          pubKeyCredParams),
      std::make_shared<std::forward_list<AttestationStatementFormatIdentifier>>(
          attStmtFmts),
      attestation);
}

const std::shared_ptr<Challenge>
PublicKeyCredentialCreationOptions::getChallenge() const {
  return this->challenge;
}

const std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
PublicKeyCredentialCreationOptions::getPublicKeyCredentialParameters() const {
  return this->pubKeyCredParams;
}

const std::shared_ptr<PublicKeyCredentialUserEntity>
PublicKeyCredentialCreationOptions::getPublicKeyCredentialUserEntity() const {
  return this->user;
}

PublicKeyCredentialCreationOptions::~PublicKeyCredentialCreationOptions() {}