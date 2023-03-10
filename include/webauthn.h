#pragma once
#include "Base64Url.h"
#include "PublicKeyCredential.h"
#include "PublicKeyCredentialCreationOptions.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <glog/logging.h>
#include <openssl/sha.h>
#include <string>
#include <type_traits>
#include <utility>

template <typename T> class Webauthn {
private:
  std::string rp_name;
  std::string rp_id;
  std::shared_ptr<std::basic_string<unsigned char>> rp_id_hash;
  std::vector<std::string> fmtList = {
      "none", "packed"}; // A vector which contains the allowed attestation
                         // statement formats.

  bool validateOrigin(const std::shared_ptr<std::string> originPtr) const;

public:
  Webauthn() = delete;
  /// @brief Create an instance of a relying party
  /// @param name This is the name of the relying party
  /// @param id This is the id of the relying party, which is transfered to the
  /// WebAgent
  Webauthn(std::string &&name, std::string &&id);
  /**
   * @brief This method returns the PublicKeyCredentialCreationOptions object,
   * which is requested by the client, to register a new Credential
   *
   * @param username The username of the user. This parameter is usally assigned
   * by the client.
   * @return std::shared_ptr<PublicKeyCredentialCreationOptions> Is returned to
   * the client.
   */
  std::shared_ptr<PublicKeyCredentialCreationOptions>
  beginRegistration(std::string &username);
  std::shared_ptr<T> finishRegistration(
      std::shared_ptr<PublicKeyCredentialCreationOptions> options,
      std::shared_ptr<Json::Value> request);
  ~Webauthn();
};

template <typename T>
Webauthn<T>::Webauthn(std::string &&name, std::string &&id)
    : rp_name{name}, rp_id{id} {
  static_assert(std::is_base_of_v<CredentialRecord, T>,
                "The return type of finishRegistration(..) must be a child of "
                "the class CredentialRecord");

  // Calculate the hash of the relying partys id
  unsigned char *hashPtr = SHA256((const unsigned char *)this->rp_id.data(),
                                  this->rp_id.size(), NULL);
  this->rp_id_hash =
      std::make_shared<std::basic_string<unsigned char>>(hashPtr, 32);
}
/**
 * @brief This method is used to start the registration ceremony of a
 * credential.
 *
 * @tparam T Of type CredentialRecord
 * @param username  The username to register. This parameter has to be
 * unique(Could be a unique name or more common an email address).
 * @return std::shared_ptr<PublicKeyCredentialCreationOptions> Prefilled
 * datatype, which has to be send to the webagent as response.
 */
template <typename T>
std::shared_ptr<PublicKeyCredentialCreationOptions>
Webauthn<T>::beginRegistration(std::string &username) {
  LOG(INFO) << "Beginning with the credential registration ceremony";
  if (username.empty()) {
    throw std::runtime_error{"The username must NOT be emtpy"};
  }

  auto rp = std::make_shared<PublicKeyCredentialRpEntity>(
      PublicKeyCredentialRpEntity(std::forward<std::string>(this->rp_name),
                                  std::forward<std::string>(this->rp_id)));

  auto user = std::make_shared<PublicKeyCredentialUserEntity>(
      PublicKeyCredentialUserEntity{std::forward<std::string>(username),
                                    std::forward<std::string>(username),
                                    std::forward<std::string>(username)});

  auto challenge = std::make_shared<Challenge>(Challenge{});

  auto params =
      std::make_shared<std::forward_list<PublicKeyCredentialParameters>>(
          std::forward_list<PublicKeyCredentialParameters>(
              {PublicKeyCredentialParameters{COSEAlgorithmIdentifier::ES256}}));

  auto ret = std::make_shared<PublicKeyCredentialCreationOptions>(
      rp, user, challenge, params);

  return ret;
}

/**
 * @brief This method has to be called after beginRegister. Else the method is
 * going to fail.
 * For more informations see:
 * https://w3c.github.io/webauthn/#sctn-registering-a-new-credential starting
 * from §7.1.3
 *
 * @tparam T The type is of base class CredentialRecord
 * @param options This parameter includes the data from /register/begin. Usually
 * you would store these in a cache like redis.
 * @param request The json from the web agent.
 * @return std::shared_ptr<T> A pointer to with filled attributes
 */
template <typename T>
std::shared_ptr<T> Webauthn<T>::finishRegistration(
    std::shared_ptr<PublicKeyCredentialCreationOptions> options,
    std::shared_ptr<Json::Value> request) {
  static_assert(std::is_base_of<CredentialRecord, T>::value,
                "The return type of finishRegistration has to be derived from "
                "CredentialRecord");
  LOG(INFO) << "Finishing the registration ceremony";

  if (!(options && request)) {
    LOG(ERROR) << "One of the parameters to finishRegistration has not been "
                  "initialized";
    throw std::invalid_argument{"One of the parameters is Null"};
  }
  auto ret = std::make_shared<T>();

  PublicKeyCredential pkeyCred;
  // Parse the json
  pkeyCred.fromJson(request);
  auto response = pkeyCred.getResponse();

  // Verify that the AuthenticatorAttestationResponse has been initialized
  if (!response) {
    LOG(WARNING) << "Missing AuthenticatorAttestationResponse";
    throw std::invalid_argument{"Missing AuthenticatorAttestationResponse"};
  }

  // §7.1.7 Verify that the value of C.type is webauthn.create.
  LOG(INFO) << "Verify that the value of C.type is webauthn.create.";
  if (response->getType()->compare("webauthn.create") != 0) {
    LOG(WARNING)
        << "The type of C.Type has to be  webauthn.create, but C.type is: "
        << response->getType();
    throw std::invalid_argument{"The type of C.type has to be webauthn.create"};
  }

  // §7.1.8 Verify that the value of C.challenge equals the base64url encoding
  // of options.challenge.
  LOG(INFO) << "Verify that the value of C.challenge equals the base64url "
               "encoding of options.challenge.";
  options->getChallenge()->encodeBase64Url();
  if (!(*response->getChallenge() == *options->getChallenge())) {
    LOG(WARNING)
        << "The value of C.challenge doesn't match the cached. C.challenge: "
        << *pkeyCred.getResponse()->getChallenge()
        << "\tcached challenge: " << *options->getChallenge();
  }

  // §7.1.9 Verify that the value of C.origin matches the Relying Party's
  // origin. RP ID: https://w3c.github.io/webauthn/#rp-id
  LOG(INFO) << "Verify that the value of C.origin matches the Relying Party's "
               "origin.";
  if (!this->validateOrigin(response->getOrigin())) {
    LOG(WARNING) << "The origin received origin is: " << *response->getOrigin()
                 << " but should have been: " << this->rp_id;
    throw std::invalid_argument{
        "The origin received doesn't match with the relying party"};
  }

  // §7.1.12 Verify that the rpIdHash in authData is the SHA-256 hash of the RP
  // ID expected by the Relying Party.
  LOG(INFO) << "Verify that the rpIdHash in authData is the SHA-256 hash of "
               "the RP ID expected by the Relying Party.";
  auto responseAuthData = response->getAuthData();
  auto responseAuthDataRpIdHash = responseAuthData->getRpIdHash();

  if (responseAuthDataRpIdHash->size() != this->rp_id_hash->size()) {
    LOG(WARNING) << "The hash length of the response and the stored arn't "
                    "equal. Response: "
                 << responseAuthDataRpIdHash->size()
                 << "\tServer: " << this->rp_id_hash->size();
    throw std::invalid_argument{
        "The hash length of the relying partys id doesn't match"};
  }

  if (this->rp_id_hash->compare(0, responseAuthDataRpIdHash->size(),
                                responseAuthDataRpIdHash->data()) != 0) {
    LOG(WARNING)
        << "The hash of the rp id provided by the web agent dosen't match";
    throw std::invalid_argument{
        "The hash of the rp id provided by the web agent doesn't match"};
  }

  // §7.1.13 Verify that the UP bit of the flags in authData is set.
  // UP = User Present -> Bit 0
  auto responseAuthDataFlags = responseAuthData->getFlags();
  LOG(INFO) << "Verify that the UP bit of the flags in authData is set.";
  if (!responseAuthDataFlags->test(0)) {
    LOG(WARNING)
        << "The user has to be present in order to register a new credential";
    throw std::invalid_argument{
        "The user has to be present in order to register a new credential"};
  }

  // §7.1.14 If the Relying Party requires user verification for this
  // registration, verify that the UV bit of the flags in authData is set.
  // TODO

  // §7.1.15 If the Relying Party uses the credential’s backup eligibility to
  // inform its user experience flows and/or policies, evaluate the BE bit of
  // the flags in authData.
  // TODO

  // §7.1.16 If the Relying Party uses the credential’s backup state to inform
  // its user experience flows and/or policies, evaluate the BS bit of the flags
  // in authData.
  // TODO

  // §7.1.17 Verify that the "alg" parameter in the credential public key in
  // authData matches the alg attribute of one of the items in
  // options.pubKeyCredParams.
  LOG(INFO) << "Verify that the \"alg\" parameter in the credential public key "
               "in authData matches the alg attribute of one of the items in "
               "options.pubKeyCredParams.";
  auto responseAuthDataPbKey =
      responseAuthData->getAttestedCredentialData()->getPublicKey();
  auto responseAuthDataPbKeyAlg = responseAuthDataPbKey->alg;
  auto optionsPublicKeyCredentialParameters =
      options->getPublicKeyCredentialParameters();

  bool algMatch = false;
  for (auto &i : *optionsPublicKeyCredentialParameters) {
    if (i.getAlgorithm() == responseAuthDataPbKeyAlg) {
      algMatch = true;
      break;
    }
  }

  if (!algMatch) {
    LOG(WARNING) << "The given COSEAlgorithmIdentifier isn't allowed";
    throw std::invalid_argument{
        "The given COSEAlgorithmIdentifier isn't allowed"};
  }

  // §7.1.18 Verify that the values of the client extension outputs in
  // clientExtensionResults and the authenticator extension outputs in the
  // extensions in authData are as expected, considering the client extension
  // input values that were given in options.extensions and any specific policy
  // of the Relying Party regarding unsolicited extensions, i.e., those that
  // were not specified as part of options.extensions. In the general case, the
  // meaning of \"are as expected\" is specific to the Relying Party and which
  // extensions are in use.
  // In this case we just ignore them.

  // §7.1.19 Determine the attestation statement format by performing a USASCII
  // case-sensitive match on fmt against the set of supported WebAuthn
  // Attestation Statement Format Identifier values. An up-to-date list of
  // registered WebAuthn Attestation Statement Format Identifier values is
  // maintained in the IANA "WebAuthn Attestation Statement Format Identifiers"
  // registry [IANA-WebAuthn-Registries] established by [RFC8809].
  LOG(INFO) << "Verify that attestation statement format provided by the "
               "client is allowed";
  if(std::find(this->fmtList.cbegin(), this->fmtList.cend(), *response->getFmt()) == this->fmtList.cend()) {
    LOG(WARNING) << "The attestation statement format is not allowed";
    DLOG(WARNING) << "The attestation statement format provided by the client "
                     "is not allowed fmt: "
                  << *response->getFmt();
    throw std::invalid_argument{
        "The attestation statement format is not allowed"};
  }

  // §7.1.20 Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and hash.
  // TODO

  // §7.1.21 If validation is successful, obtain a list of acceptable trust anchors (i.e. attestation root certificates) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.
  // FIDOMetadataService: https://w3c.github.io/webauthn/#biblio-fidometadataservice
  // TODO

  // §7.1.22 Assess the attestation trustworthiness using the outputs of the verification procedure in step 19.
  // TODO

  // §7.1.23 Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger than this many bytes SHOULD cause the RP to fail this registration ceremony.
  auto attCredData = responseAuthData->getAttestedCredentialData();
  if(attCredData->getCredentialIdLength() > 1023) {
    LOG(WARNING) << "The length of the credential id has to be <= 1023";
    DLOG(WARNING) << "The length of the credential id is: "
                  << attCredData->getCredentialIdLength();
    throw std::invalid_argument{
        "The length of the credential id has to be <= 1023"};
  }

  // Fill the instance which is inherited from CredentialRecord

  return ret;
}

template <typename T> Webauthn<T>::~Webauthn() {}

template <typename T>
bool Webauthn<T>::validateOrigin(
    const std::shared_ptr<std::string> originPtr) const {
  const std::regex reg{"https?:\\/\\/(.*?)(?=:|\\/|$)"};
  std::smatch match;

  if (!originPtr) {
    LOG(ERROR) << "Missing origin pointer";
    throw std::invalid_argument{"Missing origin pointer"};
  }
  if (std::regex_match(*originPtr, match, reg)) {
    LOG(INFO) << "Match origin directly against RP ID";
    if (match.size() == 2) {
      return match[1].str().compare(this->rp_id) == 0;
    }
  }
  return false;
}