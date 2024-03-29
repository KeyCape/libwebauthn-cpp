#pragma once
#include "AuthenticatorAssertionResponse.h"
#include "Base64Url.h"
#include "PublicKeyCredential.h"
#include "PublicKeyCredentialCreationOptions.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRequestOptions.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <CredentialRecord.h>
#include <glog/logging.h>
#include <iomanip>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <openssl/sha.h>
#include <string>
#include <type_traits>
#include <utility>

/**
 * @brief Webauthn policy
 */
struct Policy {
  /**
   * @brief Timeout in milliseconds
   *
   * This OPTIONAL member specifies a time, in milliseconds, that the Relying
   * Party is willing to wait for the call to complete. This is treated as a
   * hint, and MAY be overridden by the client.
   */
  std::shared_ptr<unsigned long> timeout;
  std::shared_ptr<UserVerificationRequirement> userVerification = nullptr;
  std::shared_ptr<AttestationConveyancePreference> attestation = nullptr;
  std::shared_ptr<std::forward_list<AttestationStatementFormatIdentifier>>
      attStmtFmts = nullptr;
};

template <typename T> class Webauthn {
private:
  std::shared_ptr<std::string> rp_name;
  std::shared_ptr<std::string> rp_id;
  std::shared_ptr<std::vector<unsigned char>> rp_id_hash;
  std::shared_ptr<Policy> policy;

  bool validateOrigin(const std::shared_ptr<std::string> originPtr) const;

public:
  Webauthn() = delete;
  Webauthn(std::shared_ptr<std::string> name, std::shared_ptr<std::string> id,
           std::shared_ptr<Policy> policy);
  std::shared_ptr<PublicKeyCredentialCreationOptions>
  beginRegistration(std::string &username);
  std::shared_ptr<T> finishRegistration(
      std::shared_ptr<PublicKeyCredentialCreationOptions> options,
      std::shared_ptr<Json::Value> request);
  std::shared_ptr<PublicKeyCredentialRequestOptions>
  beginLogin(std::shared_ptr<std::forward_list<CredentialRecord>> user);
  std::forward_list<CredentialRecord>::iterator finishLogin(
      std::shared_ptr<PublicKeyCredential<AuthenticatorAssertionResponse>>
          pKeyCred,
      std::shared_ptr<PublicKeyCredentialRequestOptions> pkeyCredReq,
      std::shared_ptr<std::forward_list<CredentialRecord>> credRec);
  void setRpId(std::string &id);
  void setRpName(std::string &name);
  ~Webauthn();
};

/**
 * @brief Create an instance of a relying party.
 * @param name This is the name of the relying party.
 * @param id This is the id of the relying party, which is transfered to the
 * WebAgent.
 * @param policy This parameter is OPTIONAL. Use this to enforce the security.
 */
template <typename T>
Webauthn<T>::Webauthn(std::shared_ptr<std::string> name,
                      std::shared_ptr<std::string> id,
                      std::shared_ptr<Policy> policy) {
  static_assert(std::is_base_of_v<CredentialRecord, T>,
                "The return type of finishRegistration(..) must be a child of "
                "the class CredentialRecord");

  // Initialize empty policy
  this->policy = policy;
  if (!this->policy) {
    this->policy = std::make_shared<Policy>();
  }

  // Verify policy
  if (!this->policy->attestation) {
    LOG(WARNING) << "Missing policy.attestation. Defaulting to none";
    this->policy->attestation =
        std::make_shared<AttestationConveyancePreference>(
            AttestationConveyancePreference::none);
  }

  if (!this->policy->attStmtFmts) {
    LOG(WARNING) << "Missing policy.attStmtFmts. Defaulting to []";
    this->policy->attStmtFmts = std::make_shared<
        std::forward_list<AttestationStatementFormatIdentifier>>();
  }

  if (!this->policy->userVerification) {
    LOG(WARNING) << "Missing policy.userVerification. Defaulting to preferred";
    this->policy->userVerification =
        std::make_shared<UserVerificationRequirement>(
            UserVerificationRequirement::preferred);
  }

  if (!this->policy->timeout) {
    this->policy->timeout = std::make_shared<unsigned long>(0);
  }

  if (!name) {
    LOG(ERROR) << "The relying party name must not be null";
    throw std::invalid_argument{"The relying party name must not be null"};
  }

  if (!id) {
    LOG(ERROR) << "The relying party id must not be null";
    throw std::invalid_argument{"The relying party id must not be null"};
  }

  this->setRpName(*name);
  this->setRpId(*id);
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
      PublicKeyCredentialRpEntity(std::forward<std::string>(*this->rp_name),
                                  std::forward<std::string>(*this->rp_id)));

  auto user = std::make_shared<PublicKeyCredentialUserEntity>(
      PublicKeyCredentialUserEntity{std::forward<std::string>(username),
                                    std::forward<std::string>(username),
                                    std::forward<std::string>(username)});

  auto challenge = std::make_shared<Challenge>(Challenge{});

  auto params =
      std::make_shared<std::forward_list<PublicKeyCredentialParameters>>(
          std::forward_list<PublicKeyCredentialParameters>(
              {PublicKeyCredentialParameters{COSEAlgorithmIdentifier::ES512},
               PublicKeyCredentialParameters{COSEAlgorithmIdentifier::ES384},
               PublicKeyCredentialParameters{COSEAlgorithmIdentifier::ES256}}));

  auto ret = std::make_shared<PublicKeyCredentialCreationOptions>(
      rp, user, challenge, params, this->policy->attStmtFmts,
      this->policy->attestation);

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

  PublicKeyCredential<AuthenticatorAttestationResponse> pkeyCred;
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
                 << " but should have been: " << *this->rp_id;
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

  // if (this->rp_id_hash->compare(0, responseAuthDataRpIdHash->size(),
  //                               responseAuthDataRpIdHash->data()) != 0) {
  if (*this->rp_id_hash != *responseAuthDataRpIdHash) {
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
  if (this->policy->attStmtFmts->empty()) {
    LOG(WARNING)
        << "No attestation statement format has been specified. It's "
           "recommended to set at least one attestation statement format!";
  } else {
    if (std::find(this->policy->attStmtFmts->cbegin(),
                  this->policy->attStmtFmts->cend(),
                  *response->getFmt()) == this->policy->attStmtFmts->cend()) {
      LOG(WARNING) << "The attestation statement format is not allowed";
      DLOG(WARNING)
          << "The attestation statement format provided by the client "
             "is not allowed fmt: "
          << *response->getFmt()->getString();
      throw std::invalid_argument{
          "The attestation statement format is not allowed"};
    }

    // §7.1.20 Verify that attStmt is a correct attestation statement, conveying
    // a valid attestation signature, by using the attestation statement format
    // fmt’s verification procedure given attStmt, authData and hash.
    LOG(INFO) << "Verify that the attestation statement is valid";
    response->verifyAttStmt();
  }

  // §7.1.21 If validation is successful, obtain a list of acceptable trust
  // anchors (i.e. attestation root certificates) for that attestation type and
  // attestation statement format fmt, from a trusted source or from policy. For
  // example, the FIDO Metadata Service [FIDOMetadataService] provides one way
  // to obtain such information, using the aaguid in the attestedCredentialData
  // in authData. FIDOMetadataService:
  // https://w3c.github.io/webauthn/#biblio-fidometadataservice
  // TODO

  // §7.1.22 Assess the attestation trustworthiness using the outputs of the
  // verification procedure in step 19.
  // TODO

  // §7.1.23 Verify that the credentialId is ≤ 1023 bytes. Credential IDs larger
  // than this many bytes SHOULD cause the RP to fail this registration
  // ceremony.
  LOG(INFO) << "Verify that the credentialId is ≤ 1023 bytes";
  auto attCredData = responseAuthData->getAttestedCredentialData();
  if (attCredData->getCredentialIdLength() > 1023) {
    LOG(WARNING) << "The length of the credential id has to be <= 1023";
    DLOG(WARNING) << "The length of the credential id is: "
                  << attCredData->getCredentialIdLength();
    throw std::invalid_argument{
        "The length of the credential id has to be <= 1023"};
  }

  // Fill the instance which is inherited from CredentialRecord
  // Should be replaced by authData->getType(), but the response is string.
  ret->type = PublicKeyCredentialType::public_key;
  ret->id = attCredData->getCredentialId();
  ret->signCount = responseAuthData->getSignCount();
  ret->publicKey = attCredData->getPublicKey();
  ret->bs = responseAuthData->getBackupState();
  ret->be = responseAuthData->getBackupEligibility();

  return ret;
}

/**
 * @brief This method is called in order to start the authentication ceremony
 * for a registered credential.
 *
 * See: https://w3c.github.io/webauthn/#sctn-verifying-assertion §7.2
 *
 * @tparam T The type is of base class CredentialRecord
 * @param username The unique username
 * @return std::shared_ptr<PublicKeyCredentialRequestOptions>
 */
template <typename T>
std::shared_ptr<PublicKeyCredentialRequestOptions> Webauthn<T>::beginLogin(
    std::shared_ptr<std::forward_list<CredentialRecord>> user) {
  LOG(INFO) << "Beginning with the credential authentication ceremony";
  if (!user) {
    throw std::runtime_error{"The user must NOT be NULL"};
  }

  // §7.2.1 Let options be a new PublicKeyCredentialRequestOptions structure
  // configured to the Relying Party's needs for the ceremony.
  auto challenge = std::make_shared<Challenge>();
  auto allowCredentials =
      std::make_shared<std::forward_list<PublicKeyCredentialDescriptor>>();

  std::transform(
      user->cbegin(), user->cend(), std::front_inserter(*allowCredentials),
      [](CredentialRecord record) {
        if (!record.id) {
          LOG(ERROR) << "Missing the credential id";
          throw std::invalid_argument{"Missing the credential id"};
        }
        std::string tmpType = "";

        switch (record.type) {
        case public_key:
          tmpType = "public-key";
          break;
        }
        DLOG(INFO) << "Found credential \tid: " << record.id
                   << "\ttype: " << tmpType;
        return PublicKeyCredentialDescriptor(
            std::move(tmpType), std::forward<std::string>(*record.id));
      });

  return std::make_shared<PublicKeyCredentialRequestOptions>(
      challenge, this->policy->timeout, this->rp_id, allowCredentials,
      this->policy->userVerification, this->policy->attestation,
      this->policy->attStmtFmts);
}

/**
 * @brief This method is called in order to finish the login cermony.
 *
 * See: https://w3c.github.io/webauthn/#sctn-verifying-assertion §7.2
 * Starting from §7.2.3
 *
 * @tparam T The type is of base class CredentialRecord
 * @param pKeyCred The response of the client
 * @param pkeyCredReq The response from webauthn<T>::beginLogin(..)
 * @param credRec The users credential record
 */
template <typename T>
std::forward_list<CredentialRecord>::iterator Webauthn<T>::finishLogin(
    std::shared_ptr<PublicKeyCredential<AuthenticatorAssertionResponse>>
        pKeyCred,
    std::shared_ptr<PublicKeyCredentialRequestOptions> pkeyCredReq,
    std::shared_ptr<std::forward_list<CredentialRecord>> credRec) {
  LOG(INFO) << "Finish the credential authentication ceremony";

  // Notice that this if-expression does not apply to credRec. See below: §7.2.6
  if (!pKeyCred || !pkeyCredReq) {
    throw std::invalid_argument{"Neither pKeyCred nor pkeyCredReq can be NULL"};
  }
  if (!credRec || credRec->empty()) {
    throw std::invalid_argument{"Missing CredentialRecord"};
  }

  LOG(INFO) << "Check if there has been provided credential ids to be used by "
               "the client";
  auto allowCredentials = pkeyCredReq->getAllowedCredentials();
  auto reqId = pKeyCred->getId();
  auto authenticatorAssertionResponse = pKeyCred->getResponse();
  if (!authenticatorAssertionResponse) {
    throw std::invalid_argument{
        "Missing AuthenticatorAssertionResponse. Check whether the "
        "response field is provided or not."};
  }

  // §7.2.5 If options.allowCredentials is not empty, verify that credential.id
  // identifies one of the public key credentials listed in
  // options.allowCredentials.
  if (allowCredentials) {
    LOG(INFO) << "The user has been provided credential IDs";
    if (!pkeyCredReq->hasCredential(reqId)) {
      throw std::invalid_argument{
          "The used credentials id doesn't match the list provided by the RP"};
    }
    LOG(INFO) << "Found match for the provided credential id";
  }

  // §7.2.6 Identify the user being authenticated and let credentialRecord be
  // the credential record for the credential.
  // Notice: There are two paths.
  // 1. The user was identified before the authentication ceremony was
  // initiated, e.g., via a username or cookie. If this is the case, the
  // parameter credRec can be NULL. If it's present, then the userHandle is
  // validated against it.
  // 2. The user was not identified before the authentication ceremony was
  // initiated. In this case the credRec must NOT be NULL. CAUTION: In either
  // case the backend implementation has to do some preparation.
  // CASE 1: During  beginLogin the client has received a list with
  // allowedCredentials. Before calling finishLogin fill credRec with the
  // appropriate credential(List size=1).
  // CASE 2: The client hasn't received a list with allowdCredentials. The
  // userHandle specifies the account and the backend fills the list with all
  // registered credentials for the user account.

  // The identification in both cases is done by the backend and checked here
  // again(credRec must at least hold one element).
  LOG(INFO)
      << "Check if the provided credential id belongs to the user account";
  auto credRecIt = credRec->begin();
  for (; credRecIt != credRec->end(); ++credRecIt) {
    DLOG(INFO) << "Comparing credential id:\t" << *credRecIt->id << " with:\t"
               << reqId;
    if (credRecIt->id->compare(reqId) == 0) {
      LOG(INFO) << "The provided credential id belongs to the user account";
      break;
    }
  }
  if (credRecIt == credRec->cend()) {
    LOG(WARNING)
        << "The provided credential id doesn't belong to the user account";
    throw std::invalid_argument{
        "The provided credential id doesn't belong to the user account"};
  }

  LOG(INFO) << "Check if the userHandle is set";
  auto userHandle = authenticatorAssertionResponse->getUserHandle();
  if (userHandle && userHandle->compare(*credRecIt->uName) != 0) {
    LOG(WARNING)
        << "UserHandle is present. And dosent't  match the user account";
    DLOG(WARNING) << "The userHandle is " << *userHandle
                  << " but should have been " << *credRecIt->uName;
  }
  // §7.2.10 Verify that the value of C.type is the string webauthn.get.
  auto cType = authenticatorAssertionResponse->getType();
  if (!cType || cType->compare("webauthn.get") != 0) {
    LOG(WARNING) << "The type of AuthenticatorResponse has to be webauthn.get";
    DLOG(WARNING)
        << "The type of AuthenticatorResponse has to be webauthn.get but was "
        << *cType;
    throw std::invalid_argument{
        "The type of respose.type has to be webauthn.get"};
  }

  // §7.2.11 Verify that the value of C.challenge equals the base64url encoding
  // of options.challenge.
  LOG(INFO) << "Verify that the value of C.challenge equals the base64url "
               "encoding of options.challenge.";
  auto cChallenge = authenticatorAssertionResponse->getChallenge();
  auto oChallenge = pkeyCredReq->getChallenge();
  oChallenge->encodeBase64Url();
  if (!cChallenge || !oChallenge) {
    LOG(WARNING) << "Missing one of the challenges";
    DLOG(WARNING) << "Challenges: cChallenge addr: " << cChallenge
                  << " oChallenge addr: " << oChallenge;
    throw std::invalid_argument{"Missing cChallenge or oChallenge"};
  }
  if (*oChallenge != *cChallenge) {
    LOG(WARNING) << "The challenges doesn't match";
    DLOG(WARNING) << "The challenges doesn't match cChallenge: " << *cChallenge
                  << " oChallenge: " << *oChallenge;
    throw std::invalid_argument{"The challenges doesn't match"};
  }

  // §7.2.12 Verify that the value of C.origin matches the Relying Party's
  // origin.
  LOG(INFO)
      << "Verify that the value of C.origin matches the Relying Party's origin";
  if (!this->validateOrigin(authenticatorAssertionResponse->getOrigin())) {
    LOG(WARNING) << "The origin doesn't match the RPs origin";
    throw std::invalid_argument{"The origin doesn't match the RPs origin"};
  }

  // §7.2.13 Verify that the rpIdHash in authData is the SHA-256 hash of the RP
  // ID expected by the Relying Party.
  LOG(INFO) << "Verify that the rpIdHash in authData is the SHA-256 hash of "
               "the RP ID expected by the Relying Party";
  auto authData = authenticatorAssertionResponse->getAuthenticatorData();
  if (!authData) {
    LOG(WARNING) << "Missing AuthenticatorData in response";
    throw std::invalid_argument{"Missing AuthenticatorData in response"};
  }
  auto authDataRpIdHash = authData->getRpIdHash();
  if (!authDataRpIdHash) {
    LOG(WARNING) << "Missing rpIdHash in AuthenticatorData";
    throw std::invalid_argument{"Missing rpIdHash in AuthenticatorData"};
  }
  if (*authDataRpIdHash != *this->rp_id_hash) {
    LOG(WARNING)
        << "The given rpIdHash doesn't match the SHA256 hash of the RPs id";
    throw std::invalid_argument{
        "The given rpIdHash doesn't match the SHA256 hash of the RPs id"};
  }

  // §7.2.14 Verify that the UP(User Present) bit of the flags in authData is
  // set.
  auto authDataFlags = authData->getFlags();
  if (!authDataFlags) {
    LOG(WARNING) << "Missing flags in AuthenticatorData";
    throw std::invalid_argument{"Missing flags in AuthenticatorData"};
  }
  if (!authDataFlags->test(0)) {
    LOG(WARNING) << "The User Present flag is false but has to be true";
    throw std::invalid_argument{
        "The User Present flag is false but has to be true"};
  }

  // §7.2.15 If the Relying Party requires user verification for this assertion,
  // verify that the UV(User Verified) bit of the flags in authData is set.
  if (*this->policy->userVerification ==
          UserVerificationRequirement::required &&
      !authDataFlags->test(2)) {
    LOG(WARNING) << "The RP requires that the User Verification flag is set to "
                    "true, but it's not";
    throw std::invalid_argument{"The RP requires that the User Verification "
                                "flag is set to true, but it's not"};
  }

  // §7.2.16 If the credential backup state is used as part of Relying Party
  // business logic or policy, let currentBe and currentBs be the values of the
  // BE and BS bits, respectively, of the flags in authData. Compare currentBe
  // and currentBs with credentialRecord.backupEligible and
  // credentialRecord.backupState and apply Relying Party policy, if any.
  // TODO: There should be some kind of functors passed as argument during the
  // initialization of Webauthn.
  DLOG(INFO) << "CredentialRecord backup eligible: " << credRecIt->be;
  DLOG(INFO) << "CredentialRecord backup state: " << credRecIt->bs;

  // §7.2.17 Verify that the values of the client extension outputs in
  // clientExtensionResults and the authenticator extension outputs in the
  // extensions in authData are as expected, considering the client extension
  // input values that were given in options.extensions and any specific policy
  // of the Relying Party regarding unsolicited extensions, i.e., those that
  // were not specified as part of options.extensions. In the general case, the
  // meaning of "are as expected" is specific to the Relying Party and which
  // extensions are in use.
  // NOTE: This implementation dosen't use extensions

  // §7.2.18 Let hash be the result of computing a hash over the cData using
  // SHA-256.
  auto clientDataJSON = authenticatorAssertionResponse->getClientDataJSON();
  unsigned char *hash = (unsigned char *)std::malloc(32);
  mbedtls_sha256(reinterpret_cast<uint8_t *>(clientDataJSON->data()),
                 clientDataJSON->size(), hash, 0);
  auto sigData = std::make_shared<std::vector<unsigned char>>(
      *authenticatorAssertionResponse->getAuthenticatorData()->getAuthData());
  for (int i = 0; i < 32; ++i) {
    sigData->push_back(hash[i]);
  }

  DLOG(INFO) << "SHA256: " << [&]() {
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
  }();

  free(hash);

  // §7.2.19 Using credentialRecord.publicKey, verify that sig is a valid
  // signature over the binary concatenation of authData and hash.
  std::shared_ptr<PublicKeyEC2> pkPtr =
      static_pointer_cast<PublicKeyEC2>(credRecIt->publicKey);

  pkPtr->checkSignature(authenticatorAssertionResponse->getSignature(),
                        sigData);
  LOG(INFO) << "The signature is valid";

  /* §7.2.20 If authData.signCount is nonzero or credentialRecord.signCount is
    nonzero, then run the following sub-step:
    -> If authData.signCount is
        -> greater than credentialRecord.signCount:
            The signature counter is valid.
        -> less than or equal to credentialRecord.signCount:
            This is a signal that the authenticator may be cloned, i.e. at least
            two copies of the credential private key may exist and are being
            used in parallel.  Relying Parties should incorporate this
            information into their risk scoring.  Whether the Relying Party
            updates credentialRecord.signCount below in this case, or not, or
            fails the authentication ceremony or not, is Relying Party-specific.
  */
  auto authDataSignCount = authData->getSignCount();
  LOG(INFO) << "Check that the signature count is greater than the saved";
  DLOG(INFO) << "credentialRecord.signcount: " << credRecIt->signCount;
  DLOG(INFO) << "authData.signCount: " << authDataSignCount;

  if (!(authDataSignCount > credRecIt->signCount)) {
    if (authDataSignCount == 0 && credRecIt->signCount == 0) {
      LOG(WARNING) << "THE STORED SIGNATURE COUNT AND THE PASSED ARE BOTH 0!!. "
                      "For more security this should be prohibited!";
    } else {
      LOG(ERROR) << "The signature count doesn't match is too low. The "
                    "authenticator may be cloned";
      throw std::invalid_argument{
          "The signature count doesn't match is too low. "
          "The authenticator may be cloned"};
    }
  }

  // §7.2.21 If response.attestationObject is present and the Relying Party
  // wishes to verify the attestation then perform CBOR decoding on
  // attestationObject to obtain the attestation statement format fmt, and the
  // attestation statement attStmt.

  /* §7.2.22 Update credentialRecord with new state values:
      1. Update credentialRecord.signCount to the value of authData.signCount
      2. Update credentialRecord.backupState to the value of currentBs.
  */
  credRecIt->signCount = authDataSignCount;
  credRecIt->bs = authData->getBackupState();

  return credRecIt;
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
      return match[1].str().compare(*this->rp_id) == 0;
    }
  }
  return false;
}

template <typename T> void Webauthn<T>::setRpId(std::string &id) {
  this->rp_id = std::make_shared<std::string>(id);
  // Calculate the hash of the relying partys id
  unsigned char *hashPtr = SHA256((const unsigned char *)this->rp_id->data(),
                                  this->rp_id->size(), NULL);
  this->rp_id_hash =
      std::make_shared<std::vector<unsigned char>>(hashPtr, hashPtr + 32);

  LOG(INFO) << "The relying party id is now: " << id;
}

template <typename T> void Webauthn<T>::setRpName(std::string &name) {
  this->rp_name = std::make_shared<std::string>(name);
  LOG(INFO) << "The relying party name is now: " << name;
}