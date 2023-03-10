#pragma once
#include "Challenge.h"
#include "IJsonSerialize.h"
#include "PublicKeyCredentialDescriptor.h"
#include <forward_list>
#include <memory>
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#enum-userVerificationRequirement
 * A WebAuthn Relying Party may require user verification for some of its
 * operations but not for others, and may use this type to express its needs.
 */
enum UserVerificationRequirement { required, preferred, discouraged };

/**
 * @brief https://w3c.github.io/webauthn/#enum-attestation-convey
 *
 * WebAuthn Relying Parties may use AttestationConveyancePreference to specify
 * their preference regarding attestation conveyance during credential
 * generation.
 *
 */
enum AttestationConveyancePreference { none, indirect, direct, enterprise };

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-assertion-options
 *
 * The PublicKeyCredentialRequestOptions dictionary supplies get() with the data
 * it needs to generate an assertion. Its challenge member MUST be present,
 * while its other members are OPTIONAL.
 *
 * This is the response to a /login/begin
 *
 */
class PublicKeyCredentialRequestOptions : public IJsonSerialize {
private:
  std::shared_ptr<Challenge> challenge;
  std::shared_ptr<unsigned long> timeout;
  std::shared_ptr<std::string> rpId;
  std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
      allowCredentials;
  std::shared_ptr<UserVerificationRequirement> userVerification;
  std::shared_ptr<AttestationConveyancePreference> attestation;
  std::shared_ptr<std::forward_list<std::string>> attestationFormats;

  // Note: AuthenticationExtensionsClientInputs extensions; is not defined,
  // because it's not used here.

public:
  PublicKeyCredentialRequestOptions() = delete;
  PublicKeyCredentialRequestOptions(
      std::shared_ptr<Challenge> challenge,
      std::shared_ptr<unsigned long> timeout, std::shared_ptr<std::string> rpId,
      std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
          allowCredentials,
      std::shared_ptr<UserVerificationRequirement> userVerification,
      std::shared_ptr<AttestationConveyancePreference> attestation,
      std::shared_ptr<std::forward_list<std::string>> attestationFormats);
  virtual std::unique_ptr<Json::Value> getJson() override;
  const std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
  getAllowedCredentials();
  const std::shared_ptr<Challenge> getChallenge();
  bool hasCredential(const std::string &id) const;
  ~PublicKeyCredentialRequestOptions();
};
