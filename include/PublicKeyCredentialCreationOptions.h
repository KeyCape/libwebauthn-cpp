#pragma once
#include "AuthenticatorSelectionCriteria.h"
#include "Challenge.h"
#include "PublicKeyCredentialDescriptor.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <forward_list>
#include <algorithm>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
 *
 * The extensions attribute unsued.
 *
 */
class PublicKeyCredentialCreationOptions : IJsonSerialize {
private:
  std::shared_ptr<PublicKeyCredentialRpEntity> rp;
  std::shared_ptr<PublicKeyCredentialUserEntity> user;

  std::shared_ptr<Challenge> challenge;
  std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
      pubKeyCredParams;

  unsigned long timeout;
  std::shared_ptr<std::forward_list<PublicKeyCredentialDescriptor>>
      excludeCredentials;
  std::shared_ptr<AuthenticatorSelectionCriteria> authenticatorSelection;
  std::string attestation = "none";
  std::shared_ptr<std::forward_list<std::string>> attestationFormats;

public:
  PublicKeyCredentialCreationOptions() = delete;
  PublicKeyCredentialCreationOptions(
      std::shared_ptr<PublicKeyCredentialRpEntity> rp,
      std::shared_ptr<PublicKeyCredentialUserEntity> user,
      std::shared_ptr<Challenge> challenge,
      std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
          pubKeyCredParams);
  virtual std::unique_ptr<Json::Value> getJson() override;
  static std::shared_ptr<PublicKeyCredentialCreationOptions> fromJson(std::shared_ptr<Json::Value> json);
  const std::shared_ptr<Challenge>getChallenge() const;
  const std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>> getPublicKeyCredentialParameters() const;
  ~PublicKeyCredentialCreationOptions();
};