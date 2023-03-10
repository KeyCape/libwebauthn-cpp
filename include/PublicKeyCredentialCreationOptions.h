#pragma once
#include "AttestationStatementFormatIdentifier.h"
#include "AuthenticatorSelectionCriteria.h"
#include "Challenge.h"
#include "PublicKeyCredentialDescriptor.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRequestOptions.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <algorithm>
#include <drogon/utils/Utilities.h>
#include <forward_list>
#include <glog/logging.h>

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
  std::shared_ptr<AttestationConveyancePreference> attestation;
  std::shared_ptr<std::forward_list<AttestationStatementFormatIdentifier>>
      attestationFormats;

public:
  PublicKeyCredentialCreationOptions() = delete;
  PublicKeyCredentialCreationOptions(
      std::shared_ptr<PublicKeyCredentialRpEntity> rp,
      std::shared_ptr<PublicKeyCredentialUserEntity> user,
      std::shared_ptr<Challenge> challenge,
      std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
          pubKeyCredParams,
      std::shared_ptr<std::forward_list<AttestationStatementFormatIdentifier>>
          attestationFormats,
      std::shared_ptr<AttestationConveyancePreference> attestation);
  virtual std::unique_ptr<Json::Value> getJson() override;
  static std::shared_ptr<PublicKeyCredentialCreationOptions>
  fromJson(std::shared_ptr<Json::Value> json);
  const std::shared_ptr<Challenge> getChallenge() const;
  const std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
  getPublicKeyCredentialParameters() const;
  const std::shared_ptr<PublicKeyCredentialUserEntity>
  getPublicKeyCredentialUserEntity() const;
  ~PublicKeyCredentialCreationOptions();
};