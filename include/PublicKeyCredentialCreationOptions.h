#pragma once
#include "AuthenticatorSelectionCriteria.h"
#include "Challenge.h"
#include "PublicKeyCredentialDescriptor.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <forward_list>

/**
 * @brief https://w3c.github.io/webauthn/#dictionary-makecredentialoptions
 *
 * The extensions attribute unsued.
 *
 */
class PublicKeyCredentialCreationOptions {
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
      std::shared_ptr<PublicKeyCredentialRpEntity> &rp,
      std::shared_ptr<PublicKeyCredentialUserEntity> &user,
      std::shared_ptr<Challenge> &challenge,
      std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
          &pubKeyCredParams);
  ~PublicKeyCredentialCreationOptions();
};