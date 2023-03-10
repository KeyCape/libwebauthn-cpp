#pragma once
#include "PublicKeyCredentialParameters.h"
#include "AttestedCredentialData.h"

class CredentialRecord {
public:
  PublicKeyCredentialType type;
  std::shared_ptr<std::string> id;
  uint32_t signCount;
  std::shared_ptr<PublicKey> publicKey;
  //! Backup eligible
  /*! https://w3c.github.io/webauthn/#backup-eligibility*/
  bool be;
  //! Backup state
  /*! https://w3c.github.io/webauthn/#backup-state*/
  bool bs;

  CredentialRecord();
  ~CredentialRecord();
};