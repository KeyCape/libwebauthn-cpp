#pragma once
#include "PublicKeyCredentialParameters.h"

class CredentialRecord {
protected:
  PublicKeyCredentialType type;
  std::string id;
  uint32_t signCount;
  //! Backup eligible
  /*! https://w3c.github.io/webauthn/#backup-eligibility*/
  bool be;
  //! Backup state
  /*! https://w3c.github.io/webauthn/#backup-state*/
  bool bs;

public:
  CredentialRecord();
  ~CredentialRecord();
};