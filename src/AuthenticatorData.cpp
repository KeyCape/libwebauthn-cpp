#include "AuthenticatorData.h"

AuthenticatorData::AuthenticatorData(const std::vector<unsigned char> &authData) {
  // authData has to be at least 37 bytes. See:
  // https://w3c.github.io/webauthn/#sctn-authenticator-data
  if (authData.size() < 37) {
    LOG(ERROR) << "authData has to be at least 37 bytes long, but was only "
               << authData.size() << " long!";
    throw std::invalid_argument{"authData has to be at least 37 bytes long"};
  }
  DLOG(INFO) << "authData len: " << authData.size();

  // The hash is sha256
  // From byte [0 - 31]
  this->rpIdHash = std::make_shared<std::vector<unsigned char>>(authData.begin(),
                                                       authData.begin() + 32);
  DLOG(INFO) << "RpIdHash length: " << this->rpIdHash->size();

  LOG(INFO) << "Extract the flags from authData";
  // Byte 33
  this->flags = std::make_shared<std::bitset<8>>(authData.at(32));
  DLOG(INFO) << "The flags are: " << *this->flags;

  LOG(INFO) << "Extract the signCount from authData";
  // The signature counter is a 32-bit unsigned big-endian integer.
  memcpy(&this->signCount, authData.data() + 33, 4);
  DLOG(INFO) << "The signcount is: " << this->signCount;

  LOG(INFO) << "Check if the authenticator has added attestedCredentialData";
  // The Bit 6 of the flag indicates whether the authenticator has added
  // attestedCredentialData or not
  if (this->flags->test(6)) {
    LOG(INFO) << "attestedCredentialData found according to the flag";
    this->attCredData = std::make_shared<AttestedCredentialData>(
        std::vector<unsigned char>{authData.begin() + 37, authData.end()});
  }
}

AuthenticatorData::~AuthenticatorData() {}