#pragma once
#include "AttestedCredentialData.h"
#include <string>
#include <bitset>
#include <memory>
#include <cstring>
#include <glog/logging.h>

/**
 * @brief The AuthenticatorData encodes contextual bindings made by the
 * authenticator.
 * See: https://w3c.github.io/webauthn/#sctn-authenticator-data
 * §6.1 Authenticator Data
 *
 */
class AuthenticatorData {
private:
std::shared_ptr<std::vector<unsigned char>> authData;
std::shared_ptr<std::vector<unsigned char>> rpIdHash;
std::shared_ptr<std::bitset<8>> flags;
uint32_t signCount;
std::shared_ptr<AttestedCredentialData> attCredData;

public:
/**
 * @brief Construct a new Authenticator Data object
 * 
 * @param authData is a bytearray which has been constructed by the authenticator(Yubikey, TPM, ..) and has the following form: 
 * 
 * 32 bytes | 1 byte | 4 bytes   | variable (if present)  | variable (if present) |
 * rpIdHash | flags  | signCount | attestedCredentialData | extensions            |
 */
  AuthenticatorData(const std::vector<unsigned char>& authData);
  const std::shared_ptr<std::vector<unsigned char>> getRpIdHash() const;
  const std::shared_ptr<std::bitset<8>> getFlags() const;
  const std::shared_ptr<std::vector<unsigned char>> getAuthData() const;
  const std::shared_ptr<AttestedCredentialData> getAttestedCredentialData() const;
  const uint32_t getSignCount() const;
  ~AuthenticatorData();
};