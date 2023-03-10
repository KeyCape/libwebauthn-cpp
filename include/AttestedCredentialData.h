#pragma once
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <glog/logging.h>
#include <cbor.h>

/**
 * @brief Attested credential data is a variable-length byte array added to the
 * authenticator data when generating an attestation object for a credential.
 * See: https://w3c.github.io/webauthn/#sctn-attested-credential-data
 * §6.5.2
 *
 */
class AttestedCredentialData {
private:
std::shared_ptr<std::string> aaguid;
uint16_t credentialIdLength;
std::shared_ptr<std::string> credentialId;

void extractCredentialPublicKey(const std::vector<unsigned char> &attCredData);
public:
  AttestedCredentialData(const std::vector<unsigned char> &attCredData);
  ~AttestedCredentialData();
};