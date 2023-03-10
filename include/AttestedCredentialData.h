#pragma once
#include "PublicKeyCredentialParameters.h"
#include <cbor.h>
#include <cstring>
#include <glog/logging.h>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Attested credential data is a variable-length byte array added to the
 * authenticator data when generating an attestation object for a credential.
 * See: https://w3c.github.io/webauthn/#sctn-attested-credential-data
 * §6.5.2
 *
 */
struct PublicKey;
class AttestedCredentialData {
private:
  std::shared_ptr<std::string> aaguid;
  uint16_t credentialIdLength;
  std::shared_ptr<std::string> credentialId;
  std::shared_ptr<PublicKey>
      pkey; // The authenticators public key, which is used to sign

  void
  extractCredentialPublicKey(const std::vector<unsigned char> &attCredData);
  void jumpToMapLabel(int &&label, CborValue *it);
  void storePublicKeyEC2(CborValue &map);

public:
  AttestedCredentialData(const std::vector<unsigned char> &attCredData);
  const std::shared_ptr<PublicKey> getPublicKey() const;
  uint16_t getCredentialIdLength() const;
  const std::shared_ptr<std::string> getCredentialId() const;
  ~AttestedCredentialData();
};

/**
 * @brief See: https://www.iana.org/assignments/cose/cose.xhtml
 *
 * Section COSE Key Types
 *
 */
enum COSEKeyType {
  RESERVED = 0,  // This value is reserved
  OKP = 1,       // Octet Key Pair
  EC2 = 2,       // Elliptic Curve Keys w/ x- and y-coordinate pair
  RSA = 3,       // RSA Key
  SYMMETRIC = 4, // Symmetric Keys
  HSS_LMS = 5,   // Public key for HSS/LMS hash-based digital signature
  WALNUT_DSA = 6 // WalnutDSA public key
};

/**
 * @brief Public key base class. This struct is not meant to be used standalone,
 * but to be derived from. See PublicKeyEC2.
 *
 */
struct PublicKey {
  COSEKeyType kty;             // Identification of the key type
  COSEAlgorithmIdentifier alg; // Key usage restriction to this algorithm
};

/**
 * @brief Public key type for elliptic curves
 * Notice, that the attribute d(private key) is missing. The attribute d is not
 * used on the server side.
 *
 */
struct PublicKeyEC2 : public PublicKey {
  PublicKeyEC2() { this->kty = COSEKeyType::EC2; }
  int crv; // EC identifier -- Taken from the "COSE Elliptic Curves" registry
  std::vector<char> x; // x-coordinate
  std::vector<char> y; // y-coordinate
};

/**
 * @brief Public key type for RSA
 *
 * Notice, that not all available attributes from [RFC9053] are implemented,
 * because the are not used here.
 *
 */
struct PublicKeyRSA : public PublicKey {
  std::vector<char> n; // The RSA modulus n
  std::vector<char> e; // The RSA public exponent e
};
