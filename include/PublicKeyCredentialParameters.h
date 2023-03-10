#pragma once
#include <string>

/**
 * @brief https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
 *
 * This enumeration is used to restrict the algorithm kobinations used by the
 * client.
 *
 */
enum COSEAlgorithmIdentifier {
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  EDDSA = -8,
  ED25519 = 6,
  P256 = 1,
  P384 = 2,
  P521 = 3
};

enum PublicKeyCredentialType { public_key };

class PublicKeyCredentialParameters {
private:
  std::string type;
  COSEAlgorithmIdentifier alg;

public:
  PublicKeyCredentialParameters(
      COSEAlgorithmIdentifier &&alg,
      PublicKeyCredentialType &&type = PublicKeyCredentialType::public_key);
  ~PublicKeyCredentialParameters();
};
