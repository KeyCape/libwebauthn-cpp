#pragma once
#include "IJsonSerialize.h"
#include <string>
#include <memory>

/**
 * @brief https://w3c.github.io/webauthn/#typedefdef-cosealgorithmidentifier
 *
 * This enumeration is used to restrict the algorithm kobinations used by the
 * client.
 * 
 * See: https://www.iana.org/assignments/cose/cose.xhtml
 *
 */
enum COSEAlgorithmIdentifier {
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  EDDSA = -8,
  ED25519 = 6,
  P256 = -37,
  P384 = -38,
  P521 = -39
};

enum PublicKeyCredentialType { public_key };

class PublicKeyCredentialParameters : public IJsonSerialize {
private:
  std::string type;
  COSEAlgorithmIdentifier alg;

public:
  PublicKeyCredentialParameters(); 
  PublicKeyCredentialParameters(
      COSEAlgorithmIdentifier &&alg,
      PublicKeyCredentialType &&type = PublicKeyCredentialType::public_key);
      virtual std::unique_ptr<Json::Value> getJson() override;
  ~PublicKeyCredentialParameters();
};
