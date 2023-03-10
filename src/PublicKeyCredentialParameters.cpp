#include "PublicKeyCredentialParameters.h"

PublicKeyCredentialParameters::PublicKeyCredentialParameters(
    COSEAlgorithmIdentifier &&alg, PublicKeyCredentialType &&type)
    : alg{alg} {
  switch (type) {
  case public_key:
    this->type = "public-key";
    break;
  }
}

PublicKeyCredentialParameters::~PublicKeyCredentialParameters() {}