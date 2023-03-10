#pragma once
#include "PublicKeyCredentialParameters.h"
#include <cbor.h>
#include <cstring>
#include <glog/logging.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <memory>
#include <string>
#include <vector>

class PublicKeyException : public std::exception {
private:
  std::string msg;

public:
  enum reason {
    MISSING_SIGNATURE,
    MISSING_SIGDATA,
    MISSING_PUBLIC_KEY,
    INVALID_CURVE,
    INVALID_ALG,
    INVALID_PUBLIC_KEY,
    INVALID_SIGNATURE
  };
  PublicKeyException() = delete;
  PublicKeyException(reason r) {
    switch (r) {
    case MISSING_SIGNATURE:
      this->msg = "The signature is missing";
      break;
    case MISSING_SIGDATA:
      this->msg = "The original data that has been signed";
      break;
    case MISSING_PUBLIC_KEY:
      this->msg = "The public key is missing";
      break;
    case INVALID_CURVE:
      this->msg = "The selected combination of curve and algorithm is invalid";
      break;
    case INVALID_ALG:
      this->msg = "The COSEAlgorithmidentifier and the COSE Key Type "
                  "combination is invalid";
      break;
    case INVALID_PUBLIC_KEY:
      this->msg = "The given public key isn't on the curve(Invalid public key)";
      break;
    case INVALID_SIGNATURE:
      this->msg = "The signature is not valid";
      break;
    }
  }
  virtual const char *what() { return this->msg.c_str(); }
};

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
namespace COSEKeyType {
enum COSEKeyType {
  RESERVED = 0,  // This value is reserved
  OKP = 1,       // Octet Key Pair
  EC2 = 2,       // Elliptic Curve Keys w/ x- and y-coordinate pair
  RSA = 3,       // RSA Key
  SYMMETRIC = 4, // Symmetric Keys
  HSS_LMS = 5,   // Public key for HSS/LMS hash-based digital signature
  WALNUT_DSA = 6 // WalnutDSA public key
};
}

/**
 * @brief Public key base class. This struct is not meant to be used standalone,
 * but to be derived from. See PublicKeyEC2.
 *
 */
struct PublicKey {
  COSEKeyType::COSEKeyType kty;             // Identification of the key type
  COSEAlgorithmIdentifier alg; // Key usage restriction to this algorithm
  virtual ~PublicKey() {}
};

/**
 * @brief Public key type for elliptic curves
 * Notice, that the attribute d(private key) is missing. The attribute d is not
 * used on the server side.
 *
 */
struct PublicKeyEC2 : public PublicKey {
  PublicKeyEC2() { this->kty = COSEKeyType::EC2; }
  virtual ~PublicKeyEC2() {}
  int crv; // EC identifier -- Taken from the "COSE Elliptic Curves" registry
  std::vector<char> x; // x-coordinate
  std::vector<char> y; // y-coordinate
  /**
   * @brief This method checks the signature according to its public key and
   * algorithm
   *
   * @param sigPtr A pointer to the signature to verify.
   * @param sigDataPtr A pointer to the original data(Not the hash).
   * @return true If the signature is valid.
   * @return false If the signature is not valid.
   */
  void checkSignature(std::shared_ptr<std::vector<uint8_t>> sigPtr,
                      std::shared_ptr<std::vector<uint8_t>> sigDataPtr) {
    // Verify data
    if (!sigPtr || sigPtr->size() == 0)
      throw PublicKeyException{PublicKeyException::MISSING_SIGNATURE};
    if (!sigDataPtr || sigDataPtr->size() == 0)
      throw PublicKeyException{PublicKeyException::MISSING_SIGDATA};
    if (this->x.size() == 0 || this->y.size() == 0) {
      throw PublicKeyException{PublicKeyException::MISSING_PUBLIC_KEY};
    }

    int errc = 0;
    unsigned char *hash = nullptr;
    size_t hashLen = 0;
    mbedtls_ecp_group_id grp;

    // Select the curve
    switch (this->alg) {
      // secp256r1
    case COSEAlgorithmIdentifier::ES256:
      // If not P-256
      if (this->crv != 1)
        throw PublicKeyException{PublicKeyException::INVALID_CURVE};
      // Calculate the hash
      hashLen = 32;
      hash = (unsigned char *)std::malloc(hashLen);
      if ((errc = mbedtls_sha256(sigDataPtr->data(), sigDataPtr->size(), hash,
                                 0)) != 0) {
        LOG(ERROR) << "An exception occured during the sha256 calculation: "
                   << mbedtls_high_level_strerr(errc);
        throw std::runtime_error{
            "An exception occured during the sha256 calculation"};
      }
      grp = MBEDTLS_ECP_DP_SECP256R1;
      break;
      // secp384r1
    case COSEAlgorithmIdentifier::ES384:
      // If not P-384
      if (this->crv != 2)
        throw PublicKeyException{PublicKeyException::INVALID_CURVE};
      // Calculate the hash
      hashLen = 48;
      hash = (unsigned char *)std::malloc(hashLen);
      if ((errc = mbedtls_sha512(sigDataPtr->data(), sigDataPtr->size(), hash,
                                 1)) != 0) {
        LOG(ERROR) << "An exception occured during the sha384 calculation: "
                   << mbedtls_high_level_strerr(errc);
        throw std::runtime_error{
            "An exception occured during the sha384 calculation"};
      }
      grp = MBEDTLS_ECP_DP_SECP384R1;
      break;
    // secp521r1
    case COSEAlgorithmIdentifier::ES512:
      // If not P-521
      if (this->crv != 3)
        throw PublicKeyException{PublicKeyException::INVALID_CURVE};
      // Calculate hash
      hashLen = 64;
      hash = (unsigned char *)std::malloc(hashLen);
      if ((errc = mbedtls_sha512(sigDataPtr->data(), sigDataPtr->size(), hash,
                                 0)) != 0) {
        LOG(ERROR) << "An exception occured during the sha512 calculation: "
                   << mbedtls_high_level_strerr(errc);
        throw std::runtime_error{
            "An exception occured during the sha512 calculation"};
      }
      grp = MBEDTLS_ECP_DP_SECP521R1;
      break;
    default:
      throw PublicKeyException{PublicKeyException::INVALID_ALG};
    }
    // Generate a valid binary key
    LOG(INFO) << "Build the public key binary";
    std::vector<unsigned char> pkBin;
    // 0x04 indicates that the binary public key is uncompressed
    pkBin.push_back(0x04);
    // Insert x point
    pkBin.insert(pkBin.cend(), this->x.cbegin(), this->x.cend());
    // Insert y point
    pkBin.insert(pkBin.cend(), this->y.cbegin(), this->y.cend());

    // Create context
    LOG(INFO) << "Generate verification context";
    mbedtls_ecdsa_context ctx_verify;
    mbedtls_ecdsa_init(&ctx_verify);
    mbedtls_ecp_group_init(&ctx_verify.private_grp);
    mbedtls_ecp_point_init(&ctx_verify.private_Q);

    // Load elliptic curve
    LOG(INFO) << "Load elliptic curve group";
    if ((errc = mbedtls_ecp_group_load(&ctx_verify.private_grp, grp)) != 0) {
      LOG(ERROR) << mbedtls_high_level_strerr(errc);
      throw std::runtime_error{"Couldn't load mbedtls ecc group"};
    }

    // Read elliptoc curve point
    LOG(INFO) << "Read elliptic curve point from binary";
    if ((errc = mbedtls_ecp_point_read_binary(
             &ctx_verify.private_grp, &ctx_verify.private_Q, pkBin.data(),
             pkBin.size())) != 0) {
      LOG(ERROR) << mbedtls_high_level_strerr(errc);
      throw std::runtime_error{"Couldn't load the public key from binary"};
    }

    // Check the ec public key
    LOG(INFO) << "Verify the public key";
    if ((errc = mbedtls_ecp_check_pubkey(&ctx_verify.private_grp,
                                         &ctx_verify.private_Q)) != 0) {
      LOG(ERROR) << mbedtls_high_level_strerr(errc);
      throw PublicKeyException{PublicKeyException::MISSING_PUBLIC_KEY};
    }

    LOG(INFO) << "Verify the signature";
    if ((errc = mbedtls_ecdsa_read_signature(&ctx_verify, hash, hashLen,
                                             sigPtr->data(), sigPtr->size())) !=
        0) {
      LOG(ERROR) << mbedtls_high_level_strerr(errc);
      if (errc == MBEDTLS_ERR_ECP_BAD_INPUT_DATA)
        throw PublicKeyException{PublicKeyException::INVALID_SIGNATURE};
      throw std::runtime_error{"An exception occured during the signature read "
                               "and validation operation"};
    }

    // Free memory
    free(hash);
    mbedtls_ecp_group_free(&ctx_verify.private_grp);
    mbedtls_ecp_point_free(&ctx_verify.private_Q);
    mbedtls_ecdsa_free(&ctx_verify);
  }
};

/**
 * @brief Public key type for RSA
 *
 * Notice, that not all available attributes from [RFC9053] are implemented,
 * because the are not used here.
 *
 */
struct PublicKeyRSA : public PublicKey {
  PublicKeyRSA() { this->kty = COSEKeyType::RSA; }
  std::vector<char> n; // The RSA modulus n
  std::vector<char> e; // The RSA public exponent e
};
