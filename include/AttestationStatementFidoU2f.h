#pragma once
#include <Base64Url.h>
#include <IAttestationStatement.h>
#include <drogon/utils/Utilities.h>
#include <glog/logging.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <memory>
#include <vector>

/**
 * @brief This attestation statement format is used with FIDO U2F authenticators
 * using the formats defined in
 * https://w3c.github.io/webauthn/#biblio-fido-u2f-message-formats
 * See: https://w3c.github.io/webauthn/#sctn-fido-u2f-attestation
 * §8.6 FIDO U2F Attestation Statement Format
 *
 */
class AttestationStatementFidoU2f : public IAttestationStatement {
private:
  std::shared_ptr<std::vector<unsigned char>> attStmt;
  std::shared_ptr<std::vector<uint8_t>> sig;
  std::shared_ptr<std::vector<uint8_t>> x5c;

public:
  AttestationStatementFidoU2f();
  virtual void
  verify(const std::shared_ptr<AuthenticatorData> authData,
         const std::shared_ptr<std::string> clientDataJSON) const override;
  virtual void extractFromCBOR(std::shared_ptr<CborValue> attStmt);
  ~AttestationStatementFidoU2f();
};