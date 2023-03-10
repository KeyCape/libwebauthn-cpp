#pragma once
#include <cstring>
#include <glog/logging.h>
#include <memory>
#include <string>

/**
 * @brief https://www.iana.org/assignments/webauthn/webauthn.xhtml
 * WebAuthn Attestation Statement Format Identifiers
 */
class AttestationStatementFormatIdentifier {
public:
  enum type {
    packed, /*!< The "packed" attestation statement format is a
               WebAuthn-optimized format for attestation. It uses a very compact
               but still extensible encoding method. This format is
               implementable by authenticators with limited resources (e.g.,
               secure elements).*/
    tpm,    /*!< The TPM attestation statement format returns an attestation
               statement in the same format as the packed attestation statement
               format, although the rawData and signature fields are computed
               differently.*/
    android_key, /*!< Platform authenticators on versions "N", and later, may
                    provide this proprietary "hardware attestation" statement.*/
    android_safetynet, /*!< Android-based platform authenticators MAY produce an
                          attestation statement based on the Android SafetyNet
                          API.*/
    fido_u2f,          /*!< Used with FIDO U2F authenticators*/
    apple,             /*!< Used with Apple devices' platform authenticators*/
    none /*!< Used to replace any authenticator-provided attestation
                   statement when a WebAuthn Relying Party indicates it does not
                   wish to receive attestation information.*/
  };
  type attStmtFmt;
  AttestationStatementFormatIdentifier() = delete;
  AttestationStatementFormatIdentifier(type &&attStmtType);
  AttestationStatementFormatIdentifier(std::string &&attStmtType);
  std::shared_ptr<std::string> getString() const;
  ~AttestationStatementFormatIdentifier();
};

bool operator==(const AttestationStatementFormatIdentifier &lhs,
                const AttestationStatementFormatIdentifier &rhs);

std::ostream &operator<<(std::ostream &os,
                         const AttestationStatementFormatIdentifier &obj);