#include "AttestationStatementFormatIdentifier.h"

AttestationStatementFormatIdentifier::AttestationStatementFormatIdentifier(
    type &&attStmtFmt)
    : attStmtFmt{attStmtFmt} {}

AttestationStatementFormatIdentifier::AttestationStatementFormatIdentifier(
    std::string &&attStmtFmt) {
  if (attStmtFmt.compare("packed") == 0) {
    this->attStmtFmt = packed;
  } else if (attStmtFmt.compare("tpm") == 0) {
    this->attStmtFmt = tpm;
  } else if (attStmtFmt.compare("android-key") == 0) {
    this->attStmtFmt = android_key;
  } else if (attStmtFmt.compare("android-safetynet") == 0) {
    this->attStmtFmt = android_safetynet;
  } else if (attStmtFmt.compare("fido-u2f") == 0) {
    this->attStmtFmt = fido_u2f;
  } else if (attStmtFmt.compare("apple") == 0) {
    this->attStmtFmt = apple;
  } else if (attStmtFmt.compare("none") == 0) {
    this->attStmtFmt = none;
  } else {
    LOG(ERROR) << "AttestationStatementFormatIdentifier " << attStmtFmt
               << " is invalid";
    throw std::invalid_argument{
        "AttestationStatementFormatIdentifier is invalid"};
  }
}

std::shared_ptr<std::string>
AttestationStatementFormatIdentifier::getString() const {
  auto strAttStmtFmt = std::make_shared<std::string>();

  switch (this->attStmtFmt) {
  case packed:
    *strAttStmtFmt = "packed";
    break;
  case tpm:
    *strAttStmtFmt = "tpm";
    break;
  case android_key:
    *strAttStmtFmt = "android-key";
    break;
  case android_safetynet:
    *strAttStmtFmt = "android-safetynet";
    break;
  case fido_u2f:
    *strAttStmtFmt = "fido-u2f";
    break;
  case apple:
    *strAttStmtFmt = "apple";
    break;
  case none:
    *strAttStmtFmt = "none";
    break;
  }
  return strAttStmtFmt;
}

AttestationStatementFormatIdentifier::~AttestationStatementFormatIdentifier() {}

bool operator==(const AttestationStatementFormatIdentifier &lhs,
                const AttestationStatementFormatIdentifier &rhs) {
  return lhs.attStmtFmt == rhs.attStmtFmt;
}

std::ostream &operator<<(std::ostream &os,
                         const AttestationStatementFormatIdentifier &obj) {
  return os << obj.getString();
}