#pragma once
#include <AuthenticatorData.h>
#include <cbor.h>
#include <memory>
#include <vector>

class IAttestationStatement {
public:
  IAttestationStatement() {}
  virtual void
  verify(const std::shared_ptr<AuthenticatorData> authData,
         const std::shared_ptr<std::string> clientDataJSON) const = 0;
  virtual void extractFromCBOR(std::shared_ptr<CborValue> attStmt) = 0;
  ~IAttestationStatement() {}
};