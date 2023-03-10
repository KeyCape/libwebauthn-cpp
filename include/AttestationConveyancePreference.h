#pragma once
#include "IJsonSerialize.h"
#include <jsoncpp/json/value.h>

/**
 * @brief https://w3c.github.io/webauthn/#enum-attestation-convey
 *
 * WebAuthn Relying Parties may use AttestationConveyancePreference to specify
 * their preference regarding attestation conveyance during credential
 * generation.
 *
 */
class AttestationConveyancePreference : public IJsonSerialize {
public:
  enum type { none, indirect, direct, enterprise };
  AttestationConveyancePreference() = delete;
  AttestationConveyancePreference(type &&attConvPref);
  virtual std::unique_ptr<Json::Value> getJson();
  ~AttestationConveyancePreference();

private:
  type attConvPref;
};