#pragma once
#include <glog/logging.h>
#include <jsoncpp/json/value.h>

/**
 * @brief https://w3c.github.io/webauthn/#enum-attestation-convey
 *
 * WebAuthn Relying Parties may use AttestationConveyancePreference to specify
 * their preference regarding attestation conveyance during credential
 * generation.
 *
 */
class AttestationConveyancePreference {
public:
  enum type { none, indirect, direct, enterprise };
  AttestationConveyancePreference() = delete;
  AttestationConveyancePreference(type &&attConvPref);
  AttestationConveyancePreference(std::string &strAttConvPref);
  std::shared_ptr<std::string> getString() const;
  ~AttestationConveyancePreference();

private:
  type attConvPref;
};