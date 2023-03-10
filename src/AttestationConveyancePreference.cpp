#include "AttestationConveyancePreference.h"

AttestationConveyancePreference::AttestationConveyancePreference(
    type &&attConvPref)
    : attConvPref{attConvPref} {}

std::unique_ptr<Json::Value> AttestationConveyancePreference::getJson() {
  auto json = std::make_unique<Json::Value>();
  std::string strType;

  switch (this->attConvPref) {
  case none:
    strType = "none";
    break;
  case indirect:
    strType = "indirect";
    break;
  case direct:
    strType = "direct";
    break;
  case enterprise:
    strType = "enterprise";
    break;
  }
  (*json)["attestation"] = std::move(strType);
  return json;
}

AttestationConveyancePreference::~AttestationConveyancePreference() {}