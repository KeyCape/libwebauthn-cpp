#include "AttestationConveyancePreference.h"

AttestationConveyancePreference::AttestationConveyancePreference(
    type &&attConvPref)
    : attConvPref{attConvPref} {}

AttestationConveyancePreference::AttestationConveyancePreference(
    std::string &attConvPref) {
  if (attConvPref.compare("none") == 0) {
    this->attConvPref = none;
  } else if (attConvPref.compare("indirect") == 0) {
    this->attConvPref = indirect;
  } else if (attConvPref.compare("direct") == 0) {
    this->attConvPref = direct;
  } else if (attConvPref.compare("enterprise") == 0) {
    this->attConvPref = enterprise;
  } else {
    LOG(ERROR) << "AttestationConveyancePreference " << attConvPref
               << " is invalid";
    throw std::invalid_argument{"AttestationConveyancePreference is invalid"};
  }
}

std::shared_ptr<std::string>
AttestationConveyancePreference::getString() const {
  auto strType = std::make_shared<std::string>();

  switch (this->attConvPref) {
  case none:
    *strType = "none";
    break;
  case indirect:
    *strType = "indirect";
    break;
  case direct:
    *strType = "direct";
    break;
  case enterprise:
    *strType = "enterprise";
    break;
  }
  return strType;
}

AttestationConveyancePreference::~AttestationConveyancePreference() {}