#pragma once
#include <string>

class Webauthn {
private:
  std::string rp_name;
  std::string rp_id;

public:
  Webauthn();
  /// @brief Create an instance of a relying party
  /// @param name This is the name of the relying party
  /// @param id This is the id of the relying party, which is transfered to the
  /// WebAgent
  Webauthn(std::string &&name, std::string &&id);
  ~Webauthn();
};