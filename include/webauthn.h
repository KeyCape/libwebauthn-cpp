#pragma once
#include "PublicKeyCredentialCreationOptions.h"
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
  /**
   * @brief This method returns the PublicKeyCredentialCreationOptions object,
   * which is requested by the client, to register a new Credential
   *
   * @param username The username of the user. This parameter is usally assigned
   * by the client.
   * @return std::shared_ptr<PublicKeyCredentialCreationOptions> Is returned to
   * the client.
   */
  std::shared_ptr<PublicKeyCredentialCreationOptions>
  beginRegistration(std::string &username);
  ~Webauthn();
};