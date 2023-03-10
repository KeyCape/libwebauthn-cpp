#pragma once
#include "PublicKeyCredentialCreationOptions.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <string>
#include <utility>
#include <type_traits>

template <typename T> class Webauthn {
private:
  std::string rp_name;
  std::string rp_id;

public:
  Webauthn() = delete;
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
  std::shared_ptr<T> finishRegistration(std::shared_ptr<Json::Value> v);
  ~Webauthn();
};

template <typename T>
Webauthn<T>::Webauthn(std::string &&name, std::string &&id)
    : rp_name{name}, rp_id{id} {
      static_assert(std::is_base_of_v<CredentialRecord, T>, "The return type of finishRegistration(..) must be a child of the class CredentialRecord");
    }

template <typename T>
std::shared_ptr<PublicKeyCredentialCreationOptions>
Webauthn<T>::beginRegistration(std::string &username) {
  if (username.empty()) {
    throw std::runtime_error{"The username must NOT be emtpy"};
  }

  auto rp = std::make_shared<PublicKeyCredentialRpEntity>(
      PublicKeyCredentialRpEntity(std::forward<std::string>(this->rp_name),
                                  std::forward<std::string>(this->rp_id)));

  auto user = std::make_shared<PublicKeyCredentialUserEntity>(
      PublicKeyCredentialUserEntity{std::forward<std::string>(username),
                                    std::forward<std::string>(username),
                                    std::forward<std::string>(username)});

  auto challenge = std::make_shared<Challenge>(Challenge{});

  auto params =
      std::make_shared<std::forward_list<PublicKeyCredentialParameters>>(
          std::forward_list<PublicKeyCredentialParameters>(
              {PublicKeyCredentialParameters{COSEAlgorithmIdentifier::ES256}}));

  auto ret = std::make_shared<PublicKeyCredentialCreationOptions>(
      rp, user, challenge, params);

  return ret;
}

template <typename T>
std::shared_ptr<T>
Webauthn<T>::finishRegistration(std::shared_ptr<Json::Value> v) {
  auto ret = std::make_shared<T>();

  return ret;
}

template <typename T> Webauthn<T>::~Webauthn() {}
