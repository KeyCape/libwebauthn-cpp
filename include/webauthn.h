#pragma once
#include "PublicKeyCredentialCreationOptions.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include "Base64Url.h"
#include "jsoncons/json.hpp"
#include "jsoncons_ext/cbor/decode_cbor.hpp"
#include "jsoncons_ext/jsonpath/jsonpath.hpp"
#include <string>
#include <type_traits>
#include <utility>

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
  std::shared_ptr<T> finishRegistration(std::shared_ptr<PublicKeyCredentialCreationOptions> options, std::shared_ptr<Json::Value> request);
  ~Webauthn();
};

template <typename T>
Webauthn<T>::Webauthn(std::string &&name, std::string &&id)
    : rp_name{name}, rp_id{id} {
  static_assert(std::is_base_of_v<CredentialRecord, T>,
                "The return type of finishRegistration(..) must be a child of "
                "the class CredentialRecord");
}
/**
 * @brief This method is used to start the registration ceremony of a
 * credential.
 *
 * @tparam T Of type CredentialRecord
 * @param username  The username to register. This parameter has to be
 * unique(Could be a unique name or more common an email address).
 * @return std::shared_ptr<PublicKeyCredentialCreationOptions> Prefilled
 * datatype, which has to be send to the webagent as response.
 */
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

/**
 * @brief This method has to be called after beginRegister. Else the method is
 * going to fail.
 *
 * @tparam T The type is of base class CredentialRecord
 * @param v A pointer to JSON of type PublicKeyCredential. See:
 * https://w3c.github.io/webauthn/#publickeycredential
 * @return std::shared_ptr<T> A pointer to with filled attributes
 */
template <typename T>
std::shared_ptr<T>
Webauthn<T>::finishRegistration(std::shared_ptr<PublicKeyCredentialCreationOptions> options, std::shared_ptr<Json::Value> request) {
  auto ret = std::make_shared<T>();

/*std::shared_ptr<std::string> data = std::make_shared<std::string>("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFNphln4gWvo48ah9pArJo6t7wP36pQECAyYgASFYIPcg7P9N6wJZ8Z0wNNlat0oFk_VfdAbnXIirqZ6CnKAGIlgglwtVKdI7VEO18BQWmm2PtCjy1lNm8TGxAmlaZ6z4j-g");
  Base64Url::decode(data);
  jsoncons::json j = jsoncons::cbor::decode_cbor<jsoncons::json>(data->begin(), data->end());

  std::stringstream str;
  str << jsoncons::pretty_print(j);

  LOG_DEBUG << "CBOR: " << str.str();
*/

  return ret;
}

template <typename T> Webauthn<T>::~Webauthn() {}
