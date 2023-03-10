#include "webauthn.h"
#include "PublicKeyCredentialParameters.h"
#include "PublicKeyCredentialRpEntity.h"
#include "PublicKeyCredentialUserEntity.h"
#include <utility>

Webauthn::Webauthn() {}

Webauthn::Webauthn(std::string &&name, std::string &&id)
    : rp_name{name}, rp_id{id} {}

std::shared_ptr<PublicKeyCredentialCreationOptions>
Webauthn::beginRegistration(std::string &username) {
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
Webauthn::~Webauthn() {}
