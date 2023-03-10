#include "PublicKeyCredentialCreationOptions.h"
#include <jsoncpp/json/value.h>

PublicKeyCredentialCreationOptions::PublicKeyCredentialCreationOptions(
    std::shared_ptr<PublicKeyCredentialRpEntity> &rp,
    std::shared_ptr<PublicKeyCredentialUserEntity> &user,
    std::shared_ptr<Challenge> &challenge,
    std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
        &pubKeyCredParams)

    : rp{rp}, user{user}, challenge{challenge} {}
std::unique_ptr<Json::Value> PublicKeyCredentialCreationOptions::getJson() {
  auto ret = std::make_unique<Json::Value>(Json::objectValue);

  (*ret)["rp"] = *this->rp->getJson();
  (*ret)["user"] = *this->user->getJson();
  (*ret)["challenge"] = *this->challenge->getJson();
  // TODO Add pubKeyCredParams
  return ret;
}
PublicKeyCredentialCreationOptions::~PublicKeyCredentialCreationOptions() {}