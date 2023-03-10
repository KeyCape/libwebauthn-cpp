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
    auto ret = std::make_unique<Json::Value>(Json::arrayValue);

    ret->append(*this->rp->getJson());
    ret->append(*this->user->getJson());
    ret->append(*this->challenge->getJson());
    // TODO Add pubKeyCredParams
    return ret;
}
PublicKeyCredentialCreationOptions::~PublicKeyCredentialCreationOptions() {}