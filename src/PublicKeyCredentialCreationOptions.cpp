#include "PublicKeyCredentialCreationOptions.h"

PublicKeyCredentialCreationOptions::PublicKeyCredentialCreationOptions(
    std::shared_ptr<PublicKeyCredentialRpEntity> &rp,
    std::shared_ptr<PublicKeyCredentialUserEntity> &user,
    std::shared_ptr<Challenge> &challenge,
    std::shared_ptr<std::forward_list<PublicKeyCredentialParameters>>
        &pubKeyCredParams)
    : rp{rp}, user{user}, challenge{challenge} {}

PublicKeyCredentialCreationOptions::~PublicKeyCredentialCreationOptions() {}