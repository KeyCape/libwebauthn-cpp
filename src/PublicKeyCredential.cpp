#include "PublicKeyCredential.h"

PublicKeyCredential::PublicKeyCredential(
    std::string &&id, std::string &&type, std::vector<std::uint8_t> &&rawId,
    std::shared_ptr<AuthenticatorResponse> response)
    : id{id}, type{type}, rawId{rawId}, response{response} {}

PublicKeyCredential::~PublicKeyCredential() {}