#include "webauthn.h"

Webauthn::Webauthn() {}

Webauthn::Webauthn(std::string &&name, std::string &&id)
    : rp_name{name}, rp_id{id} {}

Webauthn::~Webauthn() {}
