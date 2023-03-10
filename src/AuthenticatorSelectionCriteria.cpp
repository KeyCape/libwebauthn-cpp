#include "AuthenticatorSelectionCriteria.h"

AuthenticatorSelectionCriteria::AuthenticatorSelectionCriteria(
    std::string &&authenticatorAttachment, std::string &&residentKey)
    : authenticatorAttachment{authenticatorAttachment}, residentKey{
                                                            residentKey} {}

AuthenticatorSelectionCriteria::~AuthenticatorSelectionCriteria() {}