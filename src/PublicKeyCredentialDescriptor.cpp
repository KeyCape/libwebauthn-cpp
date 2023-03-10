#include "PublicKeyCredentialDescriptor.h"

PublicKeyCredentialDescriptor::PublicKeyCredentialDescriptor(std::string &&type,
                                                             std::string &&id)
    : type{type}, id{id} {}

PublicKeyCredentialDescriptor::~PublicKeyCredentialDescriptor() {}