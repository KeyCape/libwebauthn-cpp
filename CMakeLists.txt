cmake_minimum_required(VERSION 3.5)
project(webauthn VERSION 0.1)

add_library(webauthn STATIC 
    include/webauthn.h
    include/IJsonSerialize.h
    include/PublicKeyCredentialEntity.h src/PublicKeyCredentialEntity.cpp 
    include/PublicKeyCredentialUserEntity.h src/PublicKeyCredentialUserEntity.cpp
    include/PublicKeyCredentialCreationOptions.h src/PublicKeyCredentialCreationOptions.cpp
    include/PublicKeyCredentialParameters.h src/PublicKeyCredentialParameters.cpp
    include/Challenge.h src/Challenge.cpp
    include/PublicKeyCredentialDescriptor.h src/PublicKeyCredentialDescriptor.cpp
    include/AuthenticatorSelectionCriteria.h src/AuthenticatorSelectionCriteria.cpp
    include/PublicKeyCredentialRpEntity.h src/PublicKeyCredentialRpEntity.cpp
    include/CredentialRecord.h src/CredentialRecord.cpp
    )
target_include_directories(webauthn PUBLIC include)
