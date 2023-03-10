cmake_minimum_required(VERSION 3.5)
project(webauthn VERSION 0.1)

add_library(webauthn STATIC 
    src/webauthn.cpp include/webauthn.h
    include/IJsonSerialize.h
    include/PublicKeyCredentialEntity.h src/PublicKeyCredentialEntity.cpp 
    include/PublicKeyCredentialUserEntity.h src/PublicKeyCredentialUserEntity.cpp
    include/PublicKeyCredentialCreationOptions.h src/PublicKeyCredentialCreationOptions.cpp
    )
target_include_directories(webauthn PUBLIC include)
