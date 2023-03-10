cmake_minimum_required(VERSION 3.5)
project(webauthn VERSION 0.1)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_subdirectory(gtest)

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
    include/PublicKeyCredential.h src/PublicKeyCredential.cpp
    include/AuthenticatorResponse.h src/AuthenticatorResponse.cpp
    include/AuthenticatorAttestationResponse.h src/AuthenticatorAttestationResponse.cpp
    include/Base64Url.h src/Base64Url.cpp
    )
target_include_directories(webauthn PUBLIC include lib/jsoncons/include)
