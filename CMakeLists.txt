cmake_minimum_required(VERSION 3.11)
project(webauthn VERSION 0.1)
set(CMAKE_CXX_STANDARD 20)
find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(webauthn STATIC 
    include/webauthn.h
    include/IJsonSerialize.h
    include/IJsonDeserialize.h
    include/PublicKeyCredentialEntity.h src/PublicKeyCredentialEntity.cpp 
    include/PublicKeyCredentialUserEntity.h src/PublicKeyCredentialUserEntity.cpp
    include/PublicKeyCredentialCreationOptions.h src/PublicKeyCredentialCreationOptions.cpp
    include/PublicKeyCredentialParameters.h src/PublicKeyCredentialParameters.cpp
    include/Challenge.h src/Challenge.cpp
    include/PublicKeyCredentialDescriptor.h src/PublicKeyCredentialDescriptor.cpp
    include/AuthenticatorSelectionCriteria.h src/AuthenticatorSelectionCriteria.cpp
    include/PublicKeyCredentialRpEntity.h src/PublicKeyCredentialRpEntity.cpp
    include/CredentialRecord.h src/CredentialRecord.cpp
    include/PublicKeyCredential.h
    include/AuthenticatorResponse.h src/AuthenticatorResponse.cpp
    include/AuthenticatorAttestationResponse.h src/AuthenticatorAttestationResponse.cpp
    include/Base64Url.h src/Base64Url.cpp
    include/AuthenticatorData.h src/AuthenticatorData.cpp
    include/AttestedCredentialData.h src/AttestedCredentialData.cpp
    include/PublicKeyCredentialRequestOptions.h src/PublicKeyCredentialRequestOptions.cpp
    include/AuthenticatorAssertionResponse.h src/AuthenticatorAssertionResponse.cpp
    )
target_include_directories(webauthn PUBLIC include lib/jsoncons/include lib/tinycbor/src)

# Gtest
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
)

FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG        8c89224991adff88d53cd380f42a2baa36f91454 #Mbed TLS 3.3.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest mbedtls)
enable_testing()

find_package(glog)

add_executable(
    webauthn_test
    gtest/test_PublicKeyCredential.cpp
    gtest/test_AuthenticatorResponse.cpp
)

target_link_libraries(
  webauthn
  PUBLIC jsoncpp
  GTest::gtest_main
  glog::glog
  Drogon::Drogon
  ${PROJECT_SOURCE_DIR}/lib/tinycbor/lib/libtinycbor.a
  OpenSSL::Crypto
  MbedTLS::mbedtls
  MbedTLS::mbedcrypto
  MbedTLS::mbedx509
)

target_link_libraries(
  webauthn_test
  webauthn
)
include(GoogleTest)
gtest_discover_tests(webauthn_test)
