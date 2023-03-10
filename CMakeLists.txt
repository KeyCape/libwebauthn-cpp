cmake_minimum_required(VERSION 3.11)
project(webauthn VERSION 0.1)
set(CMAKE_CXX_STANDARD 20)
find_package(Drogon CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(glog)

# Gtest
include(FetchContent)
include(ExternalProject)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/release-1.12.1.zip
)

# mbedtls
set(ENABLE_TESTING OFF CACHE INTERNAL "")
set(ENABLE_PROGRAMS OFF CACHE INTERNAL "")
FetchContent_Declare(
  mbedtls
  GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
  GIT_TAG        v3.3.0
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest mbedtls)

# tinycbor
ExternalProject_Add(
  tinycbor
  GIT_REPOSITORY https://github.com/intel/tinycbor.git
  GIT_TAG v0.6.0
  BUILD_IN_SOURCE 1
  CONFIGURE_COMMAND ""
  BUILD_COMMAND make lib/libtinycbor.a
  INSTALL_COMMAND ""
)

# tinycbor source dir
ExternalProject_Get_property(tinycbor SOURCE_DIR)
message("Source dir of tinycbor = ${SOURCE_DIR}")

enable_testing()

add_library(webauthn STATIC 
    include/webauthn.h
    include/IJsonSerialize.h
    include/IJsonDeserialize.h
    include/IAttestationStatement.h
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
    include/AttestationConveyancePreference.h src src/AttestationConveyancePreference.cpp
    include/AttestationStatementFormatIdentifier.h src/AttestationStatementFormatIdentifier.cpp
    include/AttestationStatementFidoU2f.h src/AttestationStatementFidoU2f.cpp
)
# Has to be set to add compatibility, so that this project can be added via add_subdirectory()
add_dependencies(webauthn tinycbor)

target_include_directories(webauthn PUBLIC include lib/jsoncons/include ${SOURCE_DIR}/src)

add_executable(
    webauthn_test
    gtest/test_PublicKeyCredential.cpp
    gtest/test_AuthenticatorResponse.cpp
    gtest/test_AuthenticatorAttestationResponse.cpp
    gtest/test_AttestationStatementFidoU2f.cpp
    gtest/test_PublicKeyCredentialCreationOptions.cpp
)

target_link_libraries(
  webauthn
  PUBLIC jsoncpp
  ${SOURCE_DIR}/lib/libtinycbor.a
  GTest::gtest_main
  glog::glog
  Drogon::Drogon
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
