#include "AttestationStatementFormatIdentifier.h"
#include "AuthenticatorAttestationResponse.h"
#include "PublicKeyCredentialCreationOptions.h"
#include <gtest/gtest.h>
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <memory>
#include <string>

class PublicKeyCredentialCreationOptionsTest : public ::testing::Test {
protected:
  std::shared_ptr<Json::Value> json;
  std::shared_ptr<PublicKeyCredentialCreationOptions> pkco;

  std::string attestation = "indirect",
              challenge = R"(6x/z5RcjDaBlUzYPBgq6QQ==)";
  std::string rpId = "localhost", rpName = "localhost";
  std::string userName = "Testuser",
              userId = "VGVzdHVzZXI=", userDisplayName = "Testuser";

  void SetUp() override {

    this->json = std::make_shared<Json::Value>();
    (*this->json)["attestation"] = attestation;
    (*this->json)["challenge"] = challenge;
    (*this->json)["rp"]["id"] = rpId;
    (*this->json)["rp"]["name"] = rpName;
    (*this->json)["user"]["displayName"] = userDisplayName;
    (*this->json)["user"]["id"] = userId;
    (*this->json)["user"]["name"] = userName;

    pkco = PublicKeyCredentialCreationOptions::fromJson(this->json);
  }

  void TearDown() override {}
};

TEST_F(PublicKeyCredentialCreationOptionsTest, CheckChallenge) {
  auto tmpChallenge = std::make_shared<std::vector<unsigned char>>(
      this->challenge.begin(), this->challenge.end());
  ASSERT_EQ(*tmpChallenge, *this->pkco->getChallenge()->getChallenge())
      << "The Challenges doesn't match";
}

TEST_F(PublicKeyCredentialCreationOptionsTest,
       CheckPublicKeyCredentialUserEntity) {
  auto ueJson = this->pkco->getPublicKeyCredentialUserEntity()->getJson();
  ASSERT_TRUE(ueJson->isMember("id"))
      << "Missing PublicKeyCredentialUserEntity field id";
  ASSERT_EQ((*ueJson)["id"].asString(), userId)
      << "The id should have been " << userId << " but was "
      << (*ueJson)["id"].asString();
  ASSERT_TRUE(ueJson->isMember("displayName"))
      << "Missing PublicKeyCredentialUserEntity field displayName";
  ASSERT_EQ((*ueJson)["displayName"].asString(), userDisplayName)
      << "The displayName should have been " << userDisplayName << " but was "
      << (*ueJson)["displayName"].asString();
  ASSERT_TRUE(ueJson->isMember("name"))
      << "Missing PublicKeyCredentialUserEntity field name";
  ASSERT_EQ((*ueJson)["name"].asString(), userName)
      << "The name should have been " << userName << " but was "
      << (*ueJson)["name"].asString();
}