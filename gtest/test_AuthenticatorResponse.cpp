#include <AuthenticatorResponse.h>
#include <gtest/gtest.h>
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <memory>
#include <string>
#include <glog/logging.h>

class AuthenticatorResponseTest : public ::testing::Test {
protected:
  std::shared_ptr<Json::Value> json;
  std::shared_ptr<AuthenticatorResponse> ar;

  void SetUp() override {
//    google::InitGoogleLogging("log_dir=log");
    std::string clientDataJSONTmp =
        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUUQzajJ2N0FpWHpjRW"
        "1SZmRORVBvUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ";

    this->json = std::make_shared<Json::Value>();
    (*this->json)["response"]["clientDataJSON"] = clientDataJSONTmp;

    this->ar = std::make_shared<AuthenticatorResponse>();
    this->ar->fromJson(this->json);
  }

  void TearDown() override {}
};

TEST_F(AuthenticatorResponseTest, CheckTypeInterpretation) {
  ASSERT_TRUE(this->ar->getType());
  ASSERT_EQ(*this->ar->getType(), std::string{"webauthn.create"}) << "Wrong type";
}

TEST_F(AuthenticatorResponseTest, CheckChallengeInterpretation) {
  auto challengePtr = this->ar->getChallenge()->getChallenge();
  auto challenge = std::string{"QD3j2v7AiXzcEmRfdNEPoQ"};
  ASSERT_TRUE(std::equal(challengePtr->begin(), challengePtr->end(), challenge.begin(), challenge.end())) << "Wrong challenge";
}

TEST_F(AuthenticatorResponseTest, CheckOriginInterpretation) {
  ASSERT_EQ(*this->ar->getOrigin(), std::string{"http://localhost"}) << "Wrong origin";
}