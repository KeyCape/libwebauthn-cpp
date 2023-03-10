#include "PublicKeyCredential.h"
#include "AuthenticatorAttestationResponse.h"
#include <gtest/gtest.h>
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <memory>
#include <string>

class PublicKeyCredentialTest : public ::testing::Test {
protected:
  std::string id;
  std::string type;
  std::shared_ptr<std::vector<std::uint8_t>> rawId;

  std::shared_ptr<std::vector<std::uint8_t>> attObj;
  std::shared_ptr<std::vector<std::uint8_t>> clientDataJSON;

  std::shared_ptr<Json::Value> json;

  std::shared_ptr<PublicKeyCredential<AuthenticatorAttestationResponse>> pkeyCred;

  void SetUp() override {
    this->id = "TM28y3B8gDGzpo4NyGkzQtJ1Cv0";
    this->type = "public-key";

    std::string rawIdTmp{"TM28y3B8gDGzpo4NyGkzQtJ1Cv0"};
    this->rawId = std::make_shared<std::vector<std::uint8_t>>(rawIdTmp.begin(),
                                                              rawIdTmp.end());

    std::string attObjTmp =
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViYSZYN5YgOjGh0NBcPZHZgW4_"
        "krrmihjLHmVzzuoMdl2NdAAAAAAAAAAAAAAAAAAAAAAAAAAAAFEzNvMtwfIAxs6aODchpM"
        "0LSdQr9pQECAyYgASFYIDbLEAzNaa8l_"
        "cr8BMcjckfjsdxY5c6j2dvwTqQ8iANeIlgguWzONjKbOWQuvH-"
        "rBdssm5YGCfwp8C1E3TYt6luf3Qk";

    this->attObj = std::make_shared<std::vector<std::uint8_t>>(
        attObjTmp.begin(), attObjTmp.end());

    std::string clientDataJSONTmp =
        "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiUUQzajJ2N0FpWHpjRW"
        "1SZmRORVBvUSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3QifQ";
    this->clientDataJSON = std::make_shared<std::vector<std::uint8_t>>(
        clientDataJSONTmp.begin(), clientDataJSONTmp.end());

    this->json = std::make_shared<Json::Value>();

    (*this->json)["id"] = this->id;
    (*this->json)["rawId"] = rawIdTmp;
    (*this->json)["type"] = this->type;
    (*this->json)["response"]["attestationObject"] = attObjTmp;
    (*this->json)["response"]["clientDataJSON"] = clientDataJSONTmp;

    this->pkeyCred = std::make_shared<PublicKeyCredential<AuthenticatorAttestationResponse>>();
    this->pkeyCred->fromJson(this->json);
  }

  void TearDown() override {}
};

TEST_F(PublicKeyCredentialTest, CheckDeserializedId) {
  ASSERT_EQ(pkeyCred->getId(), this->id)
      << "The deserialization of the id failed";
}

TEST_F(PublicKeyCredentialTest, CheckDeserializedRawId) {
  ASSERT_EQ(pkeyCred->getRawId(), *this->rawId)
      << "The deserialization of the rawId failed";
}

TEST_F(PublicKeyCredentialTest, CheckDeserializedType) {
  ASSERT_EQ(pkeyCred->getType(), this->type)
      << "The deserialization of the type failed";
}
