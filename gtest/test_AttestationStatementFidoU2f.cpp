#include "AttestationStatementFormatIdentifier.h"
#include "AuthenticatorAttestationResponse.h"
#include "PublicKeyCredential.h"
#include <gtest/gtest.h>
#include <jsoncpp/json/value.h>
#include <jsoncpp/json/writer.h>
#include <memory>
#include <string>

class AttestationStatementFidoU2fTest : public ::testing::Test {
protected:
  std::shared_ptr<Json::Value> json;
  AuthenticatorAttestationResponse attr;

  void SetUp() override {

    this->json = std::make_shared<Json::Value>();
    (*this->json)["response"]["attestationObject"] =
        R"(o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgNfK_Vw9EZUwZcQ5goUNG625LP9rnGxpDQUDE-KgC-JACIQDAv6zlu3vIO4acExc1Vc1NL8cqyNguKbgC1cYkhyySnmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEHo-HNDANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNTEyNzIyNzQwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqHn4IzjtFJS6wHBLzH_GY9GycXFZdiQxAcdgURXXwVKeKBwcZzItOEtc1V3T6YGNX9hcIq8ybgxk_CCv4z8jZqNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjcwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQL8BXn4ETR-qxFrtajbkgKjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQCGk_9i3w1XedR0jX_I0QInMYqOWA5qOlfBCOlOA8OFaLNmiU_OViS-Sj79fzQRiz2ZN0P3kqGYkWDI_JrgsE49-e4V4-iMBPyCqNy_WBjhCNzCloV3rnn_ZiuUc0497EWXMF1z5uVe4r65zZZ4ygk15TPrY4-OJvq7gXzaRB--mDGDKuX24q2ZL56720xiI4uPjXq0gdbTJjvNv55KV1UDcJiK1YE0QPoDLK22cjyt2PjXuoCfdbQ8_6Clua3RQjLvnZ4UgSY4IzxMpKhzufismOMroZFnYG4VkJ_N20ot_72uRiAkn5pmRqyB5IMtERn-v6pzGogtolp3gn1G0ZAXaGF1dGhEYXRhWMRlxjLRXu5WsROIot2sv7Qf46-_HV60l9yyOa4ZUIWTb0EAAAAAAAAAAAAAAAAAAAAAAAAAAABAuYaJev8FqVNlii1-bS7eZNUIUZk0mahRt9dwf0BhWeD-fBi8Ki0qjOsJ_FNOcmW7pZKvdNcJx10YLmwlIztOIKUBAgMmIAEhWCAFKR1T5jYUVPev2j2QGCp4XhUtR3vCXU5od-lYFt-S2SJYICtI400qsTrTBikZ4XCOBDLtizffnSbvxqT7wAWyPHDJ)";
    (*this->json)["response"]["clientDataJSON"] = R"(eyJjaGFsbGVuZ2UiOiI2eF96NVJjakRhQmxVellQQmdxNlFRIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5vZ2t3LmRlIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9)";
    attr.fromJson(json);
  }

  void TearDown() override {}
};

TEST_F(AttestationStatementFidoU2fTest,
       CheckAttestationStatement) {
        this->attr.verifyAttStmt();
}
