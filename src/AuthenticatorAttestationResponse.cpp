#include "AuthenticatorAttestationResponse.h"

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse() {}

AuthenticatorAttestationResponse::AuthenticatorAttestationResponse(
    std::vector<uint8_t> &&attObj, std::shared_ptr<std::string> clientDataJSON)
    : attestationObject{attObj}, AuthenticatorResponse{clientDataJSON} {}

void AuthenticatorAttestationResponse::fromJson(
    const std::shared_ptr<Json::Value> json) {
  LOG(INFO) << "Parsing AuthenticatorAttestationResponse";
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }

  // Check if the following json structure exists: {"response":
  // {"attestationObject: "", ..}}
  if (json->isMember("response")) {
    if (!(*json)["response"].isMember("attestationObject")) {
      throw std::invalid_argument{"Missing key attestationObject"};
    }
  } else {
    throw std::invalid_argument{"Missing key: response"};
  }
  std::string tmp = (*json)["response"]["attestationObject"].asString();

  this->attestationObject.reserve(tmp.size());
  std::transform(tmp.begin(), tmp.end(), this->attestationObject.begin(),
                 [](const auto &t) { return t; });

  LOG(INFO) << "Decode attestationObject";
  DLOG(INFO) << "atteStationObject: " << tmp;
  tmp = drogon::utils::base64Decode(tmp);

  // Parse cbor
  CborParser parser;
  CborValue map;

  LOG(INFO) << "Parse the attestationObject with cbor";
  CborError err =
      cbor_parser_init((uint8_t *)tmp.data(), tmp.size(), 0, &parser, &map);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Couldn't parse the attestationObject with cbor. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  LOG(INFO) << "Check if the attestationObject is a map";
  if (!cbor_value_is_map(&map)) {
    throw std::invalid_argument{
        "The attestationObject has to be a cbor map, but is from type: " +
        cbor_value_get_type(&map)};
  }

  CborValue cval;
  size_t clen;

  LOG(INFO) << "Search after the textfield fmt inside of the cbor";
  // Field fmt
  err = cbor_value_map_find_value(&map, "fmt", &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the find proccess of the fmt field. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  LOG(INFO) << "Check if the textfield fmt exists";
  // Check if the field fmt is missing
  if (cbor_value_get_type(&cval) == CborInvalidType) {
    throw std::invalid_argument{"attestationObject is missing the field fmt"};
  }

  LOG(INFO) << "Check if the the field fmt is of type text";
  if (!cbor_value_is_text_string(&cval)) {
    throw std::invalid_argument{
        "The cbor field fmt has to be a text string but is of type: " +
        cbor_value_get_type(&cval)};
  }

  err = cbor_value_calculate_string_length(&cval, &clen);
  if (err != CborNoError) {
    throw std::invalid_argument{"Error occured during the string "
                                "length determination of field fmt"};
  }

  LOG(INFO) << "Check if the length of the field fmt is > 0. Length: " << clen;
  if (clen > 0) {
    // Add one byte to the buffer, so that tinycbor can append the null
    // terminator
    char *buf = (char *)std::malloc(clen + 1);
    err = cbor_value_copy_text_string(&cval, buf, &clen, NULL);
    if (err != CborNoError) {
      free(buf);
      throw std::invalid_argument{
          std::string{"Error occured during the copy operation of the fmt "
                      "field. CborError: "}
              .append(cbor_error_string(err))};
    }
    DLOG(INFO) << "fmt has the value: " << buf;
    if (this->fmt) {
      this->fmt.reset(
          new AttestationStatementFormatIdentifier{std::string{buf, clen}});
    } else {
      this->fmt = std::make_shared<AttestationStatementFormatIdentifier>(
          std::string{buf, clen});
    }
    free(buf);
  }

  LOG(INFO) << "Search for the bytefield authData inside of the cbor";
  // Field authData
  err = cbor_value_map_find_value(&map, "authData", &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the find proccess of the authData "
                    "field. CborError: "}
            .append(cbor_error_string(err))};
  }

  LOG(INFO) << "Check if the bytefield authData exists";
  if (cbor_value_get_type(&cval) == CborInvalidType) {
    throw std::invalid_argument{"Missing cbor field authData"};
  }

  LOG(INFO) << "Check if the field authData is of type bytestring";
  if (!cbor_value_is_byte_string(&cval)) {
    throw std::invalid_argument{
        "The cbor field fmt has to be a byte string but is of type: " +
        cbor_value_get_type(&cval)};
  }

  err = cbor_value_calculate_string_length(&cval, &clen);
  if (err != CborNoError) {
    throw std::invalid_argument{"Error occured while during the byte string "
                                "length determination of field fmt"};
  }

  LOG(INFO) << "Check if the length of the field authData > 0. Length: "
            << clen;
  if (clen > 0) {
    std::vector<unsigned char> authData(clen);
    /*if (this->authData) {
      this->authData->clear();
      this->authData->resize(clen);
    } else {
      this->authData = std::make_shared<std::vector<uint8_t>>(clen);
    }*/
    err = cbor_value_copy_byte_string(&cval, authData.data(), &clen, NULL);
    if (err != CborNoError) {
      throw std::invalid_argument{
          "Error occured while copying the data field authData"};
    }

    DLOG(INFO) << "authData length: " << authData.size();
    if (!this->authData) {
      this->authData = std::make_shared<AuthenticatorData>(authData);
    } else {
      this->authData.reset(new AuthenticatorData{authData});
    }
  }

  // Extract the attestationStatement
  auto cborAttStmt = std::make_shared<CborValue>();
  err = cbor_value_map_find_value(&map, "attStmt", cborAttStmt.get());
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the find proccess of the attStmt "
                    "field. CborError: "}
            .append(cbor_error_string(err))};
  }

  switch (this->fmt->attStmtFmt) {
  case AttestationStatementFormatIdentifier::type::fido_u2f:
    LOG(INFO) << "The attestation statement is of type fido_u2f";
    this->attStmt = std::make_shared<AttestationStatementFidoU2f>();
    this->attStmt->extractFromCBOR(cborAttStmt);
    break;
  default:
    LOG(INFO) << "The attestation statement format is not implemented yet";
    break;
  }

  // Call the overridden method to parse the clientDataJson
  AuthenticatorResponse::fromJson(json);
}
const std::shared_ptr<AuthenticatorData>
AuthenticatorAttestationResponse::getAuthData() const {
  return this->authData;
}

const std::shared_ptr<AttestationStatementFormatIdentifier>
AuthenticatorAttestationResponse::getFmt() const {
  return this->fmt;
}

void AuthenticatorAttestationResponse::verifyAttStmt() const {
  this->attStmt->verify(this->authData, this->clientDataJSON);
}

AuthenticatorAttestationResponse::~AuthenticatorAttestationResponse() {}