#include "AttestedCredentialData.h"
#include <bitset>

AttestedCredentialData::AttestedCredentialData(
    const std::vector<unsigned char> &attCredData) {
  if (attCredData.size() < 18) {
    LOG(WARNING) << "No attested credential data given. The length has to be "
                    "at least 18 bytes, but was only: "
                 << attCredData.size() << " bytes";
    return;
  }
  DLOG(INFO) << "attestedCredData len: " << attCredData.size();

  LOG(INFO) << "Extract the AAGUID from attCredData";
  // The AAGUID is 16 bytes long
  this->aaguid = std::make_shared<std::string>(attCredData.begin(),
                                               attCredData.begin() + 16);
  DLOG(INFO) << "The AAGUID is: " << *this->aaguid;

  LOG(INFO) << "Extract the credential id length";
  // The credential id length is 2 bytes  long
  memcpy(&this->credentialIdLength, attCredData.data() + 16, 1);
  this->credentialIdLength = this->credentialIdLength << 8;
  memcpy(&this->credentialIdLength, attCredData.data() + 17, 1);

  DLOG(INFO) << "The credential id length is: " << this->credentialIdLength;
  LOG(INFO) << "Check if the credential id length is <= 1023";
  if (this->credentialIdLength > 1023) {
    LOG(ERROR) << "The credentialIdLength has to be <= 1023 but is: "
               << this->credentialIdLength;
    throw std::invalid_argument{
        "The credentialIdLength of attested credential data has to be >= 1023"};
  }

  LOG(INFO) << "Extract the credential id from attCrdData";
  this->credentialId = std::make_shared<std::string>(
      attCredData.begin() + 18,
      attCredData.begin() + 18 + this->credentialIdLength + 1);
  DLOG(INFO) << "The credential id is: " << *this->credentialId;

  this->extractCredentialPublicKey(attCredData);
}

/**
 * @brief This method extracts the credentials public key, which is later used
 * to validate the authenticator signatures. The key is in COSE format. See the
 * definition here: https://www.rfc-editor.org/rfc/rfc9052#section-7
 *
 * @param attCredData See constructor
 */
void AttestedCredentialData::extractCredentialPublicKey(
    const std::vector<unsigned char> &attCredData) {
  LOG(INFO) << "Extract the credential public key";
  DLOG(INFO) << "attCredData len: " << attCredData.size();

  // Calculate the start position of the credentials public key
  // rpIdHash + flags + signCount + aaguid + credentialIdLength + credentialId +
  // 1 = start address
  size_t pkCoseStart = 16 + 2 + this->credentialIdLength;
  DLOG(INFO) << "The start index of the credentials public key is: "
             << pkCoseStart;
  std::vector<unsigned char> dd{attCredData.begin() + pkCoseStart,
                                attCredData.end()};

  std::stringstream ss;
  for (auto &i : dd) {
    ss << (unsigned int)i << " ";
  }
  DLOG(INFO) << "attestedCredentialPublicKey len: " << dd.size();
  DLOG(INFO) << "attestedCredentialPublicKey: " << ss.str();

  // Parse cbor
  CborParser parser;
  CborValue map;

  LOG(INFO) << "Parse credentials public key";
  CborError err = cbor_parser_init(dd.data(), dd.size(), 0, &parser, &map);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Couldn't parse the attestationObject with cbor. CborError: "}
                                    .append(cbor_error_string(err))};
  }
  size_t len = 0;
  cbor_value_get_map_length(&map, &len);
  LOG(INFO) << "Cbor map len: " << len;
  LOG(INFO) << "Check if the attestationObject is a map";
  if (!cbor_value_is_map(&map)) {
    throw std::invalid_argument{
        "The attestationObject has to be a cbor map, but is from type: " +
        cbor_value_get_type(&map)};
  }
  LOG(INFO) << "Is map array?: " << cbor_value_is_array(&map);

  CborValue cval;
  size_t clen;

  err = cbor_value_enter_container(&map, &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the enter container proccess. CborError: "}
                                    .append(cbor_error_string(err))};
  }
  LOG(INFO) << "It type: " << cbor_value_get_type(&cval);
  int res = 0;
  cbor_value_get_int(&cval, &res);
  LOG(INFO) << "Value: " << res;

  err = cbor_value_advance(&cval);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the advance it proccess. CborError: "}
            .append(cbor_error_string(err))};
  }

  LOG(INFO) << "It type: " << cbor_value_get_type(&cval);
  LOG(INFO) << "Is tag: " << cbor_value_is_tag(&cval);
  cbor_value_get_int(&cval, &res);
  LOG(INFO) << "Value: " << res;

  err = cbor_value_advance(&cval);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the advance it proccess. CborError: "}
            .append(cbor_error_string(err))};
  }

  LOG(INFO) << "It type: " << cbor_value_get_type(&cval);
  LOG(INFO) << "Is tag: " << cbor_value_is_tag(&cval);
  cbor_value_get_int(&cval, &res);
  LOG(INFO) << "Value: " << res;

  err = cbor_value_advance(&cval);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the advance it proccess. CborError: "}
            .append(cbor_error_string(err))};
  }

  LOG(INFO) << "It type: " << cbor_value_get_type(&cval);
  LOG(INFO) << "Is tag: " << cbor_value_is_tag(&cval);
  cbor_value_get_int(&cval, &res);
  LOG(INFO) << "Value: " << res;

  LOG(INFO) << "Search after the key type";
  // Field 1
  err = cbor_value_map_find_value(&map, "1", &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the find proccess of the 1 field. CborError: "}
                                    .append(cbor_error_string(err))};
  }
  LOG(INFO) << "Check if the field 1 exists";
  // Check if the field fmt is missing
  if (cbor_value_get_type(&cval) == CborInvalidType) {
    throw std::invalid_argument{"attestationObject is missing the field 1"};
  }
}

AttestedCredentialData::~AttestedCredentialData() {}