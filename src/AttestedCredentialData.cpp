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
  // Check if the cbor is of type map
  LOG(INFO) << "Check if the attestationObject is a map";
  if (!cbor_value_is_map(&map)) {
    throw std::invalid_argument{
        "The attestationObject has to be a cbor map, but is from type: " +
        cbor_value_get_type(&map)};
  }

  // Get the length of the map
  size_t len = 0;
  cbor_value_get_map_length(&map, &len);
  LOG(INFO) << "Cbor map len: " << len;

  // Temporary vars
  CborValue cval;
  size_t clen;

  // Use an iterator to move between the fields of the map.
  // Unfortunately we can't use the key finder function to extract the fields,
  // because the COSE_Key format is used
  err = cbor_value_enter_container(&map, &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the enter container proccess. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  // 1. Iterate through the cbor map until the kty(COSEKeyType) is found.
  LOG(INFO) << "Extracting the key type";
  this->jumpToMapLabel(1, &cval);
  if (cbor_value_at_end(&cval)) {
    throw std::invalid_argument{"Missing the key type.(COSE_KEY)"};
  }

  int keyType = 0;
  switch (cbor_value_get_type(&cval)) {
  case CborIntegerType:
    if ((err = cbor_value_get_int(&cval, &keyType)) != CborNoError) {
      LOG(ERROR) << "An unexpected error occured while getting the key type. "
                    "CborError: "
                 << cbor_error_string(err);
      std::runtime_error{
          "An unexpected error occured while getting the key type"};
    }
    break;
  case CborTextStringType:
    LOG(WARNING)
        << "The key type value has to int. STRINGS ARE NOT IMPLEMENTED YET!";
    throw std::invalid_argument{
        "The key type value has to int. STRINGS ARE NOT IMPLEMENTED YET!"};
  default:
    LOG(WARNING) << "Invalid key type value type";
    throw std::invalid_argument{"Invalid key type type"};
  }

  // Checking if the COSEKeyType is valid
  switch (keyType) {
  case COSEKeyType::EC2:
    LOG(INFO) << "The COSEKeyType is EC2";
    this->storePublicKeyEC2(map);
    break;
  case COSEKeyType::RSA:
    LOG(INFO) << "The COSEKeyType is RSA";
    break;
  default:
    LOG(ERROR) << "The COSEKeyType is not supported. COSEKeyType: " << keyType;
    throw std::invalid_argument{"The COSEKeyType is not supported"};
  }
}

/**
 * @brief Jumps to a field with the specified label
 *
 * @param label Label as int
 * @param it Iterator has to be a iterator pointing to the first label
 */
void AttestedCredentialData::jumpToMapLabel(int &&label, CborValue *it) {
  CborError err;
  for (unsigned int idx = 0; !cbor_value_at_end(it); ++idx) {
    // If the index points to the label
    if (idx % 2 == 0) {
      // The label can either be an int or string
      int tmpLabel = 0;
      switch (cbor_value_get_type(it)) {
      case CborType::CborIntegerType:
        if ((err = cbor_value_get_int(it, &tmpLabel)) != CborNoError) {
          throw std::invalid_argument{std::string{
              "An error occured while reading the label from the COSE_KEY map"}
                                          .append(cbor_error_string(err))};
        }
        // Checks if the label is found
        if (tmpLabel == label) {
          // Move to the value
          if ((err = cbor_value_advance(it)) != CborNoError) {
            LOG(ERROR) << "An unexpected error occured while iterating over "
                          "the cbor map. CborError: "
                       << cbor_error_string(err);
            throw std::runtime_error{"An unexpected error occured."};
          }
          return;
        }
        break;
      case CborType::CborTextStringType:
        // TODO
        throw std::invalid_argument{
            "The label type has to be int and not a text string. THIS IS NOT "
            "IMPLEMENTED YET!"};
      default:
        throw std::invalid_argument{
            "The cbor format is not compliant. Wrong label type."};
      }
      if ((err = cbor_value_advance(it)) != CborNoError) {
        LOG(ERROR) << "An unexpected error occured while iterating over the "
                      "cbor map. CborError: "
                   << cbor_error_string(err);
        throw std::runtime_error{"An unexpected error occured."};
      }
    }
  }
}

void AttestedCredentialData::storePublicKeyEC2(CborValue &map) {
  auto pkPtr = std::make_shared<PublicKeyEC2>();
  CborValue it;
  CborError err;
  // If all 4 bits are set to true, then all parameters has been set. Else some
  // are missing
  std::bitset<4> check{0};

  if ((err = cbor_value_enter_container(&map, &it)) != CborNoError) {
    LOG(ERROR)
        << "Error occured during the enter container proccess. CborError: "
        << cbor_error_string(err);
    throw std::invalid_argument{std::string{
        "Error occured during the enter container proccess. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  // Iterate through all fields
  for (unsigned int idx = 0; !cbor_value_at_end(&it); ++idx) {
    switch (cbor_value_get_type(&it)) {
    case CborIntegerType:
      int tmpLabel = 0;
      if ((err = cbor_value_get_int(&it, &tmpLabel)) != CborNoError) {
        LOG(ERROR) << "An unexpected error occured during cbor_value_get_int() "
                      "of the label. CborError: "
                   << cbor_error_string(err);
        throw std::runtime_error{"An unexpected error occured"};
      }
      if ((err = cbor_value_advance(&it)) != CborNoError) {
        LOG(ERROR) << "An unexpected error occured during cbor_value_advance() "
                      "CborError: "
                   << cbor_error_string(err);
        throw std::runtime_error{"An unexpected error occured"};
      }
      switch (tmpLabel) {
      case 3: // Algorithm
      {
        LOG(INFO) << "Extract the algorithm";
        check.set(0);
        if (cbor_value_get_type(&it) != CborIntegerType) {
          LOG(WARNING) << "The algorithm value has to be an int";
          throw std::invalid_argument{
              "The type of the field 3(alg) has to be an int"};
        }
        int alg = 0;
        cbor_value_get_int(&it, &alg);
        pkPtr->alg = static_cast<COSEAlgorithmIdentifier>(alg);
        break;
      }
      case -1: // Curve
        LOG(INFO) << "Extract the curve";
        check.set(1);
        if (cbor_value_get_type(&it) != CborIntegerType) {
          LOG(WARNING) << "The curve value has to be an int";
          throw std::invalid_argument{
              "The type of the field -1(curve) has to be an int"};
        }
        cbor_value_get_int(&it, &pkPtr->crv);
        break;
      case -2: // X-coordinate
      {
        LOG(INFO) << "Extract the x-coordinate";
        check.set(2);
        size_t tmpLen = 0;
        if (!cbor_value_is_byte_string(&it)) {
          LOG(WARNING) << "The x-coordinate has to be a bytestring";
          throw std::invalid_argument{
              "The x-coordinate has to be a bytestring"};
        }
        if ((err = cbor_value_calculate_string_length(&it, &tmpLen)) !=
            CborNoError) {
          LOG(ERROR) << "An unexpected error occured while calculating the "
                        "length of the x-coordinate. CborError: "
                     << cbor_error_string(err);
          throw std::runtime_error{
              "An unexpected error occured while calculating the length of the "
              "x-coordinate."};
        }
        DLOG(INFO) << "The x-coordinate has a length of: " << tmpLen;
        pkPtr->x.resize(tmpLen);
        if ((err = cbor_value_copy_byte_string(&it, (uint8_t *)pkPtr->x.data(),
                                               &tmpLen, NULL)) != CborNoError) {
          LOG(ERROR) << "An unexpected error occured while copying the "
                        "x-coordinate into the vector. CborError: "
                     << cbor_error_string(err);
          throw std::runtime_error{"An unexpected error occured while copying "
                                   "the x-coordinate into the vector"};
        }
        break;
      }
      case -3: // Y-coordinate
      {
        LOG(INFO) << "Extract the y-coordinate";
        check.set(3);
        size_t tmpLen = 0;
        if (!cbor_value_is_byte_string(&it)) {
          LOG(WARNING) << "The y-coordinate has to be a bytestring";
          throw std::invalid_argument{
              "The y-coordinate has to be a bytestring"};
        }
        if ((err = cbor_value_calculate_string_length(&it, &tmpLen)) !=
            CborNoError) {
          LOG(ERROR) << "An unexpected error occured while calculating the "
                        "length of the y-coordinate. CborError: "
                     << cbor_error_string(err);
          throw std::runtime_error{
              "An unexpected error occured while calculating the length of the "
              "y-coordinate."};
        }
        DLOG(INFO) << "The y-coordinate has a length of: " << tmpLen;
        pkPtr->y.resize(tmpLen);
        if ((err = cbor_value_copy_byte_string(&it, (uint8_t *)pkPtr->y.data(),
                                               &tmpLen, NULL)) != CborNoError) {
          LOG(ERROR) << "An unexpected error occured while copying the "
                        "y-coordinate into the vector. CborError: "
                     << cbor_error_string(err);
          throw std::runtime_error{"An unexpected error occured while copying "
                                   "the y-coordinate into the vector"};
        }
        break;
      }
      default: // Ignoring the rest
        break;
      }
      if ((err = cbor_value_advance(&it)) != CborNoError) {
        LOG(ERROR) << "An unexpected error occured during cbor_value_advance() "
                      "CborError: "
                   << cbor_error_string(err);
        throw std::runtime_error{"An unexpected error occured"};
      }
    }
    this->pkey = pkPtr;
  }

  // Check if all fields were found
  if (!check.all()) {
    LOG(WARNING) << "Not all fields for the specified cipher has been set";
    throw std::invalid_argument{"Missing fields for the cipher"};
  }
  LOG(INFO) << "Cipher field status check passed";
}

const std::shared_ptr<PublicKey> AttestedCredentialData::getPublicKey() const {
  return this->pkey;
}

AttestedCredentialData::~AttestedCredentialData() {}