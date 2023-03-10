#include "AttestationStatementFidoU2f.h"

AttestationStatementFidoU2f::AttestationStatementFidoU2f() {}

void AttestationStatementFidoU2f::verify(
    const std::shared_ptr<AuthenticatorData> authData,
    const std::shared_ptr<std::string> clientDataJSON) const {
  DLOG(INFO) << "Verifying FidoU2f attestation statement";

  if (!authData) {
    throw std::invalid_argument{"Authenticator data has to be initialized"};
  }

  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  DLOG(INFO) << "Parsing the x509 certificate";
  int err =
      mbedtls_x509_crt_parse_der(&crt, this->x5c->data(), this->x5c->size());
  if (err != 0) {
    throw std::invalid_argument{
        std::string{"Couldn't parse the x509 cert. Error: "}.append(
            mbedtls_low_level_strerr(err))};
  }

  char *info = (char *)std::malloc(512);
  mbedtls_x509_crt_info(info, 512, NULL, &crt);
  DLOG(INFO) << "CERT: " << info;
  std::free(info);
  DLOG(INFO) << "Signature algorithm: " << crt.private_sig_pk;

  DLOG(INFO) << "Verify that the public key is of type EC";
  int keyType = mbedtls_pk_get_type(&crt.pk);
  if (keyType != MBEDTLS_PK_ECKEY) {
    throw std::invalid_argument{
        std::string{"The certificates public key type has to be EC. But found "
                    "mbedtls_pk_type_t: "}
            .append(std::to_string(keyType))};
  }

  auto pk = mbedtls_pk_ec(crt.pk);
  if (pk == NULL) {
    throw std::invalid_argument{
        "Couldn't access the keypair of the certificate."};
  }

  DLOG(INFO)
      << "Verify that the public key is an EC public key over the P-256 curve";
  if (pk->private_grp.id != MBEDTLS_ECP_DP_SECP256R1) {
    DLOG(ERROR) << "The public key has to be an EC public key over the P-256 "
                   "curve. mbedtls_ecp_group_id: "
                << pk->private_grp.id;
    throw std::invalid_argument{
        "The public key has to be an EC public key over the P-256 curve"};
  }

  // Extract the claimed rpIdHash from authenticatorData, and the claimed
  // credentialId and credentialPublicKey from
  // authenticatorData.attestedCredentialData.
  auto attestedCredData = authData->getAttestedCredentialData();
  auto rpIdHash = authData->getRpIdHash();
  auto credentialId = attestedCredData->getCredentialId();
  auto publicKey =
      std::dynamic_pointer_cast<PublicKeyEC2>(attestedCredData->getPublicKey());

  // Convert the COSE_KEY formatted credentialPublicKey (see Section 7 of
  // [RFC9052]) to Raw ANSI X9.62 public key format (see ALG_KEY_ECC_X962_RAW in
  // Section 3.6.2 Public Key Representation Formats of [FIDO-Registry]).
  // -> Let publicKeyU2F be the concatenation 0x04 || x || y.

  auto publicKeyU2F = std::vector<uint8_t>{};
  // 0x04 indicates that the binary public key is uncompressed
  publicKeyU2F.push_back(0x04);
  // Insert x point
  publicKeyU2F.insert(publicKeyU2F.cend(), publicKey->x.cbegin(),
                      publicKey->x.cend());
  // Insert y point
  publicKeyU2F.insert(publicKeyU2F.cend(), publicKey->y.cbegin(),
                      publicKey->y.cend());

  // Let verificationData be the concatenation of (0x00 || rpIdHash ||
  // clientDataHash || credentialId || publicKeyU2F) (see Section 4.3 of
  // [FIDO-U2F-Message-Formats]).
  auto verificationData = std::vector<uint8_t>{};
  // Insert 0x00
  verificationData.push_back(0x00);
  // Insert rpIdHash
  verificationData.insert(verificationData.cend(), rpIdHash->cbegin(),
                          rpIdHash->cend());
  // Insert clientDataHash
  auto clientDataHash = std::vector<uint8_t>(32);
  err = mbedtls_sha256(reinterpret_cast<uint8_t *>(clientDataJSON->data()),
                       clientDataJSON->size(), clientDataHash.data(), 0);
  if (err != 0) {
    throw std::runtime_error{
        std::string{"Couldn't compute the sha256 hash of clientDataJSON"}
            .append(mbedtls_low_level_strerr(err))};
  }
  verificationData.insert(verificationData.cend(), clientDataHash.cbegin(),
                          clientDataHash.cend());

  // Insert credentialId
  verificationData.insert(verificationData.cend(), credentialId->cbegin(),
                          credentialId->cend());

  // Insert publicKeyU2F
  verificationData.insert(verificationData.cend(), publicKeyU2F.cbegin(),
                          publicKeyU2F.cend());

  // Verify the sig using verificationData and the certificate public key per
  // section 4.1.4 of [SEC1] with SHA-256 as the hash function used in step two.
  auto verificationDataHash = std::vector<uint8_t>(32);
  err = mbedtls_sha256(verificationData.data(), verificationData.size(),
                       verificationDataHash.data(), 0);
  if (err != 0) {
    throw std::runtime_error{
        std::string{"Couldn't compute the sha256 hash of verificationData"}
            .append(mbedtls_low_level_strerr(err))};
  }

  DLOG(INFO) << "clientDataJSON: " << clientDataJSON->data();

  DLOG(INFO) << "Verify the attestation signature " << this->sig->size();
  err = mbedtls_pk_verify(
      &crt.pk, MBEDTLS_MD_SHA256, verificationDataHash.data(),
      verificationDataHash.size(), this->sig->data(), this->sig->size());
  if (err != 0) {
    throw std::runtime_error{
        std::string{"Error occured during the signature verification of the "
                    "attestation statement: "}
            .append(mbedtls_high_level_strerr(err))};
  }
  DLOG(INFO) << "Attestation statement OK";
}

void AttestationStatementFidoU2f::extractFromCBOR(
    std::shared_ptr<CborValue> attStmt) {
  CborValue cval;
  CborError err;

  LOG(INFO) << "Check if the attestationObject is a map";
  if (!cbor_value_is_map(attStmt.get())) {
    throw std::invalid_argument{
        "The attestationObject has to be a cbor map, but is from type: " +
        cbor_value_get_type(attStmt.get())};
  }

  // Field sig
  LOG(INFO) << "Search for the field sig inside of cbor";
  err = cbor_value_map_find_value(attStmt.get(), "sig", &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the find proccess of the sig field. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  if (!cbor_value_is_byte_string(&cval)) {
    throw std::invalid_argument{
        "The cbor field sig has to be a byte_string but is of type: " +
        cbor_value_get_type(&cval)};
  }

  std::size_t buflen = 0;
  err = cbor_value_calculate_string_length(&cval, &buflen);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the length determination of the "
                    "field sig. CborError: "}
            .append(cbor_error_string(err))};
  }

  DLOG(INFO) << "The cbor field sig has a length of: " << buflen;
  this->sig = std::make_shared<std::vector<uint8_t>>(buflen);
  err = cbor_value_copy_byte_string(&cval, this->sig->data(), &buflen, NULL);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the copy operation of the sig "
                    "field. CborError: "}
            .append(cbor_error_string(err))};
  }

  // Array x5c
  LOG(INFO) << "Search for the array x5c inside of cbor";
  err = cbor_value_map_find_value(attStmt.get(), "x5c", &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{std::string{
        "Error occured during the find proccess of the x5c field. CborError: "}
                                    .append(cbor_error_string(err))};
  }

  if (!cbor_value_is_array(&cval)) {
    throw std::invalid_argument{
        "The cbor field x5c has to be an array but is of type: " +
        cbor_value_get_type(&cval)};
  }

  // Extract the first x509 cert
  err = cbor_value_enter_container(&cval, &cval);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Couldn't enter the cbor array x5c. CborError: "}.append(
            cbor_error_string(err))};
  }

  if (!cbor_value_is_byte_string(&cval)) {
    throw std::invalid_argument{"The cbor array elements of the x509 certs has "
                                "to be of type byte_string but are of type: " +
                                cbor_value_get_type(&cval)};
  }

  buflen = 0;
  err = cbor_value_calculate_string_length(&cval, &buflen);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Couldn't calculate the length of the x509 cert"}.append(
            cbor_error_string(err))};
  }

  DLOG(INFO) << "The x509 cert has a length of: " << buflen;
  this->x5c = std::make_shared<std::vector<uint8_t>>(buflen);
  err = cbor_value_copy_byte_string(&cval, this->x5c->data(), &buflen, NULL);
  if (err != CborNoError) {
    throw std::invalid_argument{
        std::string{"Error occured during the copy operation of the x509 cert. "
                    "CborError: "}
            .append(cbor_error_string(err))};
  }
  LOG(INFO) << "Finished extracting the attStmt field";
}

AttestationStatementFidoU2f::~AttestationStatementFidoU2f() {}