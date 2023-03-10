#pragma once
#include "AuthenticatorAttestationResponse.h"
#include "IJsonDeserialize.h"
#include "PublicKeyCredentialDescriptor.h"
#include <cstdint>
#include <jsoncpp/json/reader.h>
#include <jsoncpp/json/value.h>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

template <typename T> class PublicKeyCredential : IJsonDeserialize {
protected:
  std::string id;
  std::string type;
  std::vector<std::uint8_t> rawId;
  std::shared_ptr<T> response;

public:
  PublicKeyCredential();
  PublicKeyCredential(std::string &&id, std::string &&type,
                      std::vector<std::uint8_t> &&rawId,
                      std::shared_ptr<T> response);
  virtual void fromJson(const std::shared_ptr<Json::Value> json) override;
  const std::string &getId();
  const std::string &getType();
  const std::vector<std::uint8_t> &getRawId();
  const std::shared_ptr<T> getResponse();
  ~PublicKeyCredential();
};

template <typename T>
PublicKeyCredential<T>::PublicKeyCredential()
    : id{""}, type{""}, rawId{0}, response{nullptr} {
  static_assert(
      std::is_base_of_v<AuthenticatorResponse, T>,
      "The template class has to be inherited from AuthenticatorResponse");
}

template <typename T>
PublicKeyCredential<T>::PublicKeyCredential(std::string &&id,
                                            std::string &&type,
                                            std::vector<std::uint8_t> &&rawId,
                                            std::shared_ptr<T> response)
    : id{id}, type{type}, rawId{rawId}, response{response} {}

template <typename T>
void PublicKeyCredential<T>::fromJson(const std::shared_ptr<Json::Value> json) {
  if (!json || json->isNull()) {
    throw std::invalid_argument{"Empty json"};
  }
  if (!json->isMember("id")) {
    throw std::invalid_argument{"Missing key: id"};
  }
  if (!json->isMember("rawId")) {
    throw std::invalid_argument{"Missing key: rawId"};
  }
  if (!json->isMember("type")) {
    throw std::invalid_argument{"Missing key: type"};
  }

  LOG(INFO) << "Device id: " << this->id << "\ttype: " << this->type;
  this->id = (*json)["id"].asString();
  this->type = (*json)["type"].asString();
  std::string rawIdTemp = (*json)["rawId"].asString();

  this->rawId.resize(rawIdTemp.size());
  std::transform(rawIdTemp.begin(), rawIdTemp.end(), this->rawId.begin(),
                 [](unsigned char c) { return c; });

  if (this->response == nullptr) {
    this->response = std::make_shared<T>();
  }

  this->response->fromJson(json);
}

template <typename T> const std::string &PublicKeyCredential<T>::getId() {
  return this->id;
}

template <typename T> const std::string &PublicKeyCredential<T>::getType() {
  return this->type;
}

template <typename T>
const std::vector<std::uint8_t> &PublicKeyCredential<T>::getRawId() {
  return this->rawId;
}

template <typename T>
const std::shared_ptr<T> PublicKeyCredential<T>::getResponse() {
  return this->response;
}

template <typename T> PublicKeyCredential<T>::~PublicKeyCredential() {}