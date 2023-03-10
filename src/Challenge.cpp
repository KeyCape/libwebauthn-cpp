#include "Challenge.h"
#include <algorithm>
#include <drogon/utils/Utilities.h>
#include <jsoncpp/json/value.h>
#include <random>

Challenge::Challenge() {
  std::random_device rd;
  std::independent_bits_engine<std::mt19937_64, 8, unsigned int> e1{rd()};

  this->challenge = std::make_shared<std::vector<unsigned char>>(BYTE_LEN);
  std::generate(this->challenge->begin(), this->challenge->end(), e1);
}
Challenge::Challenge(std::shared_ptr<std::vector<unsigned char>> challenge)
    : challenge{challenge} {}

std::shared_ptr<std::vector<unsigned char>> Challenge::getChallenge() {
  return this->challenge;
}
std::unique_ptr<Json::Value> Challenge::getJson() {
  auto ret = std::make_unique<Json::Value>(Json::stringValue);

  // Convert the vector to a string
  std::basic_string<unsigned char> str{this->challenge->begin(),
                                       this->challenge->end()};

  // Encode the challenge to base64
  auto tmpStr = std::make_shared<std::string>(
      drogon::utils::base64Encode(str.c_str(), str.size()));
  //Base64Url::encode(tmpStr);

  /* TODO
   * Die Präprozessor DIrektive __cplusplus ist zu alt. Scheinbar existieren
   * diverse Versionen. Um die Auflösung von boost zu verhindern muss der
   * Compiler auf die neueste Version aktualisiert werden.
   */
  (*ret) = *tmpStr;

  return ret;
}
void Challenge::encodeBase64Url() {
  auto tmp = std::make_shared<std::string>(this->challenge->begin(),
                                           this->challenge->end());

  Base64Url::encode(tmp);

  this->challenge.reset(
      new std::vector<unsigned char>{tmp->begin(), tmp->end()});
}

Challenge::~Challenge() {}

std::ostream &operator<<(std::ostream &os, Challenge &obj) {
  for (auto &item : *obj.getChallenge()) {
    os << item;
  }
  return os;
}
bool operator==(Challenge &lhs, Challenge &rhs) {
  auto lPtr = lhs.getChallenge();
  auto rPtr = rhs.getChallenge();
  if (lPtr && rPtr) {
    return *lPtr == *rPtr;
  }
  return false;
}