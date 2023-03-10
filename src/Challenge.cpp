#include "Challenge.h"
#include <algorithm>
#include <jsoncpp/json/value.h>
#include <drogon/utils/Utilities.h>
#include <random>

Challenge::Challenge() {
  std::random_device rd;
  std::independent_bits_engine<std::mt19937_64, 8, unsigned int> e1{rd()};

  this->challenge = std::make_shared<std::vector<unsigned char>>(BYTE_LEN);
  std::generate(this->challenge->begin(), this->challenge->end(), e1);
}

std::shared_ptr<std::vector<unsigned char>> Challenge::getChallenge() {
  return this->challenge;
}
std::unique_ptr<Json::Value> Challenge::getJson() {
  auto ret = std::make_unique<Json::Value>(Json::objectValue);

  // Convert the vector to a string
  std::basic_string<unsigned char> str{this->challenge->begin(),
                                       this->challenge->end()};

  // Encode the challenge to base64

  /* TODO
   * Die Präprozessor DIrektive __cplusplus ist zu alt. Scheinbar existieren diverse Versionen.
   * Um die Auflösung von boost zu verhindern muss der Compiler auf die neueste Version aktualisiert werden.
  */
  (*ret)["challenge"] = drogon::utils::base64Encode(str.c_str(), str.size());

  return ret;
}

Challenge::~Challenge() {}