#include "Challenge.h"
#include <algorithm>
#include <random>

Challenge::Challenge() {
  std::random_device rd;
  std::independent_bits_engine<std::mt19937_64, 8, unsigned int> e1{rd()};

  this->challenge = std::make_shared<std::vector<char>>(BYTE_LEN);
  std::generate(this->challenge->begin(), this->challenge->end(), e1);
}

std::shared_ptr<std::vector<char>> Challenge::getChallenge() {
  return this->challenge;
}

Challenge::~Challenge() {}