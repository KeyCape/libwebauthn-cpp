#pragma once
#include <bitset>
#include <memory>
#include <random>

#define BYTE_LEN 16

class Challenge {
private:
  std::shared_ptr<std::vector<char>> challenge;

public:
  Challenge();
  std::shared_ptr<std::vector<char>> getChallenge();
  ~Challenge();
};