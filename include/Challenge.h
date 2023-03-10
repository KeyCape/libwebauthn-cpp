#pragma once
#include "IJsonSerialize.h"
#include <bitset>
#include <memory>
#include <random>

#define BYTE_LEN 16

class Challenge : IJsonSerialize {
private:
  std::shared_ptr<std::vector<unsigned char>> challenge;

public:
  Challenge();
  std::shared_ptr<std::vector<unsigned char>> getChallenge();
  virtual std::unique_ptr<Json::Value>getJson() override;
  ~Challenge();
};