#pragma once
#include "IJsonSerialize.h"
#include "Base64Url.h"
#include <bitset>
#include <memory>
#include <random>
#include <ostream>

#define BYTE_LEN 16

class Challenge : IJsonSerialize {
private:
  std::shared_ptr<std::vector<unsigned char>> challenge;

public:
  Challenge();
  Challenge(std::shared_ptr<std::vector<unsigned char>> challenge);
  std::shared_ptr<std::vector<unsigned char>> getChallenge();
  void encodeBase64Url();
  virtual std::unique_ptr<Json::Value>getJson() override;
  ~Challenge();
};
  std::ostream& operator<<(std::ostream& os, Challenge& obj); 
  bool operator==(Challenge& lhs, Challenge& rhs); 