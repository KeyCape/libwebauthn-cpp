#pragma once
#include <memory>
#include <string>
#include <regex>

class Base64Url {
private:
public:
  Base64Url() = delete;
  ~Base64Url() = delete;

  static void decode(std::shared_ptr<std::string> msg);
  static void encode(std::shared_ptr<std::string> msg);
};