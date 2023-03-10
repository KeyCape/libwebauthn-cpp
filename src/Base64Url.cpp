#include "Base64Url.h"

void Base64Url::decode(std::shared_ptr<std::string> msg) {
  if (!msg) {
    throw std::invalid_argument{"The msg must not be null"};
  }

  // Replace - with +
  *msg = std::regex_replace(*msg, std::regex{"-"}, "+");
  // Replace _ with /
  *msg = std::regex_replace(*msg, std::regex{"_"}, "/");
  // Append ==
  msg->append("==");
}

void Base64Url::encode(std::shared_ptr<std::string> msg) {
  if (!msg) {
    throw std::invalid_argument{"The msg must not be null"};
  }

  // Replace + with -
  *msg = std::regex_replace(*msg, std::regex{"\\+"}, "-");
  // Replace / with _
  *msg = std::regex_replace(*msg, std::regex{"/"}, "_");
  // Remove =
  *msg = std::regex_replace(*msg, std::regex{"="}, "");
}