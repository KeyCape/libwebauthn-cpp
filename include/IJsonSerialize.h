#pragma once
#include <jsoncpp/json/json.h>
#include <memory>

class IJsonSerialize {
public:
  IJsonSerialize(){};
  virtual std::unique_ptr<Json::Value> getJson() = 0;
  ~IJsonSerialize(){};
};