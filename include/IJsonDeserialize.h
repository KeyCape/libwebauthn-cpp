#pragma once
#include <memory>
#include <jsoncpp/json/value.h>

class IJsonDeserialize {
public:
    IJsonDeserialize() {}
    virtual void fromJson(const std::shared_ptr<Json::Value> json) = 0;
    ~IJsonDeserialize() {}
};