#pragma once
#include <memory>

template <typename T>
class IJsonDeserialize {
public:
    IJsonDeserialize() {}
    virtual std::shared_ptr<T> fromJson(const std::string &json) = 0;
    ~IJsonDeserialize() {}
};