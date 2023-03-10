#pragma once
#include <exception>

class WebauthnException : public std::exception {
private:
  std::string msg;

public:
  enum reason { MISSING_ARG };
  WebauthnException() = delete;
  WebauthnException(reason &&r);
  virtual const char *what();
  ~WebauthnException();
};