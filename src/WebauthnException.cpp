#include "WebauthnException.h"

WebauthnException::WebauthnException(reason &&r) {
  switch (r) {
  case reason::MISSING_ARG:
    this->msg = "Invalid request: missing argument";
    break;
  }
}

const char *WebauthnException::what() { return this->msg.c_str(); }

WebauthnException::~WebauthnException() {}