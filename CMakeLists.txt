cmake_minimum_required(VERSION 3.5)
project(webauthn VERSION 0.1)

add_library(webauthn STATIC src/webauthn.cpp include/webauthn.h)
target_include_directories(webauthn PUBLIC include)
