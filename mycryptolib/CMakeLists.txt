cmake_minimum_required(VERSION 3.5)

project(mycryptolib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20 -lntl -lgmp -lm")

set(HDR_FILES "exceptions.h"
              "symmetric_key/key.h"
              "public_key/rsakey.h" "public_key/rsa.h" "public_key/elgamal.h" "public_key/elgamalkey.h"
              "encoding/base64.h" "encoding/base32.h" "encoding/pkcs_base.h" "encoding/pkcs7.h" "encoding/pkcs8.h" "encoding/pkcs12.h"
              "hash/hash_base.h" "hash/sha256.h" "hash/sha512.h" "hash/streebog.h" "hash/hmac.h")

set(SRC_FILES "hash/sha256.cpp" "hash/sha512.cpp" "hash/streebog.cpp" "hash/hmac.cpp"
              "encoding/pkcs7.cpp" "encoding/pkcs8.cpp" "encoding/pkcs12.cpp"
              "public_key/rsakey.cpp" "public_key/rsa.cpp" "public_key/elgamal.cpp" "public_key/elgamalkey.cpp")

add_library(mycryptolib STATIC ${HDR_FILES} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} ntl gmp)
