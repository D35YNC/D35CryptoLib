cmake_minimum_required(VERSION 3.5)

project(d35crypto LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20 -lntl -lgmp -lm")

set(HDR_FILES "exceptions.h" "utils.h"
              "symmetric_key/key.h" "symmetric_key/symmetric_cipher_base.h" "symmetric_key/rc4.h" "symmetric_key/aes.cpp"
              "public_key/rsakey.h" "public_key/rsa.h" "public_key/elgamal.h" "public_key/elgamalkey.h" "public_key/fiatshamir.h" "public_key/fiatshamirkey.h"
              "encoding/base64.h" "encoding/base32.h"
              "hash/hash_base.h" "hash/sha256.h" "hash/sha512.h" "hash/streebog.h" "hash/hmac.h" "hash/crc32.h")

set(SRC_FILES "hash/sha256.cpp" "hash/sha512.cpp" "hash/streebog.cpp"
              "public_key/rsakey.cpp" "public_key/rsa.cpp" "public_key/elgamal.cpp" "public_key/elgamalkey.cpp" "public_key/fiatshamir.cpp" "public_key/fiatshamirkey.cpp"
              "symmetric_key/aes.h")

add_library(d35crypto STATIC ${HDR_FILES} ${SRC_FILES})

target_link_libraries(${PROJECT_NAME} ntl gmp)
