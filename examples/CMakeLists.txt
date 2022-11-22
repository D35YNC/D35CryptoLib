cmake_minimum_required(VERSION 3.5)

project(examples LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("base32-64")
add_subdirectory("hmac")
add_subdirectory("rsa")
add_subdirectory("sha")
add_subdirectory("signs")
add_subdirectory("streebog")
add_subdirectory("rc4")
