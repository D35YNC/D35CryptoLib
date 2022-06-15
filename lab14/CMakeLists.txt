cmake_minimum_required(VERSION 3.5)

project(lab14 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20")

add_executable(lab14 main.cpp)
target_include_directories(lab14 PRIVATE "${CMAKE_SOURCE_DIR}/mycryptolib/")
target_link_libraries(lab14 mycryptolib)
