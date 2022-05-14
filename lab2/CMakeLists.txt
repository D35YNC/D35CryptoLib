cmake_minimum_required(VERSION 3.5)

project(lab2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20")

add_executable(lab2 main.cpp)
target_include_directories(lab2 PUBLIC "${CMAKE_SOURCE_DIR}/mycryptolib/")
target_link_libraries(lab2 mycryptolib)
