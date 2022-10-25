cmake_minimum_required(VERSION 3.5)

project(sha_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20")

add_executable(sha_example main.cpp)
target_include_directories(sha_example PRIVATE "${CMAKE_SOURCE_DIR}/lib/")
target_link_libraries(sha_example d35crypto)
