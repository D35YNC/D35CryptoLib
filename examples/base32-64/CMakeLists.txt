cmake_minimum_required(VERSION 3.5)

project(base64-32_example LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGSS} -std=c++20")

add_executable(base64-32_example main.cpp)
target_include_directories(base64-32_example PUBLIC "${CMAKE_SOURCE_DIR}/lib/")
target_link_libraries(base64-32_example d35crypto)
