cmake_minimum_required(VERSION 3.10)
project(cryptopp)

set(CMAKE_CXX_STANDARD 17)
#link_directories(${CMAKE_SOURCE_DIR}/lib)
#set(CMAKE_CXX_FLAGS "-v")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

add_executable(cryptopp main.cpp)

include(FindPkgConfig)
find_package(Cryptopp REQUIRED)
include_directories(${CRYPTOPP_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} ${CRYPTOPP_LIBRARY})