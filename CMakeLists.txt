cmake_minimum_required(VERSION 3.13)
project(uw)

add_library(uw INTERFACE)
target_include_directories(uw INTERFACE include)
target_link_libraries(uw INTERFACE uv)
target_compile_features(uw INTERFACE cxx_std_11)

option(BUILD_TESTING "BUILD_TESTING?" OFF)
if(BUILD_TESTING)
  add_subdirectory(test)
endif()
