cmake_minimum_required(VERSION 3.13)
project(uw)


find_package(Boost 1.70.0 COMPONENTS headers)

add_library(uw INTERFACE)
target_include_directories(uw INTERFACE include)
target_compile_features(uw INTERFACE cxx_std_11)
if (Boost_FOUND)
  target_compile_definitions(uw INTERFACE UW_USE_BOOST)
  target_link_libraries(uw INTERFACE uv Boost::headers)
else()
  target_link_libraries(uw INTERFACE uv)
endif()


option(BUILD_TESTING "BUILD_TESTING?" OFF)
if(BUILD_TESTING)
  add_subdirectory(test)
endif()

option(BUILD_SAMPLES "BUILD_SAMPLES?" OFF)
if(BUILD_SAMPLES)
  add_subdirectory(samples/socks5-proxy)
endif()
