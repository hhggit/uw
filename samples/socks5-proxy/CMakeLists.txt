cmake_minimum_required(VERSION 3.5)
project(socks5-proxy)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "-Wall -Wextra")

aux_source_directory(${PROJECT_SOURCE_DIR} _src_list)

add_executable(${PROJECT_NAME} ${_src_list})
target_link_libraries(${PROJECT_NAME} PRIVATE uw)
set(MAX_CONNECT_COUNT "" CACHE STRING "for VALGRIND")
if (MAX_CONNECT_COUNT)
  target_compile_definitions(${PROJECT_NAME} PRIVATE MAX_CONNECT_COUNT=${MAX_CONNECT_COUNT})
endif()
