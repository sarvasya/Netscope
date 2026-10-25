cmake_minimum_required(VERSION 3.10)
project(NetScope VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# ---- Core library: no libpcap dependency, fully unit-testable --------------
add_library(netscope_core STATIC
  src/subnet.cpp
  src/parser.cpp
  src/analyzer.cpp)
target_include_directories(netscope_core PUBLIC include)

# ---- libpcap -------------------------------------------------------------
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found. Install it (e.g. 'sudo apt install libpcap-dev' "
                      "or 'brew install libpcap') and re-run cmake.")
endif()

add_executable(netscope src/main.cpp src/capture.cpp)
target_include_directories(netscope PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(netscope PRIVATE netscope_core ${PCAP_LIBRARY})

# ---- Tests ---------------------------------------------------------------
enable_testing()
add_executable(test_subnet tests/test_subnet.cpp)
target_link_libraries(test_subnet PRIVATE netscope_core)
add_test(NAME subnet COMMAND test_subnet)

add_executable(test_parser tests/test_parser.cpp)
target_link_libraries(test_parser PRIVATE netscope_core)
add_test(NAME parser COMMAND test_parser)

