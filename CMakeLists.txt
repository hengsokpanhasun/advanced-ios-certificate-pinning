cmake_minimum_required(VERSION 3.10)
project(advanced_ios_certificate_pinning C)

# This builds and tests the portable C core (src/). The iOS integration layer in
# ios/ is Objective-C against Apple's Security framework and is built inside an
# Xcode app project, not here. See ios/README.md.

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
  add_compile_options(/W4)
else()
  add_compile_options(-Wall -Wextra)
endif()

add_library(aicp STATIC
  src/sha256.c
  src/hmac_sha256.c
  src/pins.c
  src/aicp.c)
target_include_directories(aicp PUBLIC include PRIVATE src)

add_executable(aicp_demo examples/demo.c)
target_link_libraries(aicp_demo aicp)
target_include_directories(aicp_demo PRIVATE src tests)

add_executable(gen_pins tools/gen_pins.c)
target_link_libraries(gen_pins aicp)
target_include_directories(gen_pins PRIVATE src)

enable_testing()

add_executable(test_crypto tests/test_crypto.c)
target_link_libraries(test_crypto aicp)
target_include_directories(test_crypto PRIVATE src)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_pinning tests/test_pinning.c)
target_link_libraries(test_pinning aicp)
target_include_directories(test_pinning PRIVATE src tests)
add_test(NAME pinning COMMAND test_pinning)
