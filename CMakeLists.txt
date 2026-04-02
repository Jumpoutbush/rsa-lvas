cmake_minimum_required(VERSION 3.16)

project(rsa_lvas LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- OpenSSL ----
find_package(OpenSSL REQUIRED)

# ---- Library ----
add_library(rsa_lvas STATIC
  rsa_lvas.cpp
)
# ---- PKI module (LVAS Directory PKI demo) ----
add_library(pki_lvas STATIC
  pki_lvas.cpp
)
# ---- Time-Space Tradeoff PKI module ----
add_library(pki_timespace STATIC
  pki_timespace.cpp
)

target_include_directories(rsa_lvas
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(pki_lvas PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)
target_include_directories(pki_timespace PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(rsa_lvas
  PUBLIC
    OpenSSL::Crypto
)
target_link_libraries(pki_lvas PUBLIC
  rsa_lvas
  OpenSSL::Crypto
)
target_link_libraries(pki_timespace PUBLIC
  pki_lvas
  rsa_lvas
  OpenSSL::Crypto
)

# Reasonable warnings (optional)
if (MSVC)
  target_compile_options(rsa_lvas PRIVATE /W4 /permissive-)
else()
  target_compile_options(rsa_lvas PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ---- Example ----
add_executable(example
  example.cpp
)
target_link_libraries(example
  PRIVATE
    rsa_lvas
)

add_executable(pki_demo
  pki_demo.cpp
)
target_link_libraries(pki_demo PRIVATE
  pki_lvas
)

add_executable(pki_demo_chain_timespace
  pki_demo_chain_timespace.cpp
)
target_link_libraries(pki_demo_chain_timespace PRIVATE
  pki_lvas
  rsa_lvas
  OpenSSL::Crypto
)

add_executable(pki_demo_chain
  pki_demo_chain.cpp
)

target_link_libraries(pki_demo_chain PRIVATE
  pki_lvas
  rsa_lvas
  OpenSSL::Crypto
)