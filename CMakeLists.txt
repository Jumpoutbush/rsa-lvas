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

target_include_directories(rsa_lvas
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(rsa_lvas
  PUBLIC
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
