cmake_minimum_required(VERSION 3.25)
project(cpp_passman)

set(CMAKE_CXX_STANDARD 17)


if (MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(cpp_passman main.cpp user.cpp user.h vault.cpp vault.h account.cpp account.h password.cpp password.h)

target_link_libraries(cpp_passman ${OPENSSL_LIBRARIES})
