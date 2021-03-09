cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(socks5-c-client
  VERSION "1.0.0"
  )

find_package(OpenSSL REQUIRED QUIET)

set(SOCKS5_C_CLIENT_SRCS
  src/main.c
  src/socks5.c
  src/tcp.c
  src/tls.c
  )

add_executable(socks5_c_client ${SOCKS5_C_CLIENT_SRCS})

target_include_directories(socks5_c_client
  PUBLIC include
  )

target_link_libraries(socks5_c_client
  PUBLIC OpenSSL::SSL
  )
if(WIN32)
  target_link_libraries(socks5_c_client
    PUBLIC wsock32 ws2_32
    )
endif()
