cmake_minimum_required(VERSION 3.16)

project(nif_nif_tcp LANGUAGES C)

set(CMAKE_C_STANDARD 99)

add_executable(nif_nif_tcp main.c header.h time_func.c print_address.c app_info.c)

include(FindPCAP.cmake)

target_link_libraries(nif_nif_tcp ${PCAP_LIBRARY})
