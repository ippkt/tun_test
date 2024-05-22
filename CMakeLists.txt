
cmake_minimum_required (VERSION 3.10)

project(tun_test)

add_executable(tun_test tun_test.cc)
target_include_directories(tun_test PUBLIC ${PROJECT_SOURCE_DIR}/src)
# target_link_libraries(tun_test nng nng_private)

