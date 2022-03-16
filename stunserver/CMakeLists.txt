cmake_minimum_required(VERSION 3.20)
project(stunserver)

add_executable(stunserver
        stop_signal.hh
        main.cpp)

target_compile_features(stunserver PRIVATE cxx_std_20)

target_include_directories(stunserver PRIVATE .)

target_compile_options(stunserver PRIVATE -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments)

target_link_libraries(stunserver PRIVATE ministun)
