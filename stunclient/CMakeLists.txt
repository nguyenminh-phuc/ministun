cmake_minimum_required(VERSION 3.20)
project(stunclient)

add_executable(stunclient
        main.cpp)

target_compile_features(stunclient PRIVATE cxx_std_20)

target_include_directories(stunclient PRIVATE .)

target_compile_options(stunclient PRIVATE -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments)

target_link_libraries(stunclient PRIVATE ministun)
