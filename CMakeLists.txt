cmake_minimum_required(VERSION 3.20)
project(ministun-project)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif ()

enable_testing()

add_subdirectory(ministun)
add_subdirectory(stunclient)
add_subdirectory(stunserver)
add_subdirectory(tests)
