cmake_minimum_required(VERSION 3.20)
project(tests)

function(ms_add_test name)
    add_executable(${name} ${name}.cpp)
    target_compile_features(${name} PRIVATE cxx_std_20)
    target_compile_options(${name} PRIVATE -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments)
    target_link_libraries(${name} PRIVATE ministun)
    add_test(${name}Test ${name})
endfunction()

ms_add_test(Rfc5769ShortTerm)
ms_add_test(Rfc5769LongTerm)
ms_add_test(Rfc8489)