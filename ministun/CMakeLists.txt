cmake_minimum_required(VERSION 3.20)
project(ministun)

find_package(uriparser CONFIG REQUIRED char)
find_package(OpenSSL REQUIRED)
find_package(Seastar REQUIRED)

add_library(ministun
        include/ministun/Attribute.h
        include/ministun/Authenticator.h
        include/ministun/Body.h
        include/ministun/Buffer.h
        include/ministun/Builder.h
        include/ministun/Client.h
        include/ministun/ClientConfig.h
        include/ministun/ClientCred.h
        include/ministun/ClientSocket.h
        include/ministun/Connection.h
        include/ministun/Header.h
        include/ministun/Message.h
        include/ministun/MetricReporter.h
        include/ministun/MiniStun.h
        include/ministun/RateLimiter.h
        include/ministun/Server.h
        include/ministun/ServerConfig.h
        include/ministun/ServerSocket.h
        include/ministun/ShardedInstance.h
        include/ministun/Types.h
        include/ministun/Uri.h
        include/ministun/Utils.h
        Attribute.cpp
        Authenticator.cpp
        Body.cpp
        Builder.cpp
        Client.cpp
        ClientCred.cpp
        ClientSocket.cpp
        Connection.cpp
        Header.cpp
        Message.cpp
        MetricReporter.cpp
        RateLimiter.cpp
        Server.cpp
        ServerConfig.cpp
        ServerSocket.cpp
        Uri.cpp
        Utils.cpp)

target_compile_features(ministun PUBLIC cxx_std_20)

target_include_directories(ministun PUBLIC include)

# Disable __VA_OPT__ warning: -Wno-gnu-zero-variadic-macro-arguments
target_compile_options(ministun PRIVATE -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments)

target_link_libraries(ministun
        PUBLIC
        Seastar::seastar
        PRIVATE
        uriparser::uriparser
        OpenSSL::Crypto)
