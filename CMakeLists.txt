cmake_minimum_required(VERSION 2.6)
project(sslscan)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpthread -lssl -lcrypto")

set(SOURCE_FILES
    sslscan.c
	)

add_executable(sslscan ${SOURCE_FILES})