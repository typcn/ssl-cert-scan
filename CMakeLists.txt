cmake_minimum_required(VERSION 2.6)
project(sslscan)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -lpthread -lssl -lcrypto -std=c99")

set(SOURCE_FILES
    sslscan.c
	)

add_executable(sslscan ${SOURCE_FILES})