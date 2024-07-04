cmake_minimum_required(VERSION 3.13)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

add_library(dr_model SHARED dr_model.cpp tracers.cpp util.cpp)

find_package(DynamoRIO)
if (NOT DynamoRIO_FOUND)
    message(FATAL_ERROR "DynamoRIO package required to build")
endif(NOT DynamoRIO_FOUND)

configure_DynamoRIO_client(dr_model)
use_DynamoRIO_extension(dr_model drmgr)
use_DynamoRIO_extension(dr_model drreg)
use_DynamoRIO_extension(dr_model drutil)
use_DynamoRIO_extension(dr_model drx)
use_DynamoRIO_extension(dr_model drwrap)
use_DynamoRIO_extension(dr_model drsyms)
