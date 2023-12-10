cmake_minimum_required(VERSION 3.0.0)
project(sadplib VERSION 0.1.1)

set(DIR ${PROJECT_SOURCE_DIR})

add_executable(sadptool 
    ${DIR}/sadptool.cpp
    ${DIR}/adapter.cpp
    ${DIR}/checksum.cpp
    ${DIR}/ethernet.cpp
    ${DIR}/sadplib.cpp
    
    )