cmake_minimum_required(VERSION 2.8.12)
project(ReflectiveDLL)

file(GLOB SOURCE_FILES *.c *.h)
add_library(ReflectiveDLL STATIC ${SOURCE_FILES})
target_include_directories(ReflectiveDLL PUBLIC .)
