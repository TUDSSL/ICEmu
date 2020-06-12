cmake_minimum_required(VERSION 3.15)

message("Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}")

project(arm-test-code LANGUAGES C ASM)

add_subdirectory(apps)
