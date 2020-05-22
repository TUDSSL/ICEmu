cmake_minimum_required(VERSION 3.15)

set(CMAKE_TOOLCHAIN_FILE "config-m4/toolchain.cmake")

project(arm-test-code LANGUAGES C ASM)

add_subdirectory(apps)
