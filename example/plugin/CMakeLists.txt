cmake_minimum_required(VERSION 3.15)

project(Plugins LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(ICEMU_ROOT_DIR "${CMAKE_SOURCE_DIR}/../../")

#Include Unicorn
include_directories(${ICEMU_ROOT_DIR}/lib/unicorn/include)
link_directories(${ICEMU_ROOT_DIR}/lib/unicorn/build)

#Include Capstone
include_directories(${ICEMU_ROOT_DIR}/lib/capstone/include)
link_directories(${ICEMU_ROOT_DIR}/lib/capstone)

#Include ElfIO
include_directories(${ICEMU_ROOT_DIR}/lib/ELFIO)

#Include ICEmu
include_directories(${ICEMU_ROOT_DIR}/include/)
link_directories(${ICEMU_ROOT_DIR}/build/)

set(PLUGIN_COMPILE_OPTIONS
    -Wall
    -Wextra
    -g
    -O3
    -std=c++11
    -shared
    -fPIC
    )

set(PLUGIN_LINK_OPTIONS
    -shared
    -fPIC
    )

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

add_subdirectory(hook_code_plugin)
add_subdirectory(hook_memory_plugin)
add_subdirectory(hook_all_events_plugin)
add_subdirectory(mock_function_plugin)
