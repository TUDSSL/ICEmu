cmake_minimum_required(VERSION 3.15)

project(ICEmu LANGUAGES C ASM)

#execute_process(COMMAND "setup-lib.sh")

#Include Unicorn
include_directories(${CMAKE_SOURCE_DIR}/lib/unicorn/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/unicorn)

#Include Capstone
include_directories(${CMAKE_SOURCE_DIR}/lib/capstone/include/capstone)
link_directories(${CMAKE_SOURCE_DIR}/lib/capstone)

add_subdirectory(src)
