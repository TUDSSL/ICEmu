cmake_minimum_required(VERSION 3.15)

project(ICEmu LANGUAGES CXX)

# Build the libraries
execute_process(COMMAND bash "-c" ${CMAKE_SOURCE_DIR}/"setup-lib.sh")

#Include Unicorn
include_directories(${CMAKE_SOURCE_DIR}/lib/unicorn/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/unicorn)

#Include Capstone
include_directories(${CMAKE_SOURCE_DIR}/lib/capstone/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/capstone)

#Include JsonCPP
include_directories(${CMAKE_SOURCE_DIR}/lib/jsoncpp/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/jsoncpp/build/lib)

#Include ElfIO
include_directories(${CMAKE_SOURCE_DIR}/lib/ELFIO)

# ICEmu sources
add_subdirectory(src/icemu)
