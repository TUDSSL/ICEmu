cmake_minimum_required(VERSION 3.15)

project(ICEmu LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

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


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING
        #"Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel."
        "Choose the type of build, options are: Debug Release - Defaulting to: Debug"
        FORCE
        )
    message("Defaulting build type to: ${CMAKE_BUILD_TYPE}")
else()
    message("Build type: ${CMAKE_BUILD_TYPE}")
endif()

# ICEmu sources
add_subdirectory(src/icemu)

# Build the plugins
add_subdirectory(src/plugins)

# Build the examples (TODO: Make optional)
add_subdirectory(example/plugin)

# Build ARM code using GCC
add_custom_target(arm-gcc
    COMMAND bash "-c" ${CMAKE_SOURCE_DIR}/"arm-code/build-gcc.sh"
    COMMENT "Build ARM code using GCC"
    VERBATIM
)

# Build ARM code using Clang
add_custom_target(arm-clang
    COMMAND bash "-c" ${CMAKE_SOURCE_DIR}/"arm-code/build-clang.sh"
    COMMENT "Build ARM code using Clang+LLVM"
    VERBATIM
)

# Build the ARM code GCC and Clang
add_custom_target(arm
    COMMENT "Build ARM code"
    DEPENDS arm-gcc arm-clang
    VERBATIM
)
