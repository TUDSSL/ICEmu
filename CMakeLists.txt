cmake_minimum_required(VERSION 3.15)

project(ICEmu LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Build the libraries
#execute_process(COMMAND bash "-c" ${CMAKE_SOURCE_DIR}/"setup-lib.sh")

#Include Unicorn
include_directories(${CMAKE_SOURCE_DIR}/lib/unicorn/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/unicorn/build)

#Include Capstone
include_directories(${CMAKE_SOURCE_DIR}/lib/capstone/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/capstone/build)

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
include(ExternalProject)
ExternalProject_Add(plugins
  EXCLUDE_FROM_ALL false
  DEPENDS ICEmu
  SOURCE_DIR ${CMAKE_SOURCE_DIR}/plugins
  BINARY_DIR ${CMAKE_SOURCE_DIR}/plugins/build
  CONFIGURE_COMMAND ${CMAKE_COMMAND} ../
  #BUILD_COMMAND "make"
  BUILD_ALWAYS true
  INSTALL_COMMAND ""
  )
