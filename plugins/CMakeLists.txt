cmake_minimum_required(VERSION 3.15)

project(Plugins LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#Include Unicorn
include_directories(${CMAKE_SOURCE_DIR}/../lib/unicorn/include)
link_directories(${CMAKE_SOURCE_DIR}/../lib/unicorn/build)

#Include Capstone
include_directories(${CMAKE_SOURCE_DIR}/../lib/capstone/include)
link_directories(${CMAKE_SOURCE_DIR}/../lib/capstone)

#Include ElfIO
include_directories(${CMAKE_SOURCE_DIR}/../lib/ELFIO)

#Include ICEmu
include_directories(${CMAKE_SOURCE_DIR}/../include/)
link_directories(${CMAKE_SOURCE_DIR}/../build/)

# Include Common dir
include_directories(common/)

set(PLUGIN_INCLUDE_DIRECTORIES
    ${PROJECT_SOURCE_DIR}/include
    )

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

add_subdirectory(display_instructions_plugin)
add_subdirectory(call_count_plugin)
add_subdirectory(mock_putc_plugin)
add_subdirectory(mock_clockfunc_plugin)
add_subdirectory(display_memory_plugin)
add_subdirectory(shadow_memory_plugin)

# ARMv7 specific plugins
add_subdirectory(armv7_stop_emulation_plugin)

# RISCV generic plugins
add_subdirectory(riscv_stop_emulation_plugin)

# RISCV64 specific plugins
add_subdirectory(riscv64_rocketchip_syscall_plugin)

# RISCV32 specific plugins
add_subdirectory(riscv32_rocketchip_syscall_plugin)


# Legacy plugins, not tested with the currecnt version of ICEmu
#add_subdirectory(callsite_count_plugin)
#add_subdirectory(step_instructions_plugin)
#add_subdirectory(mock_putc_plugin)
#add_subdirectory(mock_clockfunc_emutime_plugin)
#add_subdirectory(memory_access_ratio_plugin)
#add_subdirectory(instruction_count_main_plugin)
#add_subdirectory(intermittency_plugin)
#add_subdirectory(idempotency_statistics_plugin)
#add_subdirectory(cycle_count_plugin)
#add_subdirectory(final_value_plugin)
#add_subdirectory(track_variable_plugin)
#add_subdirectory(checkpoint_verification_plugin)
#add_subdirectory(checkpoint_marker_plugin)
#add_subdirectory(checkpoint_side_effects_plugin)
#add_subdirectory(instruction_profiling_plugin)
#add_subdirectory(call_count_plugin)
#add_subdirectory(call_frequency_plugin)
#add_subdirectory(powertrace_plugin)
