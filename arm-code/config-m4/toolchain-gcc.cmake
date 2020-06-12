# CMake toolchain file for GCC

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(CPU "cortex-m4" CACHE STRING "")

set(CONFIG_DIR "${PROJECT_SOURCE_DIR}/config-m4")

set(OUTPUT_SUFFIX ".elf" CACHE STRING "")
set(LINKER_SCRIPT "${CONFIG_DIR}/linkerscript.ld")
set(STARTUP_CODE "${CONFIG_DIR}/startup.c")

set(CMAKE_C_COMPILER    "arm-none-eabi-gcc")
set(CMAKE_CXX_COMPILER  "arm-none-eabi-g++")
set(CMAKE_AR            "arm-none-eabi-ar")
set(CMAKE_LINKER        "arm-none-eabi-ld")
set(CMAKE_NM            "arm-none-eabi-nm")
set(CMAKE_OBJDUMP       "arm-none-eabi-objdump")
set(CMAKE_STRIP         "arm-none-eabi-strip")
set(CMAKE_RANLIB        "arm-none-eabi-ranlib")
set(CMAKE_SIZE          "arm-none-eabi-size")

# General compiler flags
add_compile_options(
    -mthumb
    -mcpu=${CPU}
    )



# Toolchain include directories
# include_directories(
#     )

# Device linker flags
add_link_options(
    -mthumb
    -mcpu=${CPU}
    -specs=nano.specs -specs=nosys.specs
    )
