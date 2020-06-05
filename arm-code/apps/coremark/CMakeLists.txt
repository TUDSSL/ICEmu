project(coremark LANGUAGES C ASM)

#set(DEPENDENCIES
#    )
#
## Source files of libraries and externals
#foreach(dep ${DEPENDENCIES})
#    list(APPEND DEP_SOURCES "${CMAKE_SOURCE_DIR}/${dep}/*.[cs]")
#endforeach()

# List source files to be compiled
file(GLOB SOURCES
    core_list_join.c
    core_main.c
    core_matrix.c
    core_state.c
    core_util.c
    icemu/core_portme.c
    icemu/printf.c
    ${STARTUP_CODE}
    )

# Add executable target
add_executable(${PROJECT_NAME} ${SOURCES})

# Change target suffix
set_target_properties(${PROJECT_NAME} PROPERTIES SUFFIX ${OUTPUT_SUFFIX})

target_include_directories(${PROJECT_NAME}
       PUBLIC
       ./
       ./icemu/
     )


# Compiler options for this project
target_compile_options(${PROJECT_NAME}
    PUBLIC -mfpu=fpv4-sp-d16 -mfloat-abi=hard
    PRIVATE -O0
    PRIVATE -g -gdwarf-3
    PRIVATE -Wall
    PRIVATE -std=c99
    PRIVATE -MMD -MP
    PRIVATE -ffunction-sections -fdata-sections -fomit-frame-pointer
    )

# Include directories of libraries and externals
#foreach(dep ${DEPENDENCIES})
#    target_include_directories(${PROJECT_NAME}
#        PRIVATE ${CMAKE_SOURCE_DIR}/${dep}/)
#endforeach()

# Linker options for this project
target_link_options(${PROJECT_NAME}
    PUBLIC -mfpu=fpv4-sp-d16 -mfloat-abi=hard
    PRIVATE -nostartfiles -static
    PRIVATE -Wl,--gc-sections,--entry,Reset_Handler
    PRIVATE -Wl,-Map=${PROJECT_NAME}.map
    PRIVATE -T ${LINKER_SCRIPT}
    )

target_link_libraries(${PROJECT_NAME}
    gcc
    c
    m
    )

target_compile_definitions(${PROJECT_NAME}
  PUBLIC
  PERFORMANCE_RUN=1
  ITERATIONS=1
  COMPILER_FLAGS="todo"
  PRINTF_LONG_SUPPORT
  )

# Print size of binary after linking
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_SIZE} ${PROJECT_NAME}${OUTPUT_SUFFIX}
    )

