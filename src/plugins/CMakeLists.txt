set(PLUGIN_INCLUDE_DIRECTORIES
    ${PROJECT_SOURCE_DIR}/include
    )

set(PLUGIN_COMPILE_OPTIONS
    -Wall
    -Wextra
    -g
    -O0
    -std=c++11
    -shared
    -fPIC
    )

set(PLUGIN_LINK_OPTIONS
    -shared
    -fPIC
    )

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/plugins)

add_subdirectory(display_instructions_plugin)
add_subdirectory(step_instructions_plugin)
add_subdirectory(mock_putc_plugin)
add_subdirectory(mock_clockfunc_plugin)
add_subdirectory(mock_clockfunc_emutime_plugin)
add_subdirectory(memory_access_ratio_plugin)
add_subdirectory(instruction_count_main_plugin)
add_subdirectory(intermittency_plugin)
add_subdirectory(idempotency_statistics_plugin)
