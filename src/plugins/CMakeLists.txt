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
add_subdirectory(mock_function_plugin)
