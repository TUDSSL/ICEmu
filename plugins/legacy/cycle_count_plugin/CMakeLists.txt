
set(PLUGIN_NAME "cycle_count_plugin.so")

add_executable(${PLUGIN_NAME}
    "CycleCount.cpp"
    )

target_include_directories(${PLUGIN_NAME}
    PUBLIC
    "../common"
    ${PLUGIN_INCLUDE_DIRECTORIES}
    )

target_compile_options(${PLUGIN_NAME}
    PUBLIC
    ${PLUGIN_COMPILE_OPTIONS}
    )

target_link_options(${PLUGIN_NAME}
    PUBLIC
    ${PLUGIN_LINK_OPTIONS}
    )

target_link_libraries(${PLUGIN_NAME}
    )
