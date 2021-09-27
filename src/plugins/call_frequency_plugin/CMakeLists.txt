
set(PLUGIN_NAME "call_frequency_plugin.so")

add_executable(${PLUGIN_NAME}
    "CallFrequency.cpp"
    )

target_include_directories(${PLUGIN_NAME}
    PUBLIC
    "../cycle_count_plugin/"
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
