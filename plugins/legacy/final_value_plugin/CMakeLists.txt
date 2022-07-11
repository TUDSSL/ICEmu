
set(PLUGIN_NAME "final_value_plugin.so")

add_executable(${PLUGIN_NAME}
    "FinalValue.cpp"
    )

target_include_directories(${PLUGIN_NAME}
    PUBLIC
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
