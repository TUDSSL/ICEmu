
set(PLUGIN_NAME "idempotency_statistics_plugin.so")

add_executable(${PLUGIN_NAME}
    "IdempotencyStatistics.cpp"
    )

target_include_directories(${PLUGIN_NAME}
    PUBLIC
    ${PLUGIN_INCLUDE_DIRECTORIES}
    ${PROJECT_SOURCE_DIR}/src/plugins
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
