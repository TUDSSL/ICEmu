
set(PLUGIN_NAME "memory_access_ratio.so")

add_executable(${PLUGIN_NAME}
    "MemoryAccessRatio.cpp"
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
