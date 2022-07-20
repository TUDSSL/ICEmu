
set(PLUGIN_NAME "riscv32_rocketchip_syscall_plugin.so")

add_executable(${PLUGIN_NAME}
    "Riscv32RocketchipSyscall.cpp"
    )

target_include_directories(${PLUGIN_NAME}
    PUBLIC
    ../riscv64_rocketchip_syscall_plugin/
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
