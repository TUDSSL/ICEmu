# Add executable target
add_executable(${PROJECT_NAME}
    "main.c"
    )

# Link to libraries
target_link_libraries(${PROJECT_NAME} pthread m unicorn capstone elf)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
