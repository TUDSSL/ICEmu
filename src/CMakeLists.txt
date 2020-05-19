# Add executable target
add_executable(${PROJECT_NAME}
    "main.cpp"
    "argparse.cpp"
    )

target_compile_options(${PROJECT_NAME}
    PUBLIC
    -g
    -O0
    -std=c++11
    )

# Link to libraries
target_link_libraries(${PROJECT_NAME}
    pthread
    m
    unicorn
    capstone
    jsoncpp
    boost_program_options)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
