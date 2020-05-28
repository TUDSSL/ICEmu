# Add executable target
add_executable(${PROJECT_NAME}
    "main.cpp"
    "ArgParse.cpp"
    "MemoryDump.cpp"
    "emu/Memory.cpp"
    "emu/Emulator.cpp"
    )

target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    )

set(DEBUG_COMPILE_OPTIONS
    -Wall
    -Wextra
    -g
    -ggdb
    -O0
    -std=c++11
    #-pg
    -fsanitize=address -fsanitize=undefined # Find memory related bugs, makes it way slower
    )

set(DEBUG_LINK_OPTIONS
    -rdynamic
    #-pg
    -fsanitize=address -fsanitize=undefined # Find memory related bugs, makes it way slower
    )


set(RELEASE_COMPILE_OPTIONS
    -Ofast
    -g
    -ggdb
    -Wall
    -std=c++11
    -flto
    )

set(RELEASE_LINK_OPTIONS
    -flto
    -rdynamic
    )


target_compile_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_COMPILE_OPTIONS}>")
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_COMPILE_OPTIONS}>")

target_link_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_LINK_OPTIONS}>")
target_link_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_LINK_OPTIONS}>")

# Debug options
#target_compile_options(${PROJECT_NAME}
#    PUBLIC
#    -Wall
#    -g
#    -ggdb
#    -O0
#    -std=c++11
#    -fsanitize=address -fsanitize=undefined # Find memory related bugs, makes it way slower
#    )

#target_link_options(${PROJECT_NAME}
#    PUBLIC
#    -fsanitize=address -fsanitize=undefined # Find memory related bugs, makes it way slower
#    )

# Link to libraries
target_link_libraries(${PROJECT_NAME}
    pthread
    m
    unicorn
    capstone
    jsoncpp
    boost_program_options
    dl
    boost_system
    boost_filesystem
    )

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
