#!/bin/bash

# Specify the ICEmu include directory
ICEMU_INCLUDE_FLAGS="-I../../../include -I../../../lib/unicorn/include -I../../../lib/capstone/include -I../../../lib/ELFIO/ -I../../../lib/jsoncpp/include"

echo "Build the plugin"
g++ -g -Wall $ICEMU_INCLUDE_FLAGS -shared -fPIC -I. HookCodePlugin.cpp -o hook_code_plugin.so
