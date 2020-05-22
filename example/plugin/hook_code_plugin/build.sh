#!/bin/bash

# Specify the ICEmu include directory
ICEMU_INCLUDE_DIR=../../../include

echo "Build the plugin"
g++ -g -Wall -I$ICEMU_INCLUDE_DIR -shared -fPIC -I. HookCodePlugin.cpp -o hook_code_plugin.so
