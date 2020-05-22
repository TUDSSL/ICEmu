#!/bin/bash

echo "Build the hook concept"
g++ -g -Wall -I. hooks.cpp -o hooks.o -ldl -lboost_system -lboost_filesystem
#g++ -g -Wall -fsanitize=address -fsanitize=undefined -I. hooks.cpp -o hooks.o -ldl -lboost_system -lboost_filesystem

echo "Build the plugin concept"
g++ -g -Wall -shared -fPIC -I. HookCodePlugin.cpp -o HookCodePlugin.so
