#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $BASE_DIR

# Configure and make gcc versions
echo "Building ARM code using GCC"
mkdir -p build-gcc
pushd build-gcc
../cmake-gcc.sh ../
make
echo ""
popd

# Configure and make clang versions
echo "Building ARM code using Clang"
mkdir -p build-clang
pushd build-clang
../cmake-clang.sh ../
make
echo ""
popd
