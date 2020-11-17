#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $BASE_DIR

# Configure and make clang versions
echo "Building ARM code using Clang"
mkdir -p build-clang
pushd build-clang
../cmake-clang.sh ../
make
popd
