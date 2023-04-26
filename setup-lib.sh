#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $BASE_DIR

# If MAKEFLAGS was not explicitly set by the user, set it with the number of cores
# in case the user makes use of the "Unix Makefiles" CMake generator
if [ -z "$MAKEFLAGS" ]; then
    export MAKEFLAGS="-j$(nproc)"
fi

pushd lib

#git submodule update --init --recursive unicorn
echo "Build unicorn"
# Only configure if not done so yet
if [ ! -d unicorn/build ]; then
    cmake -S unicorn -B unicorn/build
fi
cmake --build unicorn/build

#git submodule update --init --recursive capstone
echo "Build capstone"
cmake -S capstone -B capstone/build -DCMAKE_BUILD_TYPE=Release
cmake --build capstone/build

popd
