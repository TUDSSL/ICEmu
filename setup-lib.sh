#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $BASE_DIR

pushd lib

#git submodule update --init --recursive unicorn
pushd unicorn
echo "Build unicorn"
# If a build already exists (avoid re-configure)
if [ -d build ]; then
    pushd build
    make -j$(nproc)
    popd
else
    mkdir build
    pushd build
    cmake ../
    make -j$(nproc)
    popd
fi

popd

#git submodule update --init --recursive capstone
pushd capstone
echo "Build capstone"
./make.sh
popd

popd
