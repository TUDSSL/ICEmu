#!/bin/bash

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $BASE_DIR

git submodule update --init --recursive

pushd lib

pushd unicorn
echo "Build unicorn"
mkdir -p build
pushd build
cmake ../
make -j4
popd
popd

pushd capstone
echo "Build capstone"
./make.sh
popd

popd

