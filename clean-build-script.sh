#!/bin/sh

rm -rf ./build
rm -rf ./output

cmake -B build -DSTANDALONE_MODE=ON  
cmake --build build
DESTDIR=output cmake --install build

cd ./output/executables
