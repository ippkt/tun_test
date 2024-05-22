#!/bin/sh

mkdir build 2>/dev/null
cd build
cmake ..
make
cd ..
ls --color=auto -l build/
