#!/usr/bin/env bash

set -e

for proj in full simple; do
    mkdir -p ../fixtures/${proj}
    (
        cd ${proj}
        mkdir -p build
        rm -rf build/*
        cd build
        cmake -DCMAKE_BUILD_TYPE=Debug ..
        make run
    )
done

exit 0
