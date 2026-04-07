#!/bin/bash

cd openssl

if [ ! -e Makefile ]; then
    ./config
fi

make -j`nproc`
