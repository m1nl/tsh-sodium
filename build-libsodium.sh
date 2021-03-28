#!/bin/sh

SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

cd ./libsodium
CC=musl-gcc ./configure --prefix="$SCRIPTPATH/dist"
make -j$(nproc)
make install
