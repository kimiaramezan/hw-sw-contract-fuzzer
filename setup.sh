#!/bin/bash

# Install elf2hex
git clone https://github.com/sifive/elf2hex.git
pushd elf2hex > /dev/null
autoreconf -i
./configure --target=riscv64-unknown-elf
make
sudo make install
popd > /dev/null
