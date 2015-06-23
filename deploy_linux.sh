#!/bin/sh

export CPATH=/usr/local/include
export LIBRARY_PATH=/usr/local/lib
export LD_LIBRARY_PATH=/usr/local/lib

cd /home/c00clupea #or whereever you have your source

sudo rm -r c00clupeaperf-01

tar -xzvf c00clupeaperf-01.tar.gz

#tar -xzvf htdocs.tar.gz -C /var/c00clupea/

cd c00clupeaperf-01

./configure --enable-perfwithmain

make -j3

sudo make install
