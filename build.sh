#!/bin/bash
set -e

export CC=clang
export CXX=clang++

unset CFLAGS CXXFLAGS LDFLAGS LIBS
mkdir -p build && cd build
# export LIB_FUZZING_ENGINE="/path/to/libFuzzer.a"
# custom_flags='-DCUSTOM_FUZZ=ON'
cmake -G Ninja .. \
    -DENABLE_STATIC=ON \
    -DENABLE_FUZZER=ON \
    -DINSTRUMENT_DISSECTORS_ONLY=ON \
    -DBUILD_fuzzshark=ON \
    -DBUILD_wireshark=OFF \
    -DBUILD_sharkd=OFF \
    -DENABLE_PCAP=OFF \
    -DENABLE_ZLIB=OFF \
    -DENABLE_MINIZIP=OFF \
    -DENABLE_LZ4=OFF \
    -DENABLE_BROTLI=OFF \
    -DENABLE_SNAPPY=OFF \
    -DENABLE_ZSTD=OFF \
    -DENABLE_NGHTTP2=OFF \
    -DENABLE_NGHTTP3=OFF \
    -DENABLE_LUA=OFF \
    -DENABLE_SMI=OFF \
    -DENABLE_GNUTLS=OFF \
    -DENABLE_NETLINK=OFF \
    -DENABLE_KERBEROS=OFF \
    -DENABLE_SBC=OFF \
    -DENABLE_SPANDSP=OFF \
    -DENABLE_BCG729=OFF \
    -DENABLE_AMRNB=OFF \
    -DENABLE_ILBC=OFF \
    -DENABLE_LIBXML2=OFF \
    -DENABLE_OPUS=OFF \
    -DENABLE_SINSP=OFF \
    -DENABLE_DEBUG=ON \
    $custom_flags
ninja fuzzshark
cp run/fuzzshark ..
