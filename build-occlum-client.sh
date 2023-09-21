#!/bin/bash
set -x
set -o errexit    # Used to exit upon error, avoiding cascading errors
cd /usr/share/rats-tls/samples

rm -rf occlum_workspace_client
mkdir occlum_workspace_client
cd occlum_workspace_client
occlum init

cp ../rats-tls-client image/bin
cp /lib/x86_64-linux-gnu/libdl.so.2 image/opt/occlum/glibc/lib
cp /usr/lib/x86_64-linux-gnu/libssl.so.1.1 image/opt/occlum/glibc/lib
cp /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 image/opt/occlum/glibc/lib
cp /usr/local/lib/librats/librats_lib.so.0 image/opt/occlum/glibc/lib
cp /usr/lib/x86_64-linux-gnu/libcurl.so.4 image/opt/occlum/glibc/lib
cp /usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1 image/opt/occlum/glibc/lib
cp /usr/lib/x86_64-linux-gnu/libnghttp2.so.14 image/opt/occlum/glibc/lib
mkdir -p image/usr/local/lib
cp -rf /usr/local/lib/rats-tls image/usr/local/lib
cp -rf /usr/local/lib/librats image/usr/local/lib

occlum build
occlum run /bin/rats-tls-client -l debug -m