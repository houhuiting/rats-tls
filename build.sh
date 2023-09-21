rm -rf build/
cmake -DRATS_TLS_BUILD_MODE="sgx" -DBUILD_SAMPLES=on -H. -Bbuild
make -C build install