# Project name
project(sgx-stub-enclave)

if(BUILD_SAMPLES)
    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/rats-tls
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include
                     /usr/local/include/librats
                     /usr/local/include/librats/edl
                     )

    set(LIBRARY_DIRS ${INTEL_SGXSSL_LIB_PATH}
                     ${LIBCBOR_LIB_PATH}
                     ${LIBRATS_LIB_PATH}
                     ${LIBRATS_LIB_PATH}/attesters
                     ${LIBRATS_LIB_PATH}/verifiers
                     ${LIBRATS_LIB_PATH}/crypto_wrappers
                     ${CMAKE_BINARY_DIR}/src
                     ${CMAKE_BINARY_DIR}/src/tls_wrappers/nulltls
                     ${CMAKE_BINARY_DIR}/src/tls_wrappers/openssl
                     )

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../src/external/librats/src/librats/include/edl
                         )
else()
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    include(CustomInstallDirs)
    include(FindRatsTls)
    if(NOT RATS_TLS_FOUND)
        message(FATAL_ERROR "Failed to find rats_tls!")
    endif()
    include(FindSGX)
    if(NOT SGX_FOUND)
        message(FATAL_ERROR "Failed to find sgx!")
    endif()
    include(CompilerOptions)
    include(SGXCommon)

    set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/rats-tls
                     ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl)

    set(LIBRARY_DIRS ${RATS_TLS_INSTALL_LIB_PATH})

    set(EDL_SEARCH_PATHS ${CMAKE_CURRENT_SOURCE_DIR}/../../src/include/edl
                         ${CMAKE_CURRENT_SOURCE_DIR}/../../src/external/librats/src/librats/include/edl
                         )
endif()

include_directories(${INCLUDE_DIRS})
link_directories(${LIBRARY_DIRS})

set(E_SRCS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_ecall.c)
set(EDLS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub.edl)
set(LDS ${CMAKE_CURRENT_SOURCE_DIR}/sgx_stub_enclave.lds)
set(DEPEND_TRUSTED_LIBS tls_wrapper_nulltls
                        tls_wrapper_openssl
                        attester_nullattester
                        attester_sgx_ecdsa
                        attester_sgx_la
                        crypto_wrapper_nullcrypto
                        crypto_wrapper_openssl
                        verifier_nullverifier
                        verifier_sgx_ecdsa_qve
                        verifier_sgx_la
                        rats_tls
                        cbor
                        rats_lib
                        )

add_enclave_library(sgx_stub_enclave SRCS ${E_SRCS} EDL ${EDLS} TRUSTED_LIBS ${DEPEND_TRUSTED_LIBS} EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${LDS})
enclave_sign(sgx_stub_enclave KEY sgx_stub_enclave.pem CONFIG sgx_stub_enclave.xml)
add_dependencies(sgx_stub_enclave rats_tls)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sgx_stub_enclave.signed.so
        DESTINATION /usr/share/rats-tls/samples)
