# Set include directory
set(INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls
                 ${CMAKE_CURRENT_SOURCE_DIR}/include/internal
                 /opt/intel/sgxsdk/include
                 /usr/include
                 ${RATS_TLS_INSTALL_PATH}/include
                 ${RATS_TLS_INSTALL_PATH}/include/librats
                 )
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/edl
                             ${CMAKE_BINARY_DIR}/src/sgx/trust
                             )
endif()

# Add third party and instance directory
if(SGX)
    add_subdirectory(sgx)
endif()

# Add third party library required by crypto_wrappers and tls_wrappers
if(SGX)
    list(APPEND INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/external/sgx-ssl/intel-sgx-ssl/src/intel-sgx-ssl/Linux/package/include)
    list(APPEND INCLUDE_DIRS ${LIBRATS_ROOT})
endif()
add_subdirectory(tls_wrappers)

list(APPEND INCLUDE_DIRS ${LIBCBOR_INC_PATH})

include_directories(${INCLUDE_DIRS})

# Set source file
set(SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_common.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/rtls_core_generate_certificate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/main.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/cpu.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/dice.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/endorsement.c
    ${CMAKE_CURRENT_SOURCE_DIR}/core/claim.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_cleanup.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_init.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_negotiate.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_receive.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_transmit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/api/rats_tls_callback.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_register.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_all.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_load_single.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/rtls_tls_wrapper_select.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/internal/tls_wrapper.c
    ${CMAKE_CURRENT_SOURCE_DIR}/tls_wrappers/api/tls_wrapper_verify_certificate_extension.c
    )
if(SGX)
    list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/rtls_syscalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_ecdsa_ecalls.c
                        ${CMAKE_CURRENT_SOURCE_DIR}/sgx/trust/sgx_dummy.c
                        )
endif()

# Static library dependencies
if(SGX)
    set(DEPEND_TRUSTED_LIBS rtls_edl_t
                            intel-sgx-ssl
                            tls_wrapper_nulltls
                            tls_wrapper_openssl
                            libcbor
                            librats
                            )
endif()

# Generate library
if(SGX)
    add_trusted_library(${RTLS_LIB} SRCS ${SOURCES})
    add_dependencies(${RTLS_LIB} ${DEPEND_TRUSTED_LIBS})
else()
    add_library(${RTLS_LIB} SHARED ${SOURCES})
    target_link_libraries(${RTLS_LIB} ${RATS_TLS_LDFLAGS} cbor)
    set_target_properties(${RTLS_LIB} PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR})
endif()

# Install lib
install(TARGETS ${RTLS_LIB}
    DESTINATION ${RATS_TLS_INSTALL_LIB_PATH})

# Install header
set(RTLS_INCLUDE_FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/api.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/cert.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/claim.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/crypto_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/attester.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/verifier.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/err.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/log.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/sgx.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/tls_wrapper.h
                       ${CMAKE_CURRENT_SOURCE_DIR}/include/rats-tls/hash.h
                       )
install(DIRECTORY DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH})
install(FILES ${RTLS_INCLUDE_FILES}
DESTINATION ${RATS_TLS_INSTALL_INCLUDE_PATH})
