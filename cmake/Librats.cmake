project(librats)

include(ExternalProject)

set(LIBRATS_ROOT        ${RTLS_SRC_PATH}/src/external/librats)
set(LIBRATS_SRC_PATH    ${LIBRATS_ROOT}/src/librats)
set(LIBRATS_INC_PATH    /usr/local/include/librats)
# set(LIBRATS_LIB_PATH    ${LIBRATS_ROOT}/src/librats/lib)
set(LIBRATS_LIB_PATH    /usr/local/lib/librats)
set(LIBRATS_LIB_FILES   ${LIBRATS_LIB_PATH}/librats_lib.a)

set(LIBRATS_URL        https://github.com/houhuiting/librats.git)

set(LIBRATS_CONFIGURE   cd ${LIBRATS_SRC_PATH} && cmake -DRATS_BUILD_MODE=sgx -DBUILD_SAMPLES=on -H. -Bbuild)
set(LIBRATS_MAKE        cd ${LIBRATS_SRC_PATH} && make)
set(LIBRATS_INSTALL     cd ${LIBRATS_SRC_PATH} && make install)

ExternalProject_Add(${PROJECT_NAME}
        GIT_REPOSITORY          ${LIBRATS_URL}
        GIT_TAG                 42e2d7df63aed8e08d40a13562b4e1573d7c6d8c
        PREFIX                  ${LIBRATS_ROOT}
        CONFIGURE_COMMAND       ${LIBRATS_CONFIGURE}
        BUILD_COMMAND           ${LIBRATS_MAKE}
        INSTALL_COMMAND         ${LIBRATS_INSTALL}
)