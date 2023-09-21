
if(NOT "/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitinfo.txt" IS_NEWER_THAN "/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitclone-lastrun.txt")
  message(STATUS "Avoiding repeated git clone, stamp file is up to date: '/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitclone-lastrun.txt'")
  return()
endif()

execute_process(
  COMMAND ${CMAKE_COMMAND} -E remove_directory "/root/hht/rats-tls/src/external/librats/src/librats"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to remove directory: '/root/hht/rats-tls/src/external/librats/src/librats'")
endif()

# try the clone 3 times in case there is an odd git clone issue
set(error_code 1)
set(number_of_tries 0)
while(error_code AND number_of_tries LESS 3)
  execute_process(
    COMMAND "/usr/bin/git"  clone --no-checkout "https://github.com/houhuiting/librats.git" "librats"
    WORKING_DIRECTORY "/root/hht/rats-tls/src/external/librats/src"
    RESULT_VARIABLE error_code
    )
  math(EXPR number_of_tries "${number_of_tries} + 1")
endwhile()
if(number_of_tries GREATER 1)
  message(STATUS "Had to git clone more than once:
          ${number_of_tries} times.")
endif()
if(error_code)
  message(FATAL_ERROR "Failed to clone repository: 'https://github.com/houhuiting/librats.git'")
endif()

execute_process(
  COMMAND "/usr/bin/git"  checkout 42e2d7df63aed8e08d40a13562b4e1573d7c6d8c --
  WORKING_DIRECTORY "/root/hht/rats-tls/src/external/librats/src/librats"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to checkout tag: '42e2d7df63aed8e08d40a13562b4e1573d7c6d8c'")
endif()

set(init_submodules TRUE)
if(init_submodules)
  execute_process(
    COMMAND "/usr/bin/git"  submodule update --recursive --init 
    WORKING_DIRECTORY "/root/hht/rats-tls/src/external/librats/src/librats"
    RESULT_VARIABLE error_code
    )
endif()
if(error_code)
  message(FATAL_ERROR "Failed to update submodules in: '/root/hht/rats-tls/src/external/librats/src/librats'")
endif()

# Complete success, update the script-last-run stamp file:
#
execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy
    "/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitinfo.txt"
    "/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitclone-lastrun.txt"
  RESULT_VARIABLE error_code
  )
if(error_code)
  message(FATAL_ERROR "Failed to copy script-last-run stamp file: '/root/hht/rats-tls/src/external/librats/src/librats-stamp/librats-gitclone-lastrun.txt'")
endif()

