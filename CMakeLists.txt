cmake_minimum_required(VERSION 2.6)

project(aco C ASM)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

# only build examples if this is the main project
if(CMAKE_PROJECT_NAME STREQUAL "aco")
    option(ACO_BUILD_EXAMPLES "Build aco examples" ON)
endif()

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/install)

option(USE_VALGRIND "Build aco with valgrind" OFF)
option(SHARE_FPU_MXCSR_ENV "Build aco with share fpu and mxcsr environment" OFF)

set(CMAKE_C_STANDARD 99)

set(C_FLAGS
    -g
    -Wall
    -Werror
    -fno-omit-frame-pointer
    -m64
    )

set(ASM_FLAGS
    -g
    -m64
    )

if(ACO_USE_VALGRIND)
  list(APPEND C_FLAGS "-DACO_USE_VALGRIND")
  list(APPEND ASM_FLAGS "-DACO_USE_VALGRIND")
endif()

if(SHARE_FPU_MXCSR_ENV)
    list(APPEND C_FALGS "-DACO_CONFIG_SHARE_FPU_MXCSR_ENV")
    list(APPEND ASM_FALGS "-DACO_CONFIG_SHARE_FPU_MXCSR_ENV")
endif()

string(REPLACE ";" " " CMAKE_C_FLAGS "${C_FLAGS}")
string(REPLACE ";" " " CMAKE_ASM_FLAGS "${ASM_FLAGS}")

set(CMAKE_C_FLAGS_DEBUG "-Og")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "C_FLAGS = " ${CMAKE_C_FLAGS} " " ${CMAKE_C_FLAGS_${BUILD_TYPE}})
message(STATUS "ASM_FLAGS = " ${CMAKE_ASM_FLAGS} " " ${CMAKE_ASM_FLAGS_${BUILD_TYPE}})
message(STATUS "INSTALL_PREFIX = " ${CMAKE_INSTALL_PREFIX})

include_directories(${PROJECT_SOURCE_DIR})

add_library(aco STATIC 
    acosw.S 
    aco_rbtree.c 
    aco_stream.c 
    aco_time_wheel.c
    aco.c 
    aco_log.c
    aco_scheduler.c 
    )

set(ACO_HEADERS 
    aco.h 
    aco_scheduler.h 
    aco_stream.h 
    aco_log.h 
    aco_time_wheel.h
    aco_rbtree.h
    aco_queue.h
    )
    
install(FILES ${ACO_HEADERS} DESTINATION include/aco)
install(TARGETS aco DESTINATION lib)

if(ACO_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

