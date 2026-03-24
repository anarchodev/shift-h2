cmake_minimum_required(VERSION 3.25)
project(shift_h2 VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

FetchContent_Declare(
    shift
    GIT_REPOSITORY https://github.com/anarchodev/shift.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(shift)

FetchContent_Declare(
    shift_io
    GIT_REPOSITORY https://github.com/anarchodev/shift-io.git
    GIT_TAG        main
)
FetchContent_MakeAvailable(shift_io)

FetchContent_Declare(
    nghttp2
    GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
    GIT_TAG        master
)
set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(nghttp2)

add_library(shift_h2 STATIC
    src/shift_h2.c
    src/sh2_nghttp2.c
    src/sh2_poll.c
)
target_include_directories(shift_h2
    PUBLIC  include/
    PRIVATE src/ ${nghttp2_BINARY_DIR}/lib/includes ${nghttp2_SOURCE_DIR}/lib/includes
)
target_link_libraries(shift_h2
    PUBLIC  shift shift-io
    PRIVATE nghttp2_static
)

option(BUILD_EXAMPLES "Build examples" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
