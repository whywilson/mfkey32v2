# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

project(mfkey32_library VERSION 1.0.0 LANGUAGES C)

set(COMMON_FILES
        ${SRC_DIR}/crapto1.c
        ${SRC_DIR}/crypto1.c
        ${SRC_DIR}/bucketsort.c
        ${SRC_DIR}/mfkey.c
        ${SRC_DIR}/parity.c)

include_directories(
        ${SRC_DIR}/
)

add_library(mfkey32_library SHARED
        "mfkey32.c"
        "crapto1.c"
        "crypto1.c"
        "bucketsort.c"
        "mfkey.c"
        "parity.c"
        )


set_target_properties(mfkey32_library PROPERTIES
        PUBLIC_HEADER mfkey32.h
        OUTPUT_NAME "mfkey32_library"
        )

target_compile_definitions(mfkey32_library PUBLIC DART_SHARED_LIB)