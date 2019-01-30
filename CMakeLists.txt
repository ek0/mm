cmake_minimum_required(VERSION 3.12)

project(mm VERSION 0.1)

# Putting binaries in the output folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${PROJECT_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Generating core libraries
# -----------------------------------------------------------------------------
add_library("mm" STATIC "${CMAKE_CURRENT_LIST_DIR}/mm.c"
                        "${CMAKE_CURRENT_LIST_DIR}/mm.h")