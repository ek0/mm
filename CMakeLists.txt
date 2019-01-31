cmake_minimum_required(VERSION 3.12)
include(GenerateExportHeader) 

project(mm VERSION 0.1)

# Putting binaries in the output folder
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY  ${PROJECT_BINARY_DIR}/bin)

# -----------------------------------------------------------------------------
# Generating core libraries
# -----------------------------------------------------------------------------
add_library("mm" STATIC)

generate_export_header("mm" BASE_NAME "mm" 
                       EXPORT_FILE_NAME "mm_export_config.h")
target_include_directories("mm" PUBLIC "include" ${PROJECT_BINARY_DIR})
target_sources("mm" PRIVATE "${CMAKE_CURRENT_LIST_DIR}/src/mm.c")