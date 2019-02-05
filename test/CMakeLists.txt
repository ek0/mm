add_executable("test_load" "${CMAKE_CURRENT_LIST_DIR}/test_load.c")
add_library("dummy" SHARED "${CMAKE_CURRENT_LIST_DIR}/dummy.c")
target_link_libraries("test_load" mm)