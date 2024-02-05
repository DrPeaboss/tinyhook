cmake_minimum_required(VERSION 3.20)
include_directories(${source_dir})
add_executable(example ./example.c)
target_link_libraries(example tinyhook)

