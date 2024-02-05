cmake_minimum_required(VERSION 3.20)
project(tinyhook)
set(source_dir ${PROJECT_SOURCE_DIR}/source)
aux_source_directory(${source_dir} th_source)
add_library(tinyhook STATIC ${th_source})
add_subdirectory(./example)

