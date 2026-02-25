cmake_minimum_required(VERSION 3.16)

project(fuse_tmpfs C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(_FILE_OFFSET_BITS=64)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED IMPORTED_TARGET fuse3)

add_executable(fuse-tmpfs
  main.c
  fuse_tmpfs.c
)

target_include_directories(fuse-tmpfs PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(fuse-tmpfs PRIVATE PkgConfig::FUSE3 pthread)

target_compile_options(fuse-tmpfs PRIVATE -Wall -Wextra)
