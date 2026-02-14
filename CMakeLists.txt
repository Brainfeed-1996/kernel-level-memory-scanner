cmake_minimum_required(VERSION 3.16)
project(KernelLevelMemoryScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Executable
include_directories(include)
add_executable(scanner src/main.cpp)

# Platform-specific settings
if(WIN32)
    target_link_libraries(scanner PRIVATE psapi)
    target_compile_definitions(scanner PRIVATE _WIN32_WINNT=0x0A00)
    target_compile_options(scanner PRIVATE /W4 /WX)
else()
    target_compile_options(scanner PRIVATE -Wall -Wextra -Wpedantic)
endif()

# Install
install(TARGETS scanner DESTINATION bin)
