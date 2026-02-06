cmake_minimum_required(VERSION 3.16)
project(KernelLevelMemoryScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(scanner src/main.cpp)

if(WIN32)
    target_link_libraries(scanner PRIVATE Psapi)
endif()
