cmake_minimum_required(VERSION 3.16)
project(KernelLevelMemoryScanner VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")

# Source files - Detection modules
set(DETECTION_SOURCES
    src/detection/apt_detector.cpp
    src/detection/lotl_detector.cpp
    src/detection/lateral_movement_detector.cpp
    src/detection/c2_detector.cpp
    src/detection/threat_intelligence.cpp
    src/detection/persistence_detector.cpp
    src/detection/kernel_callbacks.cpp
    src/detection/process_hollowing.cpp
    src/detection/fileless_malware.cpp
    src/detection/edr_evasion.cpp
    src/detection/driver_analyzer.cpp
    src/detection/syscall_hooks.cpp
    src/detection/code_injection.cpp
    src/detection/privilege_escalation.cpp
    src/detection/rootkit_detector.cpp
)

# Source files - Analysis modules
set(ANALYSIS_SOURCES
    src/analysis/attack_chain_visualizer.cpp
    src/analysis/memory_forensics.cpp
    src/analysis/malware_sandbox.cpp
    src/analysis/yara_compiler.cpp
    src/analysis/network_analyzer.cpp
    src/analysis/disassembler.cpp
    src/analysis/shellcode_analyzer.cpp
)

# Include directories
include_directories(include)

# Executable
add_executable(scanner 
    src/main.cpp
    ${DETECTION_SOURCES}
    ${ANALYSIS_SOURCES}
)

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
