# Kernel-Level Memory Scanner (Simulation)

A high-performance memory analysis tool designed to simulate kernel-level process inspection.

## Features
- **Process Attachment:** Attaches to process via PID (mimicking `ObReferenceObjectByHandle` logic).
- **Memory Enumeration:** Walks the Virtual Address Descriptor (VAD) equivalent structures.
- **Pattern Scanning:** Fast signature matching for code injection detection or analysis.
- **Safety:** Runs in user-mode using standard Windows APIs (`ReadProcessMemory`, `VirtualQueryEx`) to prevent BSODs during development, but architected for easy porting to `Km`.

## Requirements
- C++20 Compiler (MSVC, Clang, GCC)
- CMake 3.16+
- Windows SDK (for headers)

## Build
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## Usage
```bash
scanner.exe <TARGET_PID>
```

## Author
**Olivier Robert-Duboille**
