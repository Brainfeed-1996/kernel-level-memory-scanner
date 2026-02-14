# Kernel-Level Memory Scanner

Industrial-grade process memory analysis tool written in modern C++20.

## Features

- **Process Memory Enumeration**: Simulates kernel-level VAD (Virtual Address Descriptor) traversal
- **Pattern Scanning**: Fast byte-level pattern matching with mask support
- **Cross-Platform**: Windows (Win32 API) and Linux support
- **Build System**: CMake-based with C++20 standards

## Requirements

- C++20 compatible compiler (MSVC, GCC, Clang)
- CMake 3.16+
- Windows: Windows SDK with PSAPI
- Linux: procfs support

## Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
```

## Usage

```bash
./scanner <PID> [pattern]
```

Example:
```bash
./scanner 1234
```

## Architecture

### Components

- **MemoryRegion**: Represents a memory page with protection flags
- **MemoryScanner**: Core scanning engine with read/enumerate capabilities
- **Pattern Matching**: Byte-level comparison with wildcard mask support

### Platform Abstractions

| Feature | Windows | Linux |
|---------|---------|-------|
| Memory Read | ReadProcessMemory | procfs (simulated) |
| Enumeration | VirtualQueryEx | /proc/$pid/maps |

## License

MIT License

## Author

**Olivier Robert-Duboille**
