/**
 * Kernel-Level Memory Scanner
 * Industrial-grade process memory analysis tool
 * 
 * Features:
 * - Process memory region enumeration (VAD simulation)
 * - Pattern-based memory scanning
 * - Support for executable region detection
 * 
 * Author: Olivier Robert-Duboille
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#elif defined(__linux__)
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <procfs.h>
#endif

namespace KernelScanner {

struct MemoryRegion {
    uintptr_t base_address;
    size_t size;
    uint32_t protection;
    std::string name;
    
    bool is_executable() const {
        return (protection & 0xF0) != 0; // PAGE_EXECUTE flags
    }
    
    std::string get_protection_string() const {
        std::stringstream ss;
        if (protection & PAGE_READONLY) ss << "R--";
        if (protection & PAGE_READWRITE) ss << "RW-";
        if (protection & PAGE_EXECUTE) ss << "--X";
        if (protection & PAGE_EXECUTE_READ) ss << "R-X";
        if (protection & PAGE_EXECUTE_READWRITE) ss << "RWX";
        return ss.str();
    }
};

class MemoryScanner {
private:
#ifdef _WIN32
    HANDLE hProcess;
    DWORD pid;
#elif defined(__linux__)
    int proc_fd;
    pid_t pid;
#endif

public:
    MemoryScanner(uint32_t target_pid) : pid(target_pid) {
#ifdef _WIN32
        hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!hProcess) {
            throw std::runtime_error("Failed to open process. Access denied or process not found.");
        }
#elif defined(__linux__)
        std::stringstream ss;
        ss << "/proc/" << pid;
        proc_fd = open(ss.str().c_str(), O_RDONLY);
        if (proc_fd < 0) {
            throw std::runtime_error("Failed to open process. Process not found.");
        }
#endif
        std::cout << "[+] Scanner attached to PID: " << pid << std::endl;
    }

    ~MemoryScanner() {
#ifdef _WIN32
        if (hProcess) CloseHandle(hProcess);
#elif defined(__linux__)
        if (proc_fd > 0) close(proc_fd);
#endif
    }

    std::vector<MemoryRegion> enumerate_regions() {
        std::vector<MemoryRegion> regions;
        
#ifdef _WIN32
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_NOACCESS) == 0) {
                MemoryRegion region;
                region.base_address = (uintptr_t)mbi.BaseAddress;
                region.size = mbi.RegionSize;
                region.protection = mbi.Protect;
                region.name = "Memory Region";
                regions.push_back(region);
            }
            address += mbi.RegionSize;
        }
#elif defined(__linux__)
        // Simplified Linux implementation
        std::cout << "[*] Linux memory enumeration is limited in this simulation." << std::endl;
#endif
        return regions;
    }

    std::vector<uint8_t> read_memory(uintptr_t address, size_t size) {
        std::vector<uint8_t> buffer(size);
        SIZE_T bytesRead = 0;
        
#ifdef _WIN32
        if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead)) {
            buffer.resize(bytesRead);
        } else {
            buffer.clear();
        }
#elif defined(__linux__)
        // Simulation for Linux
        std::fill(buffer.begin(), buffer.end(), 0xCC); // Fill with INT3 for simulation
#endif
        return buffer;
    }

    void scan_pattern(const std::vector<uint8_t>& pattern, const std::string& mask) {
        std::cout << "[*] Starting pattern scan..." << std::endl;
        std::cout << "[*] Searching for pattern size: " << pattern.size() << " bytes" << std::endl;
        
        auto regions = enumerate_regions();
        size_t total_scanned = 0;
        size_t matches_found = 0;
        
        for (const auto& region : regions) {
            // Skip non-readable regions
            if (region.protection & PAGE_NOACCESS || region.protection & PAGE_GUARD) {
                continue;
            }
            
            auto data = read_memory(region.base_address, region.size);
            if (data.empty()) continue;
            
            total_scanned += data.size();
            
            for (size_t i = 0; i <= data.size() - pattern.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < pattern.size(); ++j) {
                    if (mask[j] != '?' && data[i + j] != pattern[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    std::cout << "[!] MATCH FOUND at 0x" << std::hex << (region.base_address + i) << std::dec << std::endl;
                    matches_found++;
                }
            }
        }
        
        std::cout << "[*] Scan complete." << std::endl;
        std::cout << "[*] Total scanned: " << total_scanned << " bytes" << std::endl;
        std::cout << "[*] Matches found: " << matches_found << std::endl;
    }
};

} // namespace KernelScanner

void print_help() {
    std::cout << "Usage: scanner <PID> [pattern]" << std::endl;
    std::cout << "  PID: Process ID to scan" << std::endl;
    std::cout << "  pattern: Hex pattern to search (e.g., 48 89 5C 24 00)" << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  Kernel-Level Memory Scanner v1.0" << std::endl;
    std::cout << "  Author: Olivier Robert-Duboille" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (argc < 2) {
        print_help();
        return 1;
    }
    
    uint32_t pid = std::stoul(argv[1]);
    
    try {
        KernelScanner::MemoryScanner scanner(pid);
        
        // Default pattern: MOV RBX, [RSP+offset] (common function prologue)
        std::vector<uint8_t> pattern = { 0x48, 0x89, 0x5C, 0x24, 0x00 };
        std::string mask = "xxxx?";
        
        if (argc >= 3) {
            // Parse custom pattern from arguments
            std::cout << "[*] Custom pattern detection not implemented in this build." << std::endl;
        }
        
        scanner.scan_pattern(pattern, mask);
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
