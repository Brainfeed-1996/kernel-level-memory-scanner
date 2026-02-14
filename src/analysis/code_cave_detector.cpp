#include "code_cave_detector.h"

namespace KernelScanner {

CodeCaveDetector::CodeCaveDetector() {}

std::vector<CodeCaveDetector::CodeCave> CodeCaveDetector::detect_code_caves() {
    std::cout << "[*] Scanning for code caves..." << std::endl;
    
    detected_caves.clear();
    
    // Simulate code cave detection
    CodeCave cave;
    cave.address = 0x15000;
    cave.size = 256;
    cave.containing_section = ".text";
    cave.is_executable = true;
    detected_caves.push_back(cave);
    
    cave.address = 0x20000;
    cave.size = 512;
    cave.containing_section = ".data";
    cave.is_executable = false;
    detected_caves.push_back(cave);
    
    cave.address = 0x25000;
    cave.size = 1024;
    cave.containing_section = ".rsrc";
    cave.is_executable = false;
    detected_caves.push_back(cave);
    
    return detected_caves;
}

void CodeCaveDetector::analyze_caves() {
    std::cout << "[*] Analyzing code caves..." << std::endl;
    
    for (const auto& cave : detected_caves) {
        std::cout << "  Cave at 0x" << std::hex << cave.address 
                  << " (" << std::dec << cave.size << " bytes)" << std::endl;
        
        if (cave.is_executable) {
            std::cout << "    WARNING: Executable code cave!" << std::endl;
        }
    }
}

void CodeCaveDetector::print_caves_report(const std::vector<CodeCave>& caves) {
    std::cout << "\n=== Code Cave Detection Report ===" << std::endl;
    std::cout << "Total Code Caves: " << caves.size() << std::endl;
    
    int executable_count = 0;
    for (const auto& cave : caves) {
        std::cout << "\n[Code Cave]" << std::endl;
        std::cout << "  Address: 0x" << std::hex << cave.address << std::dec << std::endl;
        std::cout << "  Size: " << cave.size << " bytes" << std::endl;
        std::cout << "  Section: " << cave.containing_section << std::endl;
        std::cout << "  Executable: " << (cave.is_executable ? "YES" : "NO") << std::endl;
        
        if (cave.is_executable) executable_count++;
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total Caves: " << caves.size() << std::endl;
    std::cout << "Executable: " << executable_count << std::endl;
    std::cout << "Non-Executable: " << (caves.size() - executable_count) << std::endl;
}

} // namespace KernelScanner
