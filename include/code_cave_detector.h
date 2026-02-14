#ifndef CODE_CAVE_DETECTOR_H
#define CODE_CAVE_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace KernelScanner {

class CodeCaveDetector {
public:
    struct CodeCave {
        uintptr_t address;
        size_t size;
        std::string containing_section;
        bool is_executable;
    };
    
    CodeCaveDetector();
    std::vector<CodeCave> detect_code_caves();
    void analyze_caves();
    void print_caves_report(const std::vector<CodeCave>& caves);

private:
    std::vector<CodeCave> detected_caves;
};

} // namespace KernelScanner

#endif
