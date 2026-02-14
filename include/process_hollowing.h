#ifndef PROCESS_HOLLOWING_H
#define PROCESS_HOLLOWING_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace KernelScanner {

class ProcessHollowingDetector {
public:
    struct HollowingResult {
        uint32_t pid;
        std::string image_path;
        bool is_hollowed;
        std::vector<std::string> indicators;
        uintptr_t real_image_base;
        uintptr_t mapped_image_base;
    };
    
    ProcessHollowingDetector();
    HollowingResult detect_hollowing(uint32_t pid);
    void print_hollowing_report(const HollowingResult& result);

private:
    std::vector<HollowingResult> results;
};

} // namespace KernelScanner

#endif
