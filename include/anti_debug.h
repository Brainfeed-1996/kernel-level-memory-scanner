#ifndef ANTI_DEBUG_H
#define ANTI_DEBUG_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class AntiDebugDetection {
public:
    struct DebugIndicator {
        std::string technique;
        std::string description;
        bool detected;
    };
    
    AntiDebugDetection();
    std::vector<DebugIndicator> detect_anti_debug();
    void check_remote_debugging();
    void check_virtualization();
    void print_detection_report(const std::vector<DebugIndicator>& indicators);

private:
    std::vector<DebugIndicator> detected_techniques;
};

} // namespace KernelScanner

#endif
