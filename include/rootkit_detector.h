#ifndef ROOTKIT_DETECTOR_H
#define ROOTKIT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class RootkitDetector {
public:
    struct RootkitInfo {
        std::string name;
        std::string type;
        std::vector<std::string> hiding_locations;
        std::vector<std::string> indicators;
        bool detected;
    };
    
    RootkitDetector();
    std::vector<RootkitInfo> scan_for_rootkits();
    void detect_hidden_processes();
    void detect_hidden_files();
    void detect_inline_hooks();
    void generate_report(const std::vector<RootkitInfo>& rootkits);

private:
    std::vector<RootkitInfo> detected_rootkits;
};

} // namespace KernelScanner

#endif
