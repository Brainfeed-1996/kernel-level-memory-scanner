#ifndef LOTL_DETECTOR_H
#define LOTL_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class LotLDetector {
public:
    struct LotLAlert {
        std::string tool_name;
        std::string category;
        std::string suspicious_usage;
        std::string process_path;
        bool is_malicious;
    };
    
    LotLDetector();
    std::vector<LotLAlert> detect_lotl();
    void print_lotl_report(const std::vector<LotLAlert>& alerts);

private:
    std::vector<std::string> known_lotl_tools;
};

} // namespace KernelScanner

#endif
