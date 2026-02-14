#ifndef EDR_EVASION_H
#define EDR_EVASION_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class EDREvasionDetector {
public:
    struct EvasionTechnique {
        std::string name;
        std::string category;
        bool detected;
        std::string description;
        std::vector<std::string> iocs;
    };
    
    EDREvasionDetector();
    std::vector<EvasionTechnique> scan_for_evasion();
    void print_evasion_report();

private:
    std::vector<EvasionTechnique> techniques;
};

} // namespace KernelScanner

#endif
