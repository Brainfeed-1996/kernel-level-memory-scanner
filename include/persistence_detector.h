#ifndef PERSISTENCE_DETECTOR_H
#define PERSISTENCE_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class PersistenceDetector {
public:
    struct PersistenceMechanism {
        std::string type;
        std::string location;
        std::string description;
        bool is_malicious;
    };
    
    PersistenceDetector();
    std::vector<PersistenceMechanism> detect_persistence();
    void print_persistence_report();

private:
    std::vector<PersistenceMechanism> mechanisms;
};

} // namespace KernelScanner

#endif
