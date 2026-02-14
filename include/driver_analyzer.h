#ifndef DRIVER_ANALYZER_H
#define DRIVER_ANALYZER_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class DriverLoadAnalyzer {
public:
    struct DriverAnalysis {
        std::string name;
        std::string path;
        bool is_signed;
        bool has_known_vulnerabilities;
        std::vector<std::string> suspicious_behaviors;
        double risk_score;
    };
    
    DriverLoadAnalyzer();
    void analyze_driver_loads();
    void print_driver_report();

private:
    std::vector<DriverAnalysis> loaded_drivers;
};

} // namespace KernelScanner

#endif
