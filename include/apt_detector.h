#ifndef APT_DETECTOR_H
#define APT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <iomanip>

namespace KernelScanner {

class APTDetector {
public:
    struct APTIndicators {
        std::string apt_group;
        std::vector<std::string> iocs;
        std::vector<std::string> ttps;
        double confidence_score;
        std::string first_seen;
        std::string last_activity;
        std::map<std::string, int> stage_counts;
    };
    
    APTDetector();
    APTIndicators detect_apt();
    void print_apt_report(const APTIndicators& ind);

private:
    std::map<std::string, APTIndicators> known_apt_profiles;
};

} // namespace KernelScanner

#endif
