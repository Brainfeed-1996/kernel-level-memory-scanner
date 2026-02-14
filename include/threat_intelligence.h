#ifndef THREAT_INTELLIGENCE_H
#define THREAT_INTELLIGENCE_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class ThreatIntelligence {
public:
    struct IOCReport {
        std::string ioc_type;
        std::string ioc_value;
        std::string threat_actor;
        std::string malware_family;
        std::string confidence;
        std::string last_seen;
    };
    
    ThreatIntelligence();
    void initialize_ioc_database();
    std::vector<IOCReport> lookup_ioc(const std::string& ioc_value);
    void print_ioc_report(const std::vector<IOCReport>& reports);

private:
    std::vector<IOCReport> ioc_database;
};

} // namespace KernelScanner

#endif
