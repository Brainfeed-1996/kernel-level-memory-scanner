#include "threat_intelligence.h"

namespace KernelScanner {

ThreatIntelligence::ThreatIntelligence() {}

void ThreatIntelligence::initialize_ioc_database() {
    ioc_database = {
        {
            "IP", "185.141.25.68", "APT29", "Nobelium", "High", "2024-12-01"
        },
        {
            "Hash", "a1b2c3d4e5f6...", "APT41", "Winnti", "Critical", "2024-11-15"
        },
        {
            "Domain", "evil.example.com", "Lazarus", "Destover", "High", "2024-10-20"
        },
        {
            "IP", "192.99.178.55", "Unknown", "Cobalt Strike", "Critical", "2024-12-01"
        }
    };
}

std::vector<ThreatIntelligence::IOCReport> ThreatIntelligence::lookup_ioc(const std::string& ioc_value) {
    std::cout << "[*] Looking up IOC: " << ioc_value << std::endl;
    
    std::vector<IOCReport> results;
    
    for (const auto& ioc : ioc_database) {
        if (ioc_value.find(ioc.ioc_value.substr(0, 8)) != std::string::npos ||
            ioc.ioc_value.find(ioc_value.substr(0, 8)) != std::string::npos) {
            results.push_back(ioc);
        }
    }
    
    return results;
}

void ThreatIntelligence::print_ioc_report(const std::vector<IOCReport>& reports) {
    std::cout << "\n=== Threat Intelligence Report ===" << std::endl;
    
    if (reports.empty()) {
        std::cout << "No matches found in threat intelligence database." << std::endl;
        return;
    }
    
    for (const auto& r : reports) {
        std::cout << "\n[IOC Match]" << std::endl;
        std::cout << "  Type: " << r.ioc_type << std::endl;
        std::cout << "  Value: " << r.ioc_value << "..." << std::endl;
        std::cout << "  Threat Actor: " << r.threat_actor << std::endl;
        std::cout << "  Malware Family: " << r.malware_family << std::endl;
        std::cout << "  Confidence: " << r.confidence << std::endl;
        std::cout << "  Last Seen: " << r.last_seen << std::endl;
    }
}

} // namespace KernelScanner
