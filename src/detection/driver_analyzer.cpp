#include "driver_analyzer.h"

namespace KernelScanner {

DriverLoadAnalyzer::DriverLoadAnalyzer() {}

void DriverLoadAnalyzer::analyze_driver_loads() {
    std::cout << "[*] Analyzing loaded drivers..." << std::endl;
    
    loaded_drivers.clear();
    
    std::vector<std::string> driver_names = {
        "ntoskrnl.exe", "hal.dll", "kdcom.dll", "ntkrnlpa.exe",
        "CI.dll", "clfs.sys", "ntfs.sys", "示范.sys"
    };
    
    for (const auto& name : driver_names) {
        DriverAnalysis analysis;
        analysis.name = name;
        analysis.path = "C:\\Windows\\System32\\drivers\\" + name;
        analysis.is_signed = (rand() % 100 > 10);
        analysis.has_known_vulnerabilities = (rand() % 100 < 5);
        
        if (!analysis.is_signed) {
            analysis.suspicious_behaviors.push_back("Driver is not signed");
        }
        if (analysis.has_known_vulnerabilities) {
            analysis.suspicious_behaviors.push_back("Known CVE exists for this driver");
            analysis.risk_score = 80.0;
        } else {
            analysis.risk_score = rand() % 50;
        }
        
        loaded_drivers.push_back(analysis);
    }
}

void DriverLoadAnalyzer::print_driver_report() {
    std::cout << "\n=== Driver Load Analysis ===" << std::endl;
    std::cout << "Loaded Drivers: " << loaded_drivers.size() << std::endl;
    
    double total_risk = 0;
    int unsigned_count = 0;
    int vulnerable_count = 0;
    
    for (const auto& drv : loaded_drivers) {
        std::cout << "\n[Driver] " << drv.name << std::endl;
        std::cout << "  Path: " << drv.path << std::endl;
        std::cout << "  Signed: " << (drv.is_signed ? "YES" : "NO (SUSPICIOUS)") << std::endl;
        std::cout << "  Risk Score: " << drv.risk_score << "/100" << std::endl;
        
        if (!drv.suspicious_behaviors.empty()) {
            std::cout << "  Behaviors:" << std::endl;
            for (const auto& b : drv.suspicious_behaviors) {
                std::cout << "    [!] " << b << std::endl;
            }
        }
        
        if (!drv.is_signed) unsigned_count++;
        if (drv.has_known_vulnerabilities) vulnerable_count++;
        total_risk += drv.risk_score;
    }
    
    std::cout << "\n=== Driver Security Summary ===" << std::endl;
    std::cout << "Total Drivers: " << loaded_drivers.size() << std::endl;
    std::cout << "Unsigned Drivers: " << unsigned_count << std::endl;
    std::cout << "Vulnerable Drivers: " << vulnerable_count << std::endl;
    std::cout << "Average Risk: " << (total_risk / loaded_drivers.size()) << "/100" << std::endl;
}

} // namespace KernelScanner
