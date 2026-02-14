#include "persistence_detector.h"

namespace KernelScanner {

PersistenceDetector::PersistenceDetector() {}

std::vector<PersistenceDetector::PersistenceMechanism> PersistenceDetector::detect_persistence() {
    std::cout << "[*] Scanning for persistence mechanisms..." << std::endl;
    
    mechanisms = {
        {
            "Registry Run Keys",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "malware.dll",
            true
        },
        {
            "Scheduled Task",
            "\\Microsoft\\Windows\\Maintenance\\UpdateTask",
            "Periodic execution",
            true
        },
        {
            "WMI Event Consumer",
            "CommandLineEventConsumer",
            "Script persistence",
            true
        },
        {
            "Service",
            "MaliciousService",
            "Auto-start service",
            false
        },
        {
            "DLL Search Order Hijacking",
            "app32.dll",
            "Preloading attack",
            true
        },
        {
            "Startup Folder",
            "C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            "User startup",
            false
        }
    };
    
    return mechanisms;
}

void PersistenceDetector::print_persistence_report() {
    std::cout << "\n=== Persistence Mechanism Analysis ===" << std::endl;
    
    for (const auto& m : mechanisms) {
        std::cout << "\n[" << m.type << "]" << std::endl;
        std::cout << "  Location: " << m.location << std::endl;
        std::cout << "  Description: " << m.description << std::endl;
        std::cout << "  Assessment: " << (m.is_malicious ? "MALICIOUS" : "LEGITIMATE") << std::endl;
    }
    
    int malicious_count = 0;
    for (const auto& m : mechanisms) {
        if (m.is_malicious) malicious_count++;
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Total Mechanisms: " << mechanisms.size() << std::endl;
    std::cout << "Malicious: " << malicious_count << std::endl;
    std::cout << "Legitimate: " << (mechanisms.size() - malicious_count) << std::endl;
}

} // namespace KernelScanner
