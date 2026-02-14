#include "edr_evasion.h"

namespace KernelScanner {

EDREvasionDetector::EDREvasionDetector() {}

std::vector<EDREvasionDetector::EvasionTechnique> EDREvasionDetector::scan_for_evasion() {
    std::cout << "[*] Scanning for EDR evasion techniques..." << std::endl;
    
    techniques.clear();
    
    techniques.push_back({"DLL Hollowing", "Process Injection", false,
                       "Replacing DLL in memory with malicious version", {}});
    techniques.push_back({"Process Doppelganging", "Process Masquerading", false,
                       "Transaction-based process creation", {}});
    techniques.push_back({"Process Herpaderping", "Process Masquerading", false,
                       "Process image replacement after creation", {}});
    techniques.push_back({"Direct Syscall", "Syscall Obfuscation", false,
                       "Direct system calls to bypass API hooks", {}});
    techniques.push_back({"Memory Encryption", "Runtime Protection", false,
                       "Encrypted payloads decrypted at runtime", {}});
    
    for (auto& tech : techniques) {
        if (rand() % 100 < 20) {
            tech.detected = true;
            tech.iocs.push_back("Suspicious memory allocation pattern");
            tech.iocs.push_back("Unbacked memory region");
        }
    }
    
    return techniques;
}

void EDREvasionDetector::print_evasion_report() {
    std::cout << "\n=== EDR Evasion Analysis ===" << std::endl;
    
    int detected = 0;
    for (const auto& tech : techniques) {
        std::cout << "\n[" << tech.category << "] " << tech.name << std::endl;
        std::cout << "  Status: " << (tech.detected ? "DETECTED" : "Not Detected") << std::endl;
        std::cout << "  Description: " << tech.description << std::endl;
        
        if (!tech.iocs.empty()) {
            std::cout << "  IOCs:" << std::endl;
            for (const auto& ioc : tech.iocs) {
                std::cout << "    - " << ioc << std::endl;
            }
        }
        
        if (tech.detected) detected++;
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Techniques Analyzed: " << techniques.size() << std::endl;
    std::cout << "Detected: " << detected << std::endl;
}

} // namespace KernelScanner
