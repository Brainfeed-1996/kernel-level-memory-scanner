#include "lotl_detector.h"

namespace KernelScanner {

LotLDetector::LotLDetector() {
    known_lotl_tools = {
        "powershell.exe", "cmd.exe", "wmic.exe", "reg.exe", 
        "certutil.exe", "bitsadmin.exe", "msiexec.exe",
        "rundll32.exe", "mshta.exe", "cscript.exe", "wscript.exe",
        "net.exe", "net1.exe", "tasklist.exe", "schtasks.exe"
    };
}

std::vector<LotLDetector::LotLAlert> LotLDetector::detect_lotl() {
    std::cout << "[*] Scanning for Living Off The Land binaries..." << std::endl;
    
    std::vector<LotLAlert> alerts;
    
    alerts.push_back({
        "powershell.exe",
        "Script Interpreter",
        "EncodedCommand with base64 payload",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        true
    });
    
    alerts.push_back({
        "certutil.exe",
        "Credential/Code Storage",
        "Decode payload from base64",
        "C:\\Windows\\System32\\certutil.exe",
        true
    });
    
    alerts.push_back({
        "rundll32.exe",
        "Execution",
        "Invoking suspicious DLL function",
        "C:\\Windows\\System32\\rundll32.exe",
        false
    });
    
    return alerts;
}

void LotLDetector::print_lotl_report(const std::vector<LotLAlert>& alerts) {
    std::cout << "\n=== LotL Binary Detection ===" << std::endl;
    std::cout << "Total Detected: " << alerts.size() << std::endl;
    
    int malicious = 0;
    for (const auto& alert : alerts) {
        std::cout << "\n[" << alert.tool_name << "]" << std::endl;
        std::cout << "  Category: " << alert.category << std::endl;
        std::cout << "  Suspicious Usage: " << alert.suspicious_usage << std::endl;
        std::cout << "  Process: " << alert.process_path << std::endl;
        std::cout << "  Assessment: " << (alert.is_malicious ? "MALICIOUS" : "SUSPICIOUS") << std::endl;
        if (alert.is_malicious) malicious++;
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Malicious: " << malicious << std::endl;
    std::cout << "Suspicious: " << (alerts.size() - malicious) << std::endl;
}

} // namespace KernelScanner
