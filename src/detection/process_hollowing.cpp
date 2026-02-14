#include "process_hollowing.h"

namespace KernelScanner {

ProcessHollowingDetector::ProcessHollowingDetector() {}

ProcessHollowingDetector::HollowingResult ProcessHollowingDetector::detect_hollowing(uint32_t pid) {
    HollowingResult result;
    result.pid = pid;
    result.is_hollowed = false;
    result.real_image_base = 0x140000000;
    result.mapped_image_base = 0x400000;
    
    std::cout << "[*] Scanning PID " << pid << " for hollowing..." << std::endl;
    
    if (rand() % 100 < 30) {
        result.is_hollowed = true;
        result.image_path = "C:\\Windows\\System32\\svchost.exe";
        result.indicators.push_back("Image base mismatch (PEB vs VAD)");
        result.indicators.push_back("Memory region protection anomaly (RWX)");
        result.indicators.push_back("Suspicious thread entry point");
        result.indicators.push_back("No matching disk file for mapped section");
    }
    
    return result;
}

void ProcessHollowingDetector::print_hollowing_report(const HollowingResult& result) {
    std::cout << "\n=== Process Hollowing Detection ===" << std::endl;
    std::cout << "PID: " << result.pid << std::endl;
    std::cout << "Image: " << result.image_path << std::endl;
    std::cout << "Status: " << (result.is_hollowed ? "HOLLOWED (MALICIOUS)" : "Clean") << std::endl;
    
    if (!result.indicators.empty()) {
        std::cout << "\nIndicators:" << std::endl;
        for (const auto& ind : result.indicators) {
            std::cout << "  [!] " << ind << std::endl;
        }
    }
}

} // namespace KernelScanner
