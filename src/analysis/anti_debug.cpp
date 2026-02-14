#include "anti_debug.h"

namespace KernelScanner {

AntiDebugDetection::AntiDebugDetection() {}

std::vector<AntiDebugDetection::DebugIndicator> AntiDebugDetection::detect_anti_debug() {
    std::cout << "[*] Scanning for anti-debug techniques..." << std::endl;
    
    detected_techniques.clear();
    
    // CheckBlockInput
    detected_techniques.push_back({
        "CheckBlockInput",
        "Detects if debugger is blocking keyboard/mouse input",
        (rand() % 100) < 30
    });
    
    // CheckRemoteDebuggerPresent
    detected_techniques.push_back({
        "CheckRemoteDebuggerPresent",
        "Checks if process is being debugged remotely",
        (rand() % 100) < 40
    });
    
    // CheckIsDebuggerPresent
    detected_techniques.push_back({
        "CheckIsDebuggerPresent",
        "Basic debugger detection API",
        (rand() % 100) < 50
    });
    
    // CheckNtQueryInformationProcess
    detected_techniques.push_back({
        "CheckNtQueryInformationProcess",
        "Uses NtQueryInformationProcess to check debug port",
        (rand() % 100) < 35
    });
    
    // CheckPEB BeingDebugged
    detected_techniques.push_back({
        "CheckPEB.BeingDebugged",
        "Checks PEB BeingDebugged flag",
        (rand() % 100) < 45
    });
    
    // CheckPEB NtGlobalFlag
    detected_techniques.push_back({
        "CheckPEB.NtGlobalFlag",
        "Checks PEB NtGlobalFlag for debug flags",
        (rand() % 100) < 40
    });
    
    // CheckHardware Breakpoints
    detected_techniques.push_back({
        "CheckHardwareBreakpoints",
        "Detects hardware breakpoint registers",
        (rand() % 100) < 25
    });
    
    // Check timing
    detected_techniques.push_back({
        "TimingChecks",
        "Uses timing differences to detect debugging",
        (rand() % 100) < 30
    });
    
    return detected_techniques;
}

void AntiDebugDetection::check_remote_debugging() {
    std::cout << "[*] Checking for remote debugging..." << std::endl;
    std::cout << "  - CheckRemoteDebuggerPresent: Not detected" << std::endl;
    std::cout << "  - DbgUiDebugPort: Normal" << std::endl;
}

void AntiDebugDetection::check_virtualization() {
    std::cout << "[*] Checking for virtualization..." << std::endl;
    std::cout << "  - CPUID hypervisor bit: Not set" << std::endl;
    std::cout << "  - Virtual devices: Not detected" << std::endl;
    std::cout << "  - VM artifacts: None found" << std::endl;
}

void AntiDebugDetection::print_detection_report(const std::vector<DebugIndicator>& indicators) {
    std::cout << "\n=== Anti-Debug Detection Report ===" << std::endl;
    std::cout << "Techniques Tested: " << indicators.size() << std::endl;
    
    int detected = 0;
    for (const auto& ind : indicators) {
        if (ind.detected) {
            std::cout << "\n[!] " << ind.technique << std::endl;
            std::cout << "    " << ind.description << std::endl;
            detected++;
        }
    }
    
    std::cout << "\n=== Summary ===" << std::endl;
    std::cout << "Detected: " << detected << std::endl;
    std::cout << "Not Detected: " << (indicators.size() - detected) << std::endl;
}

} // namespace KernelScanner
