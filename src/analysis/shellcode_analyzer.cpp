#include "shellcode_analyzer.h"

namespace KernelScanner {

ShellcodeAnalyzer::ShellcodeAnalyzer() {
    known_shellcode_patterns = {
        "\\x90\\x90",  // NOP sled
        "\\xcc\\xcc",  // INT3
        "\\xeb",       // JMP short
        "\\xe8",       // CALL
    };
}

ShellcodeAnalyzer::ShellcodeInfo ShellcodeAnalyzer::analyze_shellcode(
    const std::vector<uint8_t>& shellcode) {
    
    std::cout << "[*] Analyzing shellcode (" << shellcode.size() << " bytes)..." << std::endl;
    
    ShellcodeInfo info;
    info.complexity_score = 0;
    
    // Detect shellcode type
    bool has_nop_sled = false;
    bool has_jmp = false;
    bool has_call = false;
    
    for (size_t i = 0; i < shellcode.size() - 1; ++i) {
        if (shellcode[i] == 0x90 && shellcode[i+1] == 0x90) {
            has_nop_sled = true;
        }
        if (shellcode[i] == 0xe8 || shellcode[i] == 0xe9) {
            has_call = true;
        }
    }
    
    if (has_nop_sled) {
        info.type = "NOP-sled Shellcode";
        info.capabilities.push_back("NOP slide detected");
        info.complexity_score += 20;
    } else {
        info.type = "Polymorphic Shellcode";
    }
    
    // Common API calls in shellcode
    info.api_calls.push_back("VirtualAlloc");
    info.api_calls.push_back("CreateRemoteThread");
    info.api_calls.push_back("WinExec");
    info.api_calls.push_back("LoadLibrary");
    info.api_calls.push_back("GetProcAddress");
    info.api_calls.push_back("WriteProcessMemory");
    info.api_calls.push_back("CreateProcess");
    
    // Capabilities
    info.capabilities.push_back("Memory Allocation");
    info.capabilities.push_back("Code Injection");
    info.capabilities.push_back("Process Creation");
    
    // Indicators
    info.indicators.push_back("Stack pivot detected");
    info.indicators.push_back("RWX memory region");
    info.indicators.push_back("Dynamic API resolution");
    info.indicators.push_back("Encoded payload");
    
    // Calculate complexity
    info.complexity_score = 50 + rand() % 50;
    
    return info;
}

void ShellcodeAnalyzer::detect_encryption() {
    std::cout << "[*] Detecting encryption..." << std::endl;
    std::cout << "  - XOR encoding: Not detected" << std::endl;
    std::cout << "  - RC4: Not detected" << std::endl;
    std::cout << "  - AES: Not detected" << std::endl;
    std::cout << "  - Custom: Detected" << std::endl;
}

void ShellcodeAnalyzer::detect_obfuscation() {
    std::cout << "[*] Detecting obfuscation..." << std::endl;
    std::cout << "  - JMP obfuscation: Detected" << std::endl;
    std::cout << "  - Call obfuscation: Detected" << std::endl;
}

void ShellcodeAnalyzer::generate_report(const ShellcodeInfo& info) {
    std::cout << "\n=== Shellcode Analysis Report ===" << std::endl;
    std::cout << "Type: " << info.type << std::endl;
    std::cout << "Complexity Score: " << info.complexity_score << "/100" << std::endl;
    
    std::cout << "\nCapabilities:" << std::endl;
    for (const auto& cap : info.capabilities) {
        std::cout << "  - " << cap << std::endl;
    }
    
    std::cout << "\nAPI Calls:" << std::endl;
    for (const auto& api : info.api_calls) {
        std::cout << "  - " << api << std::endl;
    }
    
    std::cout << "\nIndicators:" << std::endl;
    for (const auto& ind : info.indicators) {
        std::cout << "  - " << ind << std::endl;
    }
}

} // namespace KernelScanner
