#ifndef SHELLCODE_ANALYZER_H
#define SHELLCODE_ANALYZER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class ShellcodeAnalyzer {
public:
    struct ShellcodeInfo {
        std::string type;
        std::vector<std::string> capabilities;
        std::vector<std::string> api_calls;
        std::vector<std::string> indicators;
        int complexity_score;
    };
    
    ShellcodeAnalyzer();
    ShellcodeInfo analyze_shellcode(const std::vector<uint8_t>& shellcode);
    void detect_encryption();
    void detect_obfuscation();
    void generate_report(const ShellcodeInfo& info);

private:
    std::vector<std::string> known_shellcode_patterns;
};

} // namespace KernelScanner

#endif
