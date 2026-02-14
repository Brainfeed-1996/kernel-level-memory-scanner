#ifndef CODE_INJECTION_H
#define CODE_INJECTION_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class CodeInjectionDetector {
public:
    struct InjectionInfo {
        uint32_t target_pid;
        std::string target_process;
        std::string injection_type;
        uintptr_t address;
        size_t size;
        std::string method;
        bool confirmed;
    };
    
    CodeInjectionDetector();
    std::vector<InjectionInfo> detect_injections();
    void analyze_process(uint32_t pid);
    void print_injection_report(const std::vector<InjectionInfo>& injections);

private:
    std::vector<InjectionInfo> detected_injections;
};

} // namespace KernelScanner

#endif
