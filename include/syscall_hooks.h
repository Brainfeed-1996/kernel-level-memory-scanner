#ifndef SYSCALL_HOOKS_H
#define SYSCALL_HOOKS_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace KernelScanner {

class SyscallHookDetector {
public:
    struct HookInfo {
        std::string syscall_name;
        uint32_t syscall_number;
        uintptr_t original_address;
        uintptr_t hooked_address;
        std::string hook_type;
        std::string hooking_module;
    };
    
    SyscallHookDetector();
    std::vector<HookInfo> detect_syscall_hooks();
    void print_hook_report();

private:
    std::vector<HookInfo> hooks;
};

} // namespace KernelScanner

#endif
