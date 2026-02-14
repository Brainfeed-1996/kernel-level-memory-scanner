#ifndef KERNEL_OBJECT_HOOK_DETECTOR_H
#define KERNEL_OBJECT_HOOK_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Detection {

struct KernelHook {
    std::string hook_type;
    std::string hooked_function;
    std::string module_name;
    uint64_t original_address;
    uint64_t hooked_address;
    std::string hook_destination;
    bool is_inline_hook;
    bool is_iat_hook;
    bool is_eat_hook;
    bool confirmed;
    double confidence_score;
};

struct SSDTEntry {
    uint32_t index;
    std::string function_name;
    uint64_t current_address;
    uint64_t original_address;
    std::string module_name;
    bool is_hooked;
};

struct IRPHandler {
    std::string device_name;
    uint8_t major_function;
    std::string function_name;
    uint64_t current_handler;
    uint64_t original_handler;
    bool is_hooked;
};

class KernelObjectHookDetector {
public:
    KernelObjectHookDetector();
    ~KernelObjectHookDetector();
    
    bool initialize();
    std::vector<KernelHook> detect_kernel_hooks();
    std::vector<SSDTEntry> analyze_ssdt();
    std::vector<IRPHandler> analyze_irp_handlers();
    bool detect_inline_hooks();
    bool detect_iat_hooks();
    bool detect_system_call_hooks();
    bool detect_callback_hooks();
    bool detect_filter_manager_hooks();
    void generate_hook_report();
    
private:
    bool initialized_;
    std::vector<KernelHook> detected_hooks_;
    
    bool compare_function_pointers(uint64_t addr1, uint64_t addr2);
    bool detect_code_modifications(uint64_t address);
    bool check_hook_prologue(uint64_t address);
    std::string resolve_symbol(uint64_t address);
};

} // namespace Detection

#endif // KERNEL_OBJECT_HOOK_DETECTOR_H
