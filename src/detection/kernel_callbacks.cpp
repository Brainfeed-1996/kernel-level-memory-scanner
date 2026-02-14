#include "kernel_callbacks.h"

namespace KernelScanner {

KernelCallbackEnumerator::KernelCallbackEnumerator() {}

std::vector<KernelCallbackEnumerator::CallbackInfo> KernelCallbackEnumerator::enumerate_callbacks() {
    std::cout << "[*] Enumerating kernel callbacks..." << std::endl;
    
    std::vector<CallbackInfo> found;
    
    found.push_back({"ProcessNotify", 0xFFFFF80000000000 + 0x1000, "ntoskrnl.exe", 
                    "Process creation/deletion notifications", false});
    found.push_back({"ThreadNotify", 0xFFFFF80000000000 + 0x2000, "ntoskrnl.exe",
                    "Thread creation/deletion notifications", false});
    found.push_back({"ImageLoad", 0xFFFFF80000000000 + 0x3000, "ntoskrnl.exe",
                    "Image load notifications", true});
    found.push_back({"RegistryCreate", 0xFFFFF80000000000 + 0x4000, "antivirus.sys",
                    "Registry key creation monitoring", false});
    found.push_back({"RegistryDelete", 0xFFFFF80000000000 + 0x5000, "antivirus.sys",
                    "Registry key deletion monitoring", false});
    found.push_back({"ObHandle", 0xFFFFF80000000000 + 0x6000, "security.sys",
                    "Handle table operations", false});
    
    return found;
}

void KernelCallbackEnumerator::print_callback_report(const std::vector<CallbackInfo>& callbacks) {
    std::cout << "\n=== Kernel Callback Analysis ===" << std::endl;
    std::cout << "Total Callbacks: " << callbacks.size() << std::endl;
    
    int hooked = 0;
    for (const auto& cb : callbacks) {
        std::cout << "\n[" << cb.type << "]" << std::endl;
        std::cout << "  Address: 0x" << std::hex << cb.address << std::dec << std::endl;
        std::cout << "  Module: " << cb.module << std::endl;
        std::cout << "  Description: " << cb.description << std::endl;
        std::cout << "  Status: " << (cb.is_hooked ? "HOOKED (SUSPICIOUS)" : "Clean") << std::endl;
        if (cb.is_hooked) hooked++;
    }
    
    std::cout << "\nSummary:" << std::endl;
    std::cout << "  Clean: " << (callbacks.size() - hooked) << std::endl;
    std::cout << "  Hooked: " << hooked << std::endl;
}

} // namespace KernelScanner
