#ifndef KERNEL_CALLBACKS_H
#define KERNEL_CALLBACKS_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class KernelCallbackEnumerator {
public:
    struct CallbackInfo {
        std::string type;
        uintptr_t address;
        std::string module;
        std::string description;
        bool is_hooked;
    };
    
    KernelCallbackEnumerator();
    std::vector<CallbackInfo> enumerate_callbacks();
    void print_callback_report(const std::vector<CallbackInfo>& callbacks);

private:
    std::vector<CallbackInfo> callbacks;
};

} // namespace KernelScanner

#endif
