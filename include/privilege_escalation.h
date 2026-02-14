#ifndef PRIVILEGE_ESCALATION_H
#define PRIVILEGE_ESCALATION_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class PrivilegeEscalationDetector {
public:
    struct EscalationEvent {
        uint32_t pid;
        std::string process_name;
        std::string technique;
        std::string target_privilege;
        uintptr_t token_address;
        bool successful;
    };
    
    PrivilegeEscalationDetector();
    std::vector<EscalationEvent> detect_privilege_escalation();
    void analyze_token(uint32_t pid);
    void print_escalation_report(const std::vector<EscalationEvent>& events);

private:
    std::vector<EscalationEvent> events;
};

} // namespace KernelScanner

#endif
