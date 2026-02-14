#include "attack_chain_visualizer.h"

namespace KernelScanner {

AttackChainVisualizer::AttackChainVisualizer() {}

void AttackChainVisualizer::build_attack_chain() {
    attack_chain = {
        {1, "Initial Access", "T1190 - Exploit Public-Facing Application",
         "2024-12-01T14:00:00Z", "Phishing email with malicious attachment"},
        {2, "Execution", "T1059 - Command and Scripting Interpreter",
         "2024-12-01T14:05:30Z", "PowerShell execution of encoded command"},
        {3, "Persistence", "T1547.001 - Boot or Logon Autostart Execution: Registry",
         "2024-12-01T14:10:15Z", "Registry run key modification"},
        {4, "Privilege Escalation", "T1068 - Exploitation for Privilege Escalation",
         "2024-12-01T14:15:45Z", "Kernel exploit for SYSTEM privileges"},
        {5, "Defense Evasion", "T1027 - Obfuscated Files",
         "2024-12-01T14:20:00Z", "Base64 encoded payloads"},
        {6, "Credential Access", "T1003 - OS Credential Dumping",
         "2024-12-01T14:30:00Z", "LSASS memory dump"},
        {7, "Discovery", "T1087 - Account Discovery",
         "2024-12-01T14:32:00Z", "Domain admin enumeration"},
        {8, "Lateral Movement", "T1021 - Remote Services",
         "2024-12-01T14:35:00Z", "WinRM to DC-01"},
        {9, "Collection", "T1005 - Data from Local System",
         "2024-12-01T14:40:00Z", "Sensitive document collection"},
        {10, "Exfiltration", "T1041 - Exfiltration Over C2 Channel",
         "2024-12-01T15:00:00Z", "Data sent to 185.141.25.68:443"}
    };
}

void AttackChainVisualizer::visualize_attack_chain() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    ATTACK CHAIN VISUALIZATION (MITRE ATT&CK)                 ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════╝\n";
    
    for (const auto& stage : attack_chain) {
        std::cout << "\n┌─ Stage " << stage.stage_id << ": " << stage.name << std::endl;
        std::cout << "│  Technique: " << stage.technique << std::endl;
        std::cout << "│  Time: " << stage.timestamp << std::endl;
        std::cout << "│  Details: " << stage.details << std::endl;
        std::cout << "│" << std::endl;
        std::cout << "└" << (stage.stage_id < 10 ? "──>" : "──[END]") << " ";
    }
    
    std::cout << "\n\n=== Attack Chain Summary ===" << std::endl;
    std::cout << "Total Stages: " << attack_chain.size() << std::endl;
    std::cout << "Duration: ~1 hour" << std::endl;
    std::cout << "Impact: CRITICAL - Domain Compromise" << std::endl;
}

} // namespace KernelScanner
