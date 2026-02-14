/**
 * Kernel-Level Memory Scanner v12.0
 * Enterprise-Grade Kernel Security Suite
 * Extended Modular Architecture with Analysis Tools
 * 
 * v12.0 Features:
 * - All v11 modules PLUS:
 * - Memory Forensics Timeline Analysis
 * - Code Injection Detection
 * - Privilege Escalation Detection
 * 
 * Author: Olivier Robert-Duboille
 */

#include <iostream>
#include <memory>

#include "include/apt_detector.h"
#include "include/lotl_detector.h"
#include "include/lateral_movement_detector.h"
#include "include/c2_detector.h"
#include "include/threat_intelligence.h"
#include "include/persistence_detector.h"
#include "include/kernel_callbacks.h"
#include "include/process_hollowing.h"
#include "include/fileless_malware.h"
#include "include/edr_evasion.h"
#include "include/driver_analyzer.h"
#include "include/syscall_hooks.h"
#include "include/code_injection.h"
#include "include/privilege_escalation.h"
#include "include/attack_chain_visualizer.h"
#include "include/memory_forensics.h"

void print_banner() {
    std::cout << R"(
    ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║     Kernel Memory Scanner v12.0 - Enterprise Security Suite with Forensics & Detection                                   ║
    ║     APT • LotL • Injections • PrivEsc • Timeline Forensics • Kernel Callbacks • Process Hollowing                     ║
    ║     Author: Olivier Robert-Duboille                                                                                      ║
    ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

int main() {
    print_banner();
    
    // Initialize all detection modules
    std::unique_ptr<KernelScanner::APTDetector> apt_detector(new KernelScanner::APTDetector());
    std::unique_ptr<KernelScanner::LotLDetector> lotl_detector(new KernelScanner::LotLDetector());
    std::unique_ptr<KernelScanner::LateralMovementDetector> lateral_detector(new KernelScanner::LateralMovementDetector());
    std::unique_ptr<KernelScanner::C2Detector> c2_detector(new KernelScanner::C2Detector());
    std::unique_ptr<KernelScanner::ThreatIntelligence> threat_intel(new KernelScanner::ThreatIntelligence());
    std::unique_ptr<KernelScanner::PersistenceDetector> persistence_detector(new KernelScanner::PersistenceDetector());
    std::unique_ptr<KernelScanner::KernelCallbackEnumerator> kernel_callbacks(new KernelScanner::KernelCallbackEnumerator());
    std::unique_ptr<KernelScanner::ProcessHollowingDetector> hollowing_detector(new KernelScanner::ProcessHollowingDetector());
    std::unique_ptr<KernelScanner::FilelessMalwareDetector> fileless_detector(new KernelScanner::FilelessMalwareDetector());
    std::unique_ptr<KernelScanner::EDREvasionDetector> edr_evasion(new KernelScanner::EDREvasionDetector());
    std::unique_ptr<KernelScanner::DriverLoadAnalyzer> driver_analyzer(new KernelScanner::DriverLoadAnalyzer());
    std::unique_ptr<KernelScanner::SyscallHookDetector> syscall_detector(new KernelScanner::SyscallHookDetector());
    std::unique_ptr<KernelScanner::CodeInjectionDetector> injection_detector(new KernelScanner::CodeInjectionDetector());
    std::unique_ptr<KernelScanner::PrivilegeEscalationDetector> priv_esc_detector(new KernelScanner::PrivilegeEscalationDetector());
    std::unique_ptr<KernelScanner::AttackChainVisualizer> attack_chain(new KernelScanner::AttackChainVisualizer());
    std::unique_ptr<KernelScanner::MemoryForensicsTimeline> timeline(new KernelScanner::MemoryForensicsTimeline());
    
    std::cout << "\nSelect Analysis Mode:" << std::endl;
    std::cout << " 1. APT Detection" << std::endl;
    std::cout << " 2. LotL Binary Detection" << std::endl;
    std::cout << " 3. Lateral Movement Analysis" << std::endl;
    std::cout << " 4. C2 Communication Detection" << std::endl;
    std::cout << " 5. Threat Intelligence Lookup" << std::endl;
    std::cout << " 6. Persistence Mechanism Detection" << std::endl;
    std::cout << " 7. Kernel Callback Enumeration" << std::endl;
    std::cout << " 8. Process Hollowing Detection" << std::endl;
    std::cout << " 9. Fileless Malware Detection" << std::endl;
    std::cout << "10. EDR Evasion Technique Detection" << std::endl;
    std::cout << "11. Driver Load Analysis" << std::endl;
    std::cout << "12. Syscall Hook Detection" << std::endl;
    std::cout << "13. Code Injection Detection" << std::endl;
    std::cout << "14. Privilege Escalation Detection" << std::endl;
    std::cout << "15. Memory Forensics Timeline" << std::endl;
    std::cout << "16. Attack Chain Visualization" << std::endl;
    std::cout << "17. Full Security Suite" << std::endl;
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 1: {
            auto apt = apt_detector->detect_apt();
            apt_detector->print_apt_report(apt);
            break;
        }
        case 2: {
            auto alerts = lotl_detector->detect_lotl();
            lotl_detector->print_lotl_report(alerts);
            break;
        }
        case 3:
            lateral_detector->detect_lateral_movement();
            lateral_detector->print_movement_report();
            break;
        case 4:
            c2_detector->detect_c2();
            c2_detector->print_c2_report();
            break;
        case 5: {
            threat_intel->initialize_ioc_database();
            auto results = threat_intel->lookup_ioc("185.141.25.68");
            threat_intel->print_ioc_report(results);
            break;
        }
        case 6:
            persistence_detector->detect_persistence();
            persistence_detector->print_persistence_report();
            break;
        case 7:
            kernel_callbacks->print_callback_report(kernel_callbacks->enumerate_callbacks());
            break;
        case 8: {
            auto result = hollowing_detector->detect_hollowing(1234);
            hollowing_detector->print_hollowing_report(result);
            break;
        }
        case 9: {
            auto analysis = fileless_detector->scan_for_fileless();
            fileless_detector->print_fileless_report(analysis);
            break;
        }
        case 10:
            edr_evasion->scan_for_evasion();
            edr_evasion->print_evasion_report();
            break;
        case 11:
            driver_analyzer->analyze_driver_loads();
            driver_analyzer->print_driver_report();
            break;
        case 12:
            syscall_detector->detect_syscall_hooks();
            syscall_detector->print_hook_report();
            break;
        case 13: {
            auto injections = injection_detector->detect_injections();
            injection_detector->print_injection_report(injections);
            break;
        }
        case 14: {
            auto events = priv_esc_detector->detect_privilege_escalation();
            priv_esc_detector->print_escalation_report(events);
            break;
        }
        case 15:
            timeline->generate_timeline();
            timeline->export_timeline("timeline.json");
            break;
        case 16:
            attack_chain->build_attack_chain();
            attack_chain->visualize_attack_chain();
            break;
        case 17:
            std::cout << "\n=== Full Security Suite ===" << std::endl;
            auto apt = apt_detector->detect_apt();
            apt_detector->print_apt_report(apt);
            auto injections = injection_detector->detect_injections();
            injection_detector->print_injection_report(injections);
            auto events = priv_esc_detector->detect_privilege_escalation();
            priv_esc_detector->print_escalation_report(events);
            timeline->generate_timeline();
            timeline->export_timeline("timeline.json");
            break;
    }
    
    return 0;
}
