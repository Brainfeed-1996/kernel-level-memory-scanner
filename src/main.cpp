/**
 * Kernel-Level Memory Scanner v15.0
 * Enterprise-Grade Kernel Security Suite
 * Complete Modular Architecture
 * 
 * v15.0 Features:
 * - All v14 modules PLUS:
 * - Volatility Framework Plugins
 * - Memory Carving
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
#include "include/rootkit_detector.h"
#include "include/attack_chain_visualizer.h"
#include "include/memory_forensics.h"
#include "include/malware_sandbox.h"
#include "include/yara_compiler.h"
#include "include/network_analyzer.h"
#include "include/disassembler.h"
#include "include/shellcode_analyzer.h"
#include "include/volatility_plugins.h"
#include "include/memory_carving.h"

void print_banner() {
    std::cout << R"(
    ╔════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║     Kernel Memory Scanner v15.0 - Complete Enterprise Security Suite (Volatility + Carving)                                                                                                                     ║
    ║     APT • LotL • Injections • PrivEsc • Rootkits • Disassembler • Shellcode • Sandbox • YARA • Network • Volatility Plugins • Memory Carving                                                       ║
    ║     Author: Olivier Robert-Duboille                                                                                                                                                                        ║
    ╚════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
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
    std::unique_ptr<KernelScanner::RootkitDetector> rootkit_detector(new KernelScanner::RootkitDetector());
    std::unique_ptr<KernelScanner::AttackChainVisualizer> attack_chain(new KernelScanner::AttackChainVisualizer());
    std::unique_ptr<KernelScanner::MemoryForensicsTimeline> timeline(new KernelScanner::MemoryForensicsTimeline());
    std::unique_ptr<KernelScanner::MalwareSandbox> sandbox(new KernelScanner::MalwareSandbox());
    std::unique_ptr<KernelScanner::YARACompiler> yara_compiler(new KernelScanner::YARACompiler());
    std::unique_ptr<KernelScanner::NetworkTrafficAnalyzer> network_analyzer(new KernelScanner::NetworkTrafficAnalyzer());
    std::unique_ptr<KernelScanner::Disassembler> disassembler(new KernelScanner::Disassembler());
    std::unique_ptr<KernelScanner::ShellcodeAnalyzer> shellcode_analyzer(new KernelScanner::ShellcodeAnalyzer());
    std::unique_ptr<KernelScanner::VolatilityPlugins> volatility(new KernelScanner::VolatilityPlugins());
    std::unique_ptr<KernelScanner::MemoryCarving> carving(new KernelScanner::MemoryCarving());
    
    std::cout << "\nSelect Analysis Mode:" << std::endl;
    std::cout << " 1. APT Detection" << std::endl;
    std::cout << " 2. Rootkit Detection" << std::endl;
    std::cout << " 3. Malware Sandbox" << std::endl;
    std::cout << " 4. YARA Compiler" << std::endl;
    std::cout << " 5. Network Analysis" << std::endl;
    std::cout << " 6. Disassembler" << std::endl;
    std::cout << " 7. Shellcode Analyzer" << std::endl;
    std::cout << " 8. Volatility Plugins (pslist, malfind, etc.)" << std::endl;
    std::cout << " 9. Memory Carving" << std::endl;
    std::cout << "10. Full Security Suite" << std::endl;
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 1: {
            auto apt = apt_detector->detect_apt();
            apt_detector->print_apt_report(apt);
            break;
        }
        case 2: {
            auto rootkits = rootkit_detector->scan_for_rootkits();
            rootkit_detector->generate_report(rootkits);
            break;
        }
        case 3: {
            auto result = sandbox->analyze_malware("sample.exe");
            sandbox->generate_report(result);
            break;
        }
        case 4: {
            auto rule = yara_compiler->create_rule("malware_rule", "rule malware { condition: true }");
            yara_compiler->compile_rule(rule);
            yara_compiler->print_compilation_result(rule);
            break;
        }
        case 5:
            network_analyzer->capture_packets(100);
            network_analyzer->analyze_traffic();
            network_analyzer->generate_report();
            break;
        case 6: {
            std::vector<uint8_t> code = {0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xE8};
            auto instructions = disassembler->disassemble_code(code, 0x10000);
            disassembler->print_disassembly(instructions);
            break;
        }
        case 7: {
            std::vector<uint8_t> shellcode = {0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00};
            auto info = shellcode_analyzer->analyze_shellcode(shellcode);
            shellcode_analyzer->generate_report(info);
            break;
        }
        case 8: {
            auto result = volatility->run_pslist();
            volatility->print_results(result);
            result = volatility->run_malfind();
            volatility->print_results(result);
            result = volatility->run_callbacks();
            volatility->print_results(result);
            break;
        }
        case 9: {
            auto objects = carving->carve_pe_files();
            carving->print_carving_results(objects);
            objects = carving->carve_urls();
            carving->print_carving_results(objects);
            break;
        }
        case 10:
            std::cout << "\n=== Full Security Suite ===" << std::endl;
            auto rootkits = rootkit_detector->scan_for_rootkits();
            rootkit_detector->generate_report(rootkits);
            auto result = volatility->run_pslist();
            volatility->print_results(result);
            auto objects = carving->carve_pe_files();
            carving->print_carving_results(objects);
            break;
    }
    
    return 0;
}
