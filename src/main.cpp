/**
 * Kernel-Level Memory Scanner v18.0
 * Enterprise-Grade Kernel Security Suite with Anti-Debug
 * 
 * v18.0 Features:
 * - All v17 modules PLUS:
 * - Anti-Debug Detection
 * 
 * Author: Olivier Robert-Duboille
 */

#include <iostream>
#include <memory>

#include "include/apt_detector.h"
#include "include/rootkit_detector.h"
#include "include/malware_sandbox.h"
#include "include/yara_compiler.h"
#include "include/network_analyzer.h"
#include "include/disassembler.h"
#include "include/shellcode_analyzer.h"
#include "include/volatility_plugins.h"
#include "include/memory_carving.h"
#include "include/pe_forensics.h"
#include "include/code_cave_detector.h"
#include "include/neural_network.h"
#include "include/anti_debug.h"

void print_banner() {
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║     Kernel Memory Scanner v18.0 - Anti-Debug & Enterprise Security Suite                ║
    ║     APT • Rootkits • Disassembler • Shellcode • Sandbox • YARA • Network • AI • Anti-Debug ║
    ║     Author: Olivier Robert-Duboille                                                  ║
    ╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

int main() {
    print_banner();
    
    std::unique_ptr<KernelScanner::APTDetector> apt_detector(new KernelScanner::APTDetector());
    std::unique_ptr<KernelScanner::RootkitDetector> rootkit_detector(new KernelScanner::RootkitDetector());
    std::unique_ptr<KernelScanner::MalwareSandbox> sandbox(new KernelScanner::MalwareSandbox());
    std::unique_ptr<KernelScanner::YARACompiler> yara_compiler(new KernelScanner::YARACompiler());
    std::unique_ptr<KernelScanner::NetworkTrafficAnalyzer> network_analyzer(new KernelScanner::NetworkTrafficAnalyzer());
    std::unique_ptr<KernelScanner::Disassembler> disassembler(new KernelScanner::Disassembler());
    std::unique_ptr<KernelScanner::ShellcodeAnalyzer> shellcode_analyzer(new KernelScanner::ShellcodeAnalyzer());
    std::unique_ptr<KernelScanner::VolatilityPlugins> volatility(new KernelScanner::VolatilityPlugins());
    std::unique_ptr<KernelScanner::MemoryCarving> carving(new KernelScanner::MemoryCarving());
    std::unique_ptr<KernelScanner::PEForensics> pe_forensics(new KernelScanner::PEForensics());
    std::unique_ptr<KernelScanner::CodeCaveDetector> code_cave(new KernelScanner::CodeCaveDetector());
    std::unique_ptr<KernelScanner::NeuralNetworkAnomalyDetection> neural_net(new KernelScanner::NeuralNetworkAnomalyDetection());
    std::unique_ptr<KernelScanner::AntiDebugDetection> anti_debug(new KernelScanner::AntiDebugDetection());
    
    std::cout << "\nSelect Analysis Mode:" << std::endl;
    std::cout << " 1. APT Detection" << std::endl;
    std::cout << " 2. Rootkit Detection" << std::endl;
    std::cout << " 3. Malware Sandbox" << std::endl;
    std::cout << " 4. YARA Compiler" << std::endl;
    std::cout << " 5. Network Analysis" << std::endl;
    std::cout << " 6. Disassembler" << std::endl;
    std::cout << " 7. Shellcode Analyzer" << std::endl;
    std::cout << " 8. Volatility Plugins" << std::endl;
    std::cout << " 9. Memory Carving" << std::endl;
    std::cout << "10. PE Forensics" << std::endl;
    std::cout << "11. Code Cave Detection" << std::endl;
    std::cout << "12. Neural Network Anomaly Detection (AI)" << std::endl;
    std::cout << "13. Anti-Debug Detection" << std::endl;
    std::cout << "14. Full Security Suite" << std::endl;
    
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
            std::vector<uint8_t> code = {0x55, 0x48, 0x89, 0xE5};
            auto instructions = disassembler->disassemble_code(code, 0x10000);
            disassembler->print_disassembly(instructions);
            break;
        }
        case 7: {
            std::vector<uint8_t> shellcode = {0x90, 0x90, 0xE8};
            auto info = shellcode_analyzer->analyze_shellcode(shellcode);
            shellcode_analyzer->generate_report(info);
            break;
        }
        case 8: {
            auto result = volatility->run_pslist();
            volatility->print_results(result);
            break;
        }
        case 9: {
            auto objects = carving->carve_pe_files();
            carving->print_carving_results(objects);
            break;
        }
        case 10: {
            auto header = pe_forensics->parse_pe_header("malware.exe");
            pe_forensics->detect_packing();
            pe_forensics->analyze_imports();
            pe_forensics->generate_report(header);
            break;
        }
        case 11: {
            auto caves = code_cave->detect_code_caves();
            code_cave->print_caves_report(caves);
            break;
        }
        case 12: {
            neural_net->print_network_architecture();
            std::vector<double> features(64, 0.5);
            auto result = neural_net->predict_anomaly(features);
            std::cout << "\nAnomaly: " << result.classification << std::endl;
            break;
        }
        case 13: {
            auto indicators = anti_debug->detect_anti_debug();
            anti_debug->print_detection_report(indicators);
            anti_debug->check_remote_debugging();
            anti_debug->check_virtualization();
            break;
        }
        case 14:
            std::cout << "\n=== Full Security Suite ===" << std::endl;
            auto indicators = anti_debug->detect_anti_debug();
            anti_debug->print_detection_report(indicators);
            break;
    }
    
    return 0;
}
