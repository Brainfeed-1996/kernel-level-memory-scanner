/**
 * Kernel-Level Memory Scanner v10.0
 * Enterprise-Grade Kernel Security & APT Detection Suite
 * Modular Architecture
 * 
 * v10.0 Features:
 * - APT (Advanced Persistent Threat) Detection
 * - Living Off The Land (LotL) Detection
 * - Lateral Movement Detection
 * - C2 (Command & Control) Communication Detection
 * - Threat Intelligence Integration
 * - Malware Persistence Mechanism Detection
 * - Attack Chain Visualization
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
#include "include/attack_chain_visualizer.h"

void print_banner() {
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
    ║     Kernel Memory Scanner v10.0 - Enterprise-Grade APT Detection & Threat Hunting Suite (Modular)           ║
    ║     APT Detection • LotL • Lateral Movement • C2 Detection • Threat Intel • Attack Chain Visualization   ║
    ║     Author: Olivier Robert-Duboille                                                                               ║
    ╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
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
    std::unique_ptr<KernelScanner::AttackChainVisualizer> attack_chain(new KernelScanner::AttackChainVisualizer());
    
    std::cout << "\nSelect Analysis Mode:" << std::endl;
    std::cout << "1. APT Detection" << std::endl;
    std::cout << "2. LotL Binary Detection" << std::endl;
    std::cout << "3. Lateral Movement Analysis" << std::endl;
    std::cout << "4. C2 Communication Detection" << std::endl;
    std::cout << "5. Threat Intelligence Lookup" << std::endl;
    std::cout << "6. Persistence Mechanism Detection" << std::endl;
    std::cout << "7. Attack Chain Visualization" << std::endl;
    std::cout << "8. Full Threat Hunting Suite" << std::endl;
    
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
            attack_chain->build_attack_chain();
            attack_chain->visualize_attack_chain();
            break;
        case 8:
            std::cout << "\n=== Full Threat Hunting Suite ===" << std::endl;
            
            auto apt = apt_detector->detect_apt();
            apt_detector->print_apt_report(apt);
            
            auto alerts = lotl_detector->detect_lotl();
            lotl_detector->print_lotl_report(alerts);
            
            lateral_detector->detect_lateral_movement();
            lateral_detector->print_movement_report();
            
            c2_detector->detect_c2();
            c2_detector->print_c2_report();
            
            persistence_detector->detect_persistence();
            persistence_detector->print_persistence_report();
            
            threat_intel->initialize_ioc_database();
            auto results = threat_intel->lookup_ioc("185.141.25.68");
            threat_intel->print_ioc_report(results);
            
            attack_chain->build_attack_chain();
            attack_chain->visualize_attack_chain();
            break;
    }
    
    return 0;
}
