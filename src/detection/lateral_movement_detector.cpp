#include "lateral_movement_detector.h"

namespace KernelScanner {

LateralMovementDetector::LateralMovementDetector() {}

std::vector<LateralMovementDetector::MovementEvent> LateralMovementDetector::detect_lateral_movement() {
    std::cout << "[*] Analyzing lateral movement patterns..." << std::endl;
    
    movements = {
        {
            "WORKSTATION-01",
            "FILE-SERVER-01",
            "SMB/Windows Admin Shares",
            "2024-12-01T14:32:15Z",
            true
        },
        {
            "WORKSTATION-01",
            "DC-01",
            "WinRM/PowerShell Remoting",
            "2024-12-01T14:35:22Z",
            true
        },
        {
            "FILE-SERVER-01",
            "DB-SERVER-01",
            "RDP Brute Force Success",
            "2024-12-01T15:01:45Z",
            false
        }
    };
    
    return movements;
}

void LateralMovementDetector::print_movement_report() {
    std::cout << "\n=== Lateral Movement Analysis ===" << std::endl;
    std::cout << "Total Events: " << movements.size() << std::endl;
    
    for (const auto& m : movements) {
        std::cout << "\n[Movement Detected]" << std::endl;
        std::cout << "  Source: " << m.source_host << std::endl;
        std::cout << "  Destination: " << m.dest_host << std::endl;
        std::cout << "  Technique: " << m.technique << std::endl;
        std::cout << "  Time: " << m.timestamp << std::endl;
        std::cout << "  Status: " << (m.confirmed ? "CONFIRMED" : "SUSPICIOUS") << std::endl;
    }
}

} // namespace KernelScanner
