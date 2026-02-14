#ifndef LATERAL_MOVEMENT_DETECTOR_H
#define LATERAL_MOVEMENT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class LateralMovementDetector {
public:
    struct MovementEvent {
        std::string source_host;
        std::string dest_host;
        std::string technique;
        std::string timestamp;
        bool confirmed;
    };
    
    LateralMovementDetector();
    std::vector<MovementEvent> detect_lateral_movement();
    void print_movement_report();

private:
    std::vector<MovementEvent> movements;
};

} // namespace KernelScanner

#endif
