#ifndef C2_DETECTOR_H
#define C2_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace KernelScanner {

class C2Detector {
public:
    struct C2Connection {
        std::string ip_address;
        std::uint16_t port;
        std::string protocol;
        std::string beacon_interval;
        std::string encoding;
        bool confirmed;
    };
    
    C2Detector();
    std::vector<C2Connection> detect_c2();
    void print_c2_report();

private:
    std::vector<C2Connection> c2_connections;
};

} // namespace KernelScanner

#endif
