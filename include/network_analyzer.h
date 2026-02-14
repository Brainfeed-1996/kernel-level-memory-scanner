#ifndef NETWORK_ANALYZER_H
#define NETWORK_ANALYZER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class NetworkTrafficAnalyzer {
public:
    struct PacketInfo {
        uint64_t timestamp;
        std::string src_ip;
        std::string dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        std::string protocol;
        std::string payload_preview;
        bool suspicious;
    };
    
    struct Connection {
        std::string src_ip;
        std::string dst_ip;
        uint64_t bytes_sent;
        uint64_t bytes_received;
        uint64_t start_time;
        uint64_t last_activity;
        bool established;
    };
    
    NetworkTrafficAnalyzer();
    void capture_packets(int count);
    void analyze_traffic();
    void detect_anomalies();
    void generate_report();

private:
    std::vector<PacketInfo> packets;
    std::map<std::string, Connection> connections;
};

} // namespace KernelScanner

#endif
