#ifndef NETWORK_TRAFFIC_ANALYZER_V2_H
#define NETWORK_TRAFFIC_ANALYZER_V2_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Analysis {

struct PacketInfo {
    uint64_t timestamp;
    uint8_t protocol;
    std::string src_ip;
    uint16_t src_port;
    std::string dst_ip;
    uint16_t dst_port;
    uint64_t payload_size;
    std::vector<uint8_t> payload;
    bool is_encrypted;
    std::string tls_sni;
    std::string dns_query;
    std::string dns_response;
};

struct FlowInfo {
    std::string flow_id;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t total_bytes;
    uint64_t packet_count;
    std::vector<uint64_t> inter_arrival_times;
    bool is_suspicious;
    std::string classification;
};

struct Connection {
    uint32_t process_id;
    std::string process_name;
    std::vector<FlowInfo> flows;
    std::string local_address;
    uint16_t local_port;
    std::string remote_address;
    uint16_t remote_port;
    std::string protocol;
    std::string state;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t last_activity;
};

struct TrafficAlert {
    uint64_t timestamp;
    std::string alert_type;
    std::string severity; // low, medium, high, critical
    std::string source_ip;
    std::string destination_ip;
    std::string description;
    std::vector<std::string>ttps;
    bool confirmed;
};

class NetworkTrafficAnalyzerV2 {
public:
    NetworkTrafficAnalyzerV2();
    ~NetworkTrafficAnalyzerV2();
    
    bool initialize();
    std::vector<PacketInfo> capture_packets(uint32_t count);
    std::vector<FlowInfo> extract_flows(const std::vector<PacketInfo>& packets);
    std::vector<Connection> get_active_connections();
    std::vector<TrafficAlert> detect_anomalies();
    std::vector<TrafficAlert> detect_c2_traffic();
    std::vector<TrafficAlert> detect_exfiltration();
    bool analyze_dns_queries();
    bool analyze_tls_handshakes();
    void generate_network_report();
    
private:
    bool initialized_;
    std::vector<PacketInfo> captured_packets_;
    std::vector<TrafficAlert> alerts_;
    
    bool extract_packet_headers(const uint8_t* data, PacketInfo& info);
    bool classify_traffic(const FlowInfo& flow);
    bool detect_beaconing(const FlowInfo& flow);
    bool detect_data_exfiltration(const FlowInfo& flow);
    bool detect_port_scanning(const std::vector<Connection>& connections);
    bool analyze_packet_payload(const PacketInfo& packet);
};

} // namespace Analysis

#endif // NETWORK_TRAFFIC_ANALYZER_V2_H
