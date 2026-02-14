#include "network_analyzer.h"

namespace KernelScanner {

NetworkTrafficAnalyzer::NetworkTrafficAnalyzer() {}

void NetworkTrafficAnalyzer::capture_packets(int count) {
    std::cout << "[*] Capturing " << count << " packets..." << std::endl;
    
    for (int i = 0; i < count; ++i) {
        PacketInfo packet;
        packet.timestamp = time(nullptr) + i;
        
        // Simulate packet capture
        if (rand() % 10 < 3) {
            // Suspicious packet to C2
            packet.src_ip = "192.168.1.100";
            packet.dst_ip = "185.141.25.68";
            packet.dst_port = 443;
            packet.protocol = "HTTPS";
            packet.suspicious = true;
        } else {
            packet.src_ip = "192.168.1." + std::to_string(rand() % 255);
            packet.dst_ip = "8.8.8.8";
            packet.dst_port = 53;
            packet.protocol = "DNS";
            packet.suspicious = false;
        }
        
        packet.src_port = 1024 + rand() % 64000;
        packet.payload_preview = "...";
        
        packets.push_back(packet);
    }
    
    std::cout << "Captured " << packets.size() << " packets" << std::endl;
}

void NetworkTrafficAnalyzer::analyze_traffic() {
    std::cout << "[*] Analyzing network traffic..." << std::endl;
    
    for (const auto& packet : packets) {
        std::string conn_key = packet.src_ip + "->" + packet.dst_ip;
        
        if (connections.find(conn_key) == connections.end()) {
            Connection conn;
            conn.src_ip = packet.src_ip;
            conn.dst_ip = packet.dst_ip;
            conn.bytes_sent = 0;
            conn.bytes_received = 0;
            conn.start_time = packet.timestamp;
            conn.last_activity = packet.timestamp;
            conn.established = true;
            connections[conn_key] = conn;
        }
        
        connections[conn_key].last_activity = packet.timestamp;
        connections[conn_key].bytes_sent += packet.payload_preview.size();
    }
}

void NetworkTrafficAnalyzer::detect_anomalies() {
    std::cout << "[*] Detecting network anomalies..." << std::endl;
    
    int suspicious_count = 0;
    for (const auto& packet : packets) {
        if (packet.suspicious) {
            suspicious_count++;
            std::cout << "[!] Suspicious connection: " << packet.src_ip 
                      << " -> " << packet.dst_ip << ":" << packet.dst_port << std::endl;
        }
    }
    
    std::cout << "Suspicious packets: " << suspicious_count << "/" << packets.size() << std::endl;
}

void NetworkTrafficAnalyzer::generate_report() {
    std::cout << "\n=== Network Traffic Analysis Report ===" << std::endl;
    std::cout << "Total Packets: " << packets.size() << std::endl;
    std::cout << "Unique Connections: " << connections.size() << std::endl;
    
    int suspicious_count = 0;
    for (const auto& packet : packets) {
        if (packet.suspicious) suspicious_count++;
    }
    
    std::cout << "Suspicious Packets: " << suspicious_count << std::endl;
    
    std::cout << "\nTop Connections:" << std::endl;
    for (const auto& [key, conn] : connections) {
        std::cout << "  " << key << " - Sent: " << conn.bytes_sent 
                  << " bytes, Recv: " << conn.bytes_received << " bytes" << std::endl;
    }
}

} // namespace KernelScanner
