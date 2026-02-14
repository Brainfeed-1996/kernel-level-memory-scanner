#ifndef HEARTBEAT_DETECTOR_H
#define HEARTBEAT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace Detection {

struct HeartbeatConfig {
    uint32_t interval_ms;
    uint32_t timeout_ms;
    bool validate_sequence;
    std::vector<uint8_t> expected_pattern;
};

struct HeartbeatEvent {
    uint32_t process_id;
    uint64_t timestamp;
    std::string event_type;
    bool suspicious;
    std::string details;
};

class HeartbeatDetector {
public:
    HeartbeatDetector();
    ~HeartbeatDetector();
    
    bool initialize();
    void configure(const HeartbeatConfig& config);
    std::vector<HeartbeatEvent> detect_anomalies();
    bool validate_heartbeat(uint32_t pid, const std::vector<uint8_t>& data);
    void generate_report();
    
private:
    bool initialized_;
    HeartbeatConfig config_;
    std::vector<uint32_t> monitored_processes_;
    
    bool check_timing_anomaly(uint32_t pid, uint64_t current_time);
    bool check_pattern_anomaly(const std::vector<uint8_t>& received);
    bool check_sequence_number(uint32_t pid, uint32_t seq);
};

} // namespace Detection

#endif // HEARTBEAT_DETECTOR_H
