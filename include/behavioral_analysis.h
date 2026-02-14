#ifndef BEHAVIORAL_ANALYSIS_H
#define BEHAVIORAL_ANALYSIS_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Analysis {

struct BehavioralEvent {
    uint64_t timestamp;
    std::string event_type;
    std::string process_name;
    uint32_t process_id;
    std::string details;
    std::vector<std::string> tags;
    double anomaly_score;
};

struct ProcessBehavior {
    uint32_t process_id;
    std::string process_name;
    std::string command_line;
    std::vector<BehavioralEvent> events;
    std::vector<std::string> file_operations;
    std::vector<std::string> registry_operations;
    std::vector<std::string> network_operations;
    std::vector<std::string> process_operations;
    uint64_t start_time;
    uint64_t end_time;
    double overall_anomaly_score;
    std::vector<std::string> suspicious_patterns;
};

struct AnomalyDetection {
    std::string anomaly_type;
    std::string description;
    double severity;
    std::string recommended_action;
    std::vector<std::string> related_ttps;
};

struct BehavioralProfile {
    std::string profile_id;
    std::string entity_type;
    std::string entity_name;
    std::vector<ProcessBehavior> behaviors;
    std::vector<AnomalyDetection> anomalies;
    double risk_score;
    uint64_t last_updated;
    std::vector<std::string> tags;
};

class BehavioralAnalysis {
public:
    BehavioralAnalysis();
    ~BehavioralAnalysis();
    
    bool initialize();
    
    // Event collection
    void record_event(const BehavioralEvent& event);
    void record_file_operation(uint32_t pid, const std::string& operation, const std::string& path);
    void record_registry_operation(uint32_t pid, const std::string& operation, const std::string& key);
    void record_network_operation(uint32_t pid, const std::string& operation, const std::string& target);
    void record_process_operation(uint32_t pid, const std::string& operation, const std::string& target);
    
    // Behavior analysis
    ProcessBehavior analyze_process_behavior(uint32_t pid);
    std::vector<ProcessBehavior> analyze_all_processes();
    BehavioralProfile generate_behavioral_profile(const std::string& entity_name);
    
    // Anomaly detection
    std::vector<AnomalyDetection> detect_anomalies(uint32_t pid);
    std::vector<AnomalyDetection> detect_behavioral_anomalies(const ProcessBehavior& behavior);
    double calculate_anomaly_score(const ProcessBehavior& behavior);
    
    // Pattern matching
    std::vector<std::string> match_attack_patterns(const ProcessBehavior& behavior);
    std::vector<std::string> detect_mitre_ttps(const ProcessBehavior& behavior);
    
    // Baseline comparison
    ProcessBehavior create_baseline(const std::string& process_name);
    std::vector<AnomalyDetection> compare_to_baseline(const ProcessBehavior& current, 
                                                       const ProcessBehavior& baseline);
    
    // Reporting
    void generate_behavioral_report();
    std::vector<BehavioralEvent> get_recent_events();
    
private:
    bool initialized_;
    std::vector<BehavioralEvent> event_log_;
    std::unordered_map<uint32_t, ProcessBehavior> process_behaviors_;
    std::unordered_map<std::string, ProcessBehavior> baselines_;
    
    bool check_suspicious_pattern(const std::string& data);
    double calculate_entropy(const std::string& data);
    bool detect_encryption_activity(const ProcessBehavior& behavior);
    bool detect_persistence_attempt(const ProcessBehavior& behavior);
    bool detect_privilege_escalation(const ProcessBehavior& behavior);
};

} // namespace Analysis

#endif // BEHAVIORAL_ANALYSIS_H
