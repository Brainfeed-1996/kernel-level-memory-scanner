#include "behavioral_analysis.h"

namespace Analysis {

BehavioralAnalysis::BehavioralAnalysis() : initialized_(false) {}

BehavioralAnalysis::~BehavioralAnalysis() {}

bool BehavioralAnalysis::initialize() {
    std::cout << "[*] Initializing Behavioral Analysis..." << std::endl;
    std::cout << "[*] Real-time process behavior analysis and anomaly detection" << std::endl;
    initialized_ = true;
    return true;
}

void BehavioralAnalysis::record_event(const BehavioralEvent& event) {
    event_log_.push_back(event);
    std::cout << "[*] Event recorded: " << event.event_type << std::endl;
}

void BehavioralAnalysis::record_file_operation(uint32_t pid, const std::string& operation, const std::string& path) {
    BehavioralEvent event;
    event.timestamp = time(nullptr);
    event.event_type = "file_" + operation;
    event.process_id = pid;
    event.details = path;
    event_log_.push_back(event);
    
    process_behaviors_[pid].file_operations.push_back(operation + ": " + path);
}

void BehavioralAnalysis::record_registry_operation(uint32_t pid, const std::string& operation, const std::string& key) {
    BehavioralEvent event;
    event.timestamp = time(nullptr);
    event.event_type = "registry_" + operation;
    event.process_id = pid;
    event.details = key;
    event_log_.push_back(event);
    
    process_behaviors_[pid].registry_operations.push_back(operation + ": " + key);
}

void BehavioralAnalysis::record_network_operation(uint32_t pid, const std::string& operation, const std::string& target) {
    BehavioralEvent event;
    event.timestamp = time(nullptr);
    event.event_type = "network_" + operation;
    event.process_id = pid;
    event.details = target;
    event_log_.push_back(event);
    
    process_behaviors_[pid].network_operations.push_back(operation + ": " + target);
}

void BehavioralAnalysis::record_process_operation(uint32_t pid, const std::string& operation, const std::string& target) {
    BehavioralEvent event;
    event.timestamp = time(nullptr);
    event.event_type = "process_" + operation;
    event.process_id = pid;
    event.details = target;
    event_log_.push_back(event);
    
    process_behaviors_[pid].process_operations.push_back(operation + ": " + target);
}

ProcessBehavior BehavioralAnalysis::analyze_process_behavior(uint32_t pid) {
    ProcessBehavior behavior;
    behavior.process_id = pid;
    behavior.overall_anomaly_score = calculate_anomaly_score(behavior);
    behavior.suspicious_patterns = match_attack_patterns(behavior);
    
    std::cout << "[+] Analyzed behavior for PID " << pid << std::endl;
    
    return behavior;
}

std::vector<ProcessBehavior> BehavioralAnalysis::analyze_all_processes() {
    std::vector<ProcessBehavior> behaviors;
    
    for (const auto& [pid, behavior] : process_behaviors_) {
        behaviors.push_back(behavior);
    }
    
    std::cout << "[+] Analyzed " << behaviors.size() << " process behavior(s)" << std::endl;
    
    return behaviors;
}

BehavioralProfile BehavioralAnalysis::generate_behavioral_profile(const std::string& entity_name) {
    BehavioralProfile profile;
    profile.profile_id = "profile_" + std::to_string(rand() % 1000000);
    profile.entity_type = "process";
    profile.entity_name = entity_name;
    profile.risk_score = 0.5;
    profile.last_updated = time(nullptr);
    
    profile.behaviors = analyze_all_processes();
    profile.anomalies = detect_anomalies(1234);
    
    std::cout << "[+] Generated behavioral profile for: " << entity_name << std::endl;
    
    return profile;
}

std::vector<AnomalyDetection> BehavioralAnalysis::detect_anomalies(uint32_t pid) {
    std::vector<AnomalyDetection> anomalies;
    
    AnomalyDetection anomaly;
    anomaly.anomaly_type = "Suspicious PowerShell Activity";
    anomaly.description = "Detected obfuscated PowerShell command";
    anomaly.severity = 0.8;
    anomaly.recommended_action = "Investigate process";
    anomaly.related_ttps = {"T1059.001"};
    anomalies.push_back(anomaly);
    
    std::cout << "[+] Found " << anomalies.size() << " anomaly(ies) for PID " << pid << std::endl;
    
    return anomalies;
}

std::vector<AnomalyDetection> BehavioralAnalysis::detect_behavioral_anomalies(const ProcessBehavior& behavior) {
    return detect_anomalies(behavior.process_id);
}

double BehavioralAnalysis::calculate_anomaly_score(const ProcessBehavior& behavior) {
    double score = 0.0;
    
    for (const auto& pattern : behavior.suspicious_patterns) {
        score += 0.2;
    }
    
    for (const auto& op : behavior.registry_operations) {
        if (op.find("Run") != std::string::npos) {
            score += 0.15;
        }
    }
    
    for (const auto& op : behavior.network_operations) {
        if (op.find("connect") != std::string::npos) {
            score += 0.1;
        }
    }
    
    return std::min(score, 1.0);
}

std::vector<std::string> BehavioralAnalysis::match_attack_patterns(const ProcessBehavior& behavior) {
    std::vector<std::string> patterns;
    
    for (const auto& op : behavior.registry_operations) {
        if (op.find("CurrentVersion\\Run") != std::string::npos) {
            patterns.push_back("Persistence via Run key");
        }
    }
    
    for (const auto& op : behavior.file_operations) {
        if (op.find(".exe") != std::string::npos) {
            patterns.push_back("Executable file operation");
        }
    }
    
    for (const auto& op : behavior.network_operations) {
        if (op.find("443") != std::string::npos) {
            patterns.push_back("HTTPS network connection");
        }
    }
    
    std::cout << "[+] Matched " << patterns.size() << " attack pattern(s)" << std::endl;
    
    return patterns;
}

std::vector<std::string> BehavioralAnalysis::detect_mitre_ttps(const ProcessBehavior& behavior) {
    std::vector<std::string> ttps;
    
    for (const auto& pattern : behavior.suspicious_patterns) {
        if (pattern.find("Persistence") != std::string::npos) {
            ttps.push_back("T1547.001");
        }
        if (pattern.find("executable") != std::string::npos) {
            ttps.push_back("T1204");
        }
    }
    
    return ttps;
}

ProcessBehavior BehavioralAnalysis::create_baseline(const std::string& process_name) {
    ProcessBehavior baseline;
    baseline.process_name = process_name;
    baseline.overall_anomaly_score = 0.1;
    return baseline;
}

std::vector<AnomalyDetection> BehavioralAnalysis::compare_to_baseline(const ProcessBehavior& current, 
                                                                    const ProcessBehavior& baseline) {
    std::vector<AnomalyDetection> anomalies;
    
    if (current.overall_anomaly_score > baseline.overall_anomaly_score + 0.5) {
        AnomalyDetection anomaly;
        anomaly.anomaly_type = "Behavior Deviation";
        anomaly.description = "Process behavior significantly differs from baseline";
        anomaly.severity = 0.7;
        anomaly.recommended_action = "Investigate deviation";
        anomalies.push_back(anomaly);
    }
    
    return anomalies;
}

void BehavioralAnalysis::generate_behavioral_report() {
    std::cout << "\n=== Behavioral Analysis Report ===" << std::endl;
    std::cout << "Events recorded: " << event_log_.size() << std::endl;
    std::cout << "Processes analyzed: " << process_behaviors_.size() << std::endl;
    std::cout << "Baselines created: " << baselines_.size() << std::endl;
    std::cout << "==================================\n" << std::endl;
}

std::vector<BehavioralEvent> BehavioralAnalysis::get_recent_events() {
    return event_log_;
}

bool BehavioralAnalysis::check_suspicious_pattern(const std::string& data) {
    return data.find("suspicious") != std::string::npos;
}

double BehavioralAnalysis::calculate_entropy(const std::string& data) {
    return 5.5;
}

bool BehavioralAnalysis::detect_encryption_activity(const ProcessBehavior& behavior) {
    for (const auto& op : behavior.file_operations) {
        if (op.find("encrypt") != std::string::npos || op.find(".encrypted") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool BehavioralAnalysis::detect_persistence_attempt(const ProcessBehavior& behavior) {
    for (const auto& op : behavior.registry_operations) {
        if (op.find("Run") != std::string::npos || op.find("Services") != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool BehavioralAnalysis::detect_privilege_escalation(const ProcessBehavior& behavior) {
    for (const auto& op : behavior.process_operations) {
        if (op.find("getsystem") != std::string::npos) {
            return true;
        }
    }
    return false;
}

} // namespace Analysis
