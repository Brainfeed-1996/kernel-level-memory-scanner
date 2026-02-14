#ifndef ADVANCED_PERSISTENCE_DETECTOR_H
#define ADVANCED_PERSISTENCE_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Detection {

struct PersistenceIndicator {
    std::string persistence_type;
    std::string location;
    std::string technique_name;
    std::string process_name;
    uint32_t process_id;
    std::string execution_path;
    uint64_t first_seen;
    uint64_t last_executed;
    bool confirmed;
    double risk_score;
    std::vector<std::string> related_files;
    std::vector<std::string> related_registry;
};

struct ScheduledTaskInfo {
    std::string task_name;
    std::string task_path;
    std::string author;
    std::string command;
    uint64_t last_run_time;
    uint64_t next_run_time;
    bool is_hidden;
    bool is_suspicious;
};

struct ServiceInfo {
    std::string service_name;
    std::string display_name;
    std::string binary_path;
    std::string service_type;
    uint32_t start_type;
    bool is_driver;
    bool is_suspicious;
};

class AdvancedPersistenceDetector {
public:
    AdvancedPersistenceDetector();
    ~AdvancedPersistenceDetector();
    
    bool initialize();
    std::vector<PersistenceIndicator> scan_all_persistence();
    std::vector<ScheduledTaskInfo> detect_scheduled_tasks();
    std::vector<ServiceInfo> detect_suspicious_services();
    bool detect_wmi_event_subscriptions();
    bool detect_image_hash Hijacking();
    bool detect_appinit_dlls();
    bool detect_com_hijacking();
    bool detect_ie_extensions();
    bool detect_browser_extensions();
    void generate_persistence_report();
    
private:
    bool initialized_;
    std::vector<PersistenceIndicator> detected_persistence_;
    
    bool parse_scheduled_task_xml(const std::string& task_path);
    bool check_service_registry(const std::string& service_name);
    bool detect_registry_run_keys();
    bool detect_winlogon_notify();
    bool detect_user_init_mpr_dlls();
};

} // namespace Detection

#endif // ADVANCED_PERSISTENCE_DETECTOR_H
