#ifndef LATERAL_MOVEMENT_DETECTOR_H
#define LATERAL_MOVEMENT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Detection {

struct LateralMovementIndicator {
    std::string source_host;
    std::string dest_host;
    std::string technique;
    std::string source_process;
    uint32_t source_pid;
    std::string dest_process;
    uint32_t dest_pid;
    uint64_t timestamp;
    bool confirmed;
    double confidence_score;
    std::vector<std::string> evidence_artifacts;
};

struct CredentialAccess {
    std::string technique;
    std::string source;
    std::vector<std::string> accounts_compromised;
    std::string data_exfiltrated;
    uint64_t timestamp;
};

struct NetworkConnection {
    std::string source_ip;
    uint32_t source_port;
    std::string dest_ip;
    uint32_t dest_port;
    std::string protocol;
    bool is_internal;
    bool is_suspicious;
    std::string process_name;
    uint32_t process_id;
};

class LateralMovementDetector {
public:
    LateralMovementDetector();
    ~LateralMovementDetector();
    
    bool initialize();
    std::vector<LateralMovementIndicator> detect_lateral_movement();
    std::vector<CredentialAccess> detect_credential_access();
    std::vector<NetworkConnection> analyze_network_connections();
    bool detect_smb_psexec();
    bool detect_wmi_lateral_movement();
    bool detect_winrm_lateral_movement();
    bool detect_scheduled_task_lateral();
    bool detect_pass_the_hash();
    bool detect_pass_the_ticket();
    bool detect_over_pass_the_hash();
    void generate_lateral_movement_report();
    
private:
    bool initialized_;
    std::vector<LateralMovementIndicator> detected_movement_;
    
    bool check_smb_activity(const std::string& source, const std::string& dest);
    bool check_wmi_activity(uint32_t pid);
    bool check_winrm_activity(uint32_t pid);
    bool check_admin_shares_access(const std::string& host);
    bool detect_remote_process_creation(uint32_t pid);
};

} // namespace Detection

#endif // LATERAL_MOVEMENT_DETECTOR_H
