#ifndef EDR_EVASION_DETECTOR_H
#define EDR_EVASION_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace Detection {

struct EDEVasionIndicator {
    std::string process_name;
    uint32_t process_id;
    std::string evasion_technique;
    std::vector<std::string> api_calls;
    std::vector<std::string> modified_files;
    std::vector<std::string> hooked_functions;
    bool confirmed;
    double confidence_score;
    uint64_t detection_time;
};

class EDEVasionDetector {
public:
    EDEVasionDetector();
    ~EDEVasionDetector();
    
    bool initialize();
    std::vector<EDEVasionIndicator> detect_edr_evasion();
    bool detect_process_hollowing();
    bool detect_dll_unhooking();
    bool detect_etw_patch();
    bool detect_syscall_abuse();
    bool detect_token_manipulation();
    void generate_edr_report();
    void add_known_evasion_technique(const std::string& technique);
    
private:
    bool initialized_;
    std::vector<std::string> known_evasion_techniques_;
    std::vector<EDEVasionIndicator> detected_evasions_;
    
    bool check_edr_dll_loaded(const std::string& process);
    bool detect_inline_hooks(uint32_t pid);
    bool check_process_mitigation_policies(uint32_t pid);
    bool detect_parent_pid_spoofing(uint32_t pid);
};

} // namespace Detection

#endif // EDR_EVASION_DETECTOR_H
