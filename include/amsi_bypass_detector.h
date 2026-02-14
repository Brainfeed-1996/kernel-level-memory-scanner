#ifndef AMSI_BYPASS_DETECTOR_H
#define AMSI_BYPASS_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace Detection {

struct AMSIBypassIndicator {
    std::string bypass_technique;
    std::string process_name;
    uint32_t process_id;
    std::string injection_location;
    std::vector<std::string> api_calls;
    bool confirmed;
    double confidence_score;
    std::string detection_time;
};

class AMSIBypassDetector {
public:
    AMSIBypassDetector();
    ~AMSIBypassDetector();
    
    bool initialize();
    std::vector<AMSIBypassIndicator> scan_for_amsi_bypasses();
    bool detect_amsi_scan_buffer_patch(uint32_t pid);
    bool detect_amsi_init_failed(uint32_t pid);
    bool detect_etw_tampering(uint32_t pid);
    bool detect_dll_unhooking(uint32_t pid);
    void generate_amsi_report();
    void add_known_bypass_signature(const std::string& signature);
    
private:
    bool initialized_;
    std::vector<AMSIBypassIndicator> detected_bypasses_;
    
    bool check_amsiDll_unloaded(const std::string& process);
    bool check_etw_event_mask(const uint32_t pid);
    bool check_memory_patch(const uint32_t pid, uint64_t address);
    bool check_hooking_patterns(const uint32_t pid);
};

} // namespace Detection

#endif // AMSI_BYPASS_DETECTOR_H
