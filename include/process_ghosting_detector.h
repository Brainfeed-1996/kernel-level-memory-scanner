#ifndef PROCESS_GHOSTING_DETECTOR_H
#define PROCESS_GHOSTING_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Detection {

struct GhostingIndicator {
    uint32_t process_id;
    std::string process_name;
    std::string ghosting_type;
    uint64_t timestamp;
    std::vector<uint64_t> suspicious_regions;
    bool confirmed;
    double confidence_score;
};

struct MemoryRegionInfo {
    uint64_t base_address;
    uint64_t size;
    std::string protection;
    bool is_executable;
    bool is_writable;
    bool is_shared;
};

class ProcessGhostingDetector {
public:
    ProcessGhostingDetector();
    ~ProcessGhostingDetector();
    
    bool initialize();
    std::vector<GhostingIndicator> detect_process_ghosting();
    bool analyze_memory_regions(uint32_t pid);
    bool detect_image_override(uint32_t pid);
    bool detect_temporal_anomalies(uint32_t pid);
    void generate_threat_report();
    
private:
    bool initialized_;
    std::unordered_map<uint32_t, std::vector<MemoryRegionInfo>> memory_maps_;
    
    bool check_pe_header_anomalies(uint32_t pid);
    bool check_section_alignment(uint32_t pid);
    bool detect_page_file_usage(uint32_t pid);
};

} // namespace Detection

#endif // PROCESS_GHOSTING_DETECTOR_H
