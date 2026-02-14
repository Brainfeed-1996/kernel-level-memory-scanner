#ifndef BOOTKIT_DETECTOR_H
#define BOOTKIT_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace Detection {

struct BootkitIndicator {
    std::string component_name;
    std::string injection_location;
    std::string bootkit_type;
    std::vector<uint64_t> modified_sectors;
    uint64_t infection_timestamp;
    bool confirmed;
    double risk_level;
};

struct MBRInfo {
    uint8_t boot_sector[512];
    uint16_t partition_table[64];
    uint64_t checksum;
    bool signature_valid;
};

struct VBRInfo {
    uint8_t vbr_sector[512];
    std::string boot_loader;
    uint64_t original_checksum;
    uint64_t current_checksum;
    bool modified;
};

class BootkitDetector {
public:
    BootkitDetector();
    ~BootkitDetector();
    
    bool initialize();
    std::vector<BootkitIndicator> scan_for_bootkits();
    bool analyze_mbr(MBRInfo& mbr_info);
    bool analyze_vbr(const std::string& drive, VBRInfo& vbr_info);
    bool detect_uefi_bootkits();
    bool check_bootmgr_integrity();
    bool detect_nvme_bootkits();
    void generate_bootkit_report();
    
private:
    bool initialized_;
    std::vector<BootkitIndicator> detected_bootkits_;
    
    uint64_t calculate_sector_checksum(const uint8_t* sector, size_t size);
    bool compare_checksums(uint64_t original, uint64_t current);
    bool detect_hidden_sectors();
    bool check_persistent_storage();
};

} // namespace Detection

#endif // BOOTKIT_DETECTOR_H
