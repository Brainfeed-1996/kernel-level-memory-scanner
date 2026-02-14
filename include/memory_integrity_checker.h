#ifndef MEMORY_INTEGRITY_CHECKER_H
#define MEMORY_INTEGRITY_CHECKER_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Analysis {

struct IntegrityViolation {
    uint64_t address;
    std::string memory_region;
    std::string violation_type;
    uint64_t original_hash;
    uint64_t current_hash;
    uint32_t process_id;
    std::string timestamp;
};

struct MemoryRegion {
    uint64_t base_address;
    uint64_t size;
    std::string protection;
    std::string path;
    uint64_t hash;
    bool monitored;
};

class MemoryIntegrityChecker {
public:
    MemoryIntegrityChecker();
    ~MemoryIntegrityChecker();
    
    bool initialize();
    void add_region(uint64_t base, uint64_t size, const std::string& protection, const std::string& path);
    std::vector<IntegrityViolation> check_integrity();
    void compute_region_hash(MemoryRegion& region);
    bool detect_modifications();
    void generate_integrity_report();
    void enable_continuous_monitoring(bool enable);
    
private:
    bool initialized_;
    bool monitoring_enabled_;
    std::unordered_map<uint64_t, MemoryRegion> monitored_regions_;
    std::vector<IntegrityViolation> violations_;
    
    uint64_t calculate_crc64(const uint8_t* data, size_t length);
    bool compare_hashes(uint64_t original, uint64_t current);
    void snapshot_region(uint64_t base);
};

} // namespace Analysis

#endif // MEMORY_INTEGRITY_CHECKER_H
