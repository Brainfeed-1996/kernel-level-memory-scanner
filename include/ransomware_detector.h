#ifndef RANSOMWARE_DETECTOR_H
#define RANSOMWARE_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Detection {

struct RansomwareIndicator {
    uint32_t process_id;
    std::string process_name;
    std::string ransomware_family;
    std::vector<std::string> encrypted_files;
    std::vector<std::string> suspicious_patterns;
    uint64_t encryption_speed;
    double confidence_score;
    bool confirmed;
    std::string detection_timestamp;
};

struct FileActivity {
    std::string file_path;
    std::string activity_type;
    uint64_t timestamp;
    uint32_t process_id;
    uint64_t bytes_processed;
};

class RansomwareDetector {
public:
    RansomwareDetector();
    ~RansomwareDetector();
    
    bool initialize();
    std::vector<RansomwareIndicator> detect_ransomware_activity();
    bool analyze_file_encryption_pattern(uint32_t pid);
    bool detect_mass_file_deletion();
    bool detect_suspicious_renaming(uint32_t pid);
    void monitor_file_activity();
    void generate_ransomware_report();
    void add_known_ransomware_signature(const std::string& signature);
    
private:
    bool initialized_;
    std::unordered_map<std::string, std::string> known_ransomware_;
    std::vector<FileActivity> file_activities_;
    std::vector<RansomwareIndicator> detected_threats_;
    
    bool check_file_extension_change(const std::string& file_path);
    bool check_encryption_pattern(const std::string& file_path);
    bool check_random_file_generation(const std::vector<std::string>& files);
    double calculate_encryption_speed(const std::vector<FileActivity>& activities);
};

} // namespace Detection

#endif // RANSOMWARE_DETECTOR_H
