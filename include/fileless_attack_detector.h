#ifndef FILESLESS_ATTACK_DETECTOR_H
#define FILESLESS_ATTACK_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Detection {

struct FilelessIndicator {
    std::string process_name;
    uint32_t process_id;
    std::string technique_type;
    std::vector<std::string> memory_regions;
    std::vector<std::string> script_patterns;
    std::vector<std::string> api_calls;
    bool confirmed;
    double confidence_score;
    uint64_t detection_time;
};

struct MemoryArtifact {
    uint64_t address;
    uint64_t size;
    std::string protection;
    std::string allocation_type;
    std::string content_type;
    bool is_executable;
    bool is_writable;
    bool is_anomalous;
};

struct ScriptExecution {
    std::string script_engine;
    std::string script_content;
    std::vector<std::string> obfuscated_patterns;
    std::vector<std::string> suspicious_commands;
    uint64_t execution_time;
    uint32_t parent_pid;
};

class FilelessAttackDetector {
public:
    FilelessAttackDetector();
    ~FilelessAttackDetector();
    
    bool initialize();
    std::vector<FilelessIndicator> detect_fileless_activity();
    bool analyze_memory_artifacts(uint32_t pid);
    std::vector<MemoryArtifact> find_anomalous_memory_regions(uint32_t pid);
    bool detect_powershell_attacks();
    bool detect_wmi_attacks();
    bool detect_registry_script_execution();
    void generate_fileless_report();
    void add_known_fileless_signature(const std::string& signature);
    
private:
    bool initialized_;
    std::vector<std::string> known_fileless_signatures_;
    std::vector<FilelessIndicator> detected_threats_;
    
    bool check_memory_allocation_pattern(uint32_t pid);
    bool detect_script_obfuscation(const std::string& script);
    bool detect_com_hijacking(uint32_t pid);
    bool check_dll_reflection(uint32_t pid);
};

} // namespace Detection

#endif // FILESLESS_ATTACK_DETECTOR_H
