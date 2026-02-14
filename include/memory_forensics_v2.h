#ifndef MEMORY_FORENSICS_V2_H
#define MEMORY_FORENSICS_V2_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Analysis {

struct MemoryRegionV2 {
    uint64_t base_address;
    uint64_t size;
    std::string protection;
    std::string allocation_type;
    std::string memory_type;
    std::string file_path;
    std::vector<uint8_t> hash;
    std::vector<std::string> tags;
    bool is_suspicious;
    double risk_score;
};

struct ProcessInfoV2 {
    uint32_t process_id;
    std::string process_name;
    uint64_t create_time;
    uint64_t exit_time;
    uint64_t parent_pid;
    std::string command_line;
    std::string current_directory;
    std::string executable_path;
    std::vector<MemoryRegionV2> memory_regions;
    std::vector<std::string> loaded_dlls;
    std::vector<std::string> handles;
    std::vector<uint8_t> process_hash;
};

struct ThreadInfoV2 {
    uint32_t thread_id;
    uint32_t process_id;
    uint64_t start_address;
    uint64_t stack_base;
    uint64_t stack_limit;
    uint64_t teb_address;
    std::string thread_state;
    std::string wait_reason;
    std::vector<uint64_t> call_stack;
    bool is_suspicious;
};

struct NetworkConnectionV2 {
    uint32_t process_id;
    std::string process_name;
    uint8_t protocol;
    std::string local_addr;
    uint16_t local_port;
    std::string remote_addr;
    uint16_t remote_port;
    std::string remote_name;
    uint64_t creation_time;
    uint32_t state;
    bool is_listening;
    bool is_established;
};

class MemoryForensicsV2 {
public:
    MemoryForensicsV2();
    ~MemoryForensicsV2();
    
    bool initialize();
    
    // Process analysis
    std::vector<ProcessInfoV2> enumerate_processes();
    ProcessInfoV2 get_process_info(uint32_t pid);
    std::vector<ProcessInfoV2> find_suspicious_processes();
    bool analyze_process_memory(uint32_t pid);
    
    // Thread analysis
    std::vector<ThreadInfoV2> enumerate_threads(uint32_t pid);
    std::vector<ThreadInfoV2> find_malicious_threads();
    bool analyze_thread_context(uint32_t tid, uint64_t& rip, uint64_t& rsp);
    
    // Memory regions
    std::vector<MemoryRegionV2> enumerate_memory_regions(uint32_t pid);
    std::vector<MemoryRegionV2> find_code_caves(uint32_t pid);
    std::vector<MemoryRegionV2> find_injected_memory(uint32_t pid);
    
    // Network connections
    std::vector<NetworkConnectionV2> enumerate_network_connections();
    std::vector<NetworkConnectionV2> find_c2_connections();
    
    // DLL analysis
    std::vector<std::string> enumerate_dlls(uint32_t pid);
    std::vector<std::string> detect_unusual_dlls(uint32_t pid);
    
    // Handle analysis
    std::vector<std::string> enumerate_handles(uint32_t pid);
    
    // Artifact extraction
    std::vector<uint8_t> extract_process_hash(uint32_t pid);
    std::string extract_command_line(uint32_t pid);
    
    void generate_forensics_report();
    
private:
    bool initialized_;
    std::vector<ProcessInfoV2> processes_;
    
    bool parse_pe_header(const uint8_t* data, uint64_t size);
    bool detect_packing(const uint8_t* data, uint64_t size);
    std::vector<uint8_t> calculate_hash(const uint8_t* data, uint64_t size);
    bool check_malicious_patterns(const std::string& data);
};

} // namespace Analysis

#endif // MEMORY_FORENSICS_V2_H
