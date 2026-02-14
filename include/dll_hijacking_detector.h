#ifndef DLL_HIJACKING_DETECTOR_H
#define DLL_HIJACKING_DETECTOR_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Detection {

struct DLLHijackIndicator {
    std::string dll_name;
    std::string hijack_path;
    std::string legitimate_path;
    std::string process_name;
    uint32_t process_id;
    bool confirmed;
    double risk_score;
    std::vector<std::string> vulnerable_paths;
};

struct SearchPathEntry {
    std::string path;
    bool writable;
    bool exists;
    std::string dll_found;
};

class DLLHijackingDetector {
public:
    DLLHijackingDetector();
    ~DLLHijackingDetector();
    
    bool initialize();
    std::vector<DLLHijackIndicator> scan_process(uint32_t pid);
    std::vector<DLLHijackIndicator> scan_all_processes();
    bool check_search_order(const std::string& process_path);
    std::vector<SearchPathEntry> enumerate_search_path(const std::string& process_path);
    void generate_hijack_report();
    void add_known_vulnerable_dll(const std::string& dll_name);
    
private:
    bool initialized_;
    std::vector<std::string> known_vulnerable_dlls_;
    std::unordered_map<std::string, std::vector<DLLHijackIndicator>> results_;
    
    bool check_dll_exists(const std::string& path);
    bool is_path_writable(const std::string& path);
    std::string find_dll_in_path(const std::string& dll_name, const std::vector<std::string>& paths);
    double calculate_risk_score(const DLLHijackIndicator& indicator);
};

} // namespace Detection

#endif // DLL_HIJACKING_DETECTOR_H
