#ifndef ADVANCED_PE_FORENSICS_H
#define ADVANCED_PE_FORENSICS_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>

namespace Analysis {

struct PESectionV2 {
    std::string section_name;
    uint64_t virtual_size;
    uint64_t raw_size;
    uint64_t virtual_address;
    uint64_t raw_address;
    uint32_t characteristics;
    std::vector<uint8_t> entropy;
    bool is_executable;
    bool is_writable;
    bool is_shared;
    double suspicious_score;
};

struct ImportTableV2 {
    std::string dll_name;
    std::vector<std::string> function_names;
    std::vector<uint32_t> ordinals;
    std::vector<uint64_t> addresses;
};

struct ExportTableV2 {
    std::string module_name;
    std::vector<std::string> exported_functions;
    std::vector<uint32_t> ordinals;
    std::vector<uint64_t> addresses;
};

struct ResourceInfoV2 {
    std::string resource_type;
    std::string resource_name;
    uint64_t offset;
    uint64_t size;
    std::string language;
    std::vector<uint8_t> hash;
};

struct PEAnalysisResult {
    std::string file_path;
    std::string pe_type; // executable, dll, driver, sys
    std::string architecture; // x86, x64, ARM
    std::string compiler;
    std::string compiler_version;
    uint64_t entry_point;
    uint64_t image_base;
    std::vector<PESectionV2> sections;
    std::vector<ImportTableV2> imports;
    std::vector<ExportTableV2> exports;
    std::vector<ResourceInfoV2> resources;
    bool is_packed;
    bool is_signed;
    bool is_malicious;
    double malicious_score;
    std::vector<std::string> suspicious_indicators;
    std::vector<std::string> yara_matches;
};

class AdvancedPEForensics {
public:
    AdvancedPEForensics();
    ~AdvancedPEForensics();
    
    bool initialize();
    PEAnalysisResult analyze_pe(const std::string& file_path);
    bool detect_packing();
    bool detect_obfuscation();
    bool detect_anti_analysis();
    bool detect_implant_indicators();
    std::vector<std::string> extract_strings();
    std::vector<std::string> detect_c2_indicators();
    void generate_pe_report(const PEAnalysisResult& result);
    
private:
    bool initialized_;
    
    bool parse_headers(const std::string& file_path, PEAnalysisResult& result);
    bool analyze_sections(const PEAnalysisResult& result);
    bool analyze_imports(const PEAnalysisResult& result);
    bool analyze_exports(const PEAnalysisResult& result);
    bool analyze_resources(const PEAnalysisResult& result);
    double calculate_suspicious_score(const PEAnalysisResult& result);
    bool check_digital_signature(const std::string& file_path);
};

} // namespace Analysis

#endif // ADVANCED_PE_FORENSICS_H
