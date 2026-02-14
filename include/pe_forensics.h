#ifndef PE_FORENSICS_H
#define PE_FORENSICS_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class PEForensics {
public:
    struct PEHeader {
        std::string machine;
        uint16_t timestamp;
        std::string sections;
        uint32_t entry_point;
        std::vector<std::string> imports;
        std::vector<std::string> exports;
    };
    
    struct SectionInfo {
        std::string name;
        uint32_t virtual_address;
        uint32_t virtual_size;
        uint32_t raw_size;
        std::string characteristics;
    };
    
    PEForensics();
    PEHeader parse_pe_header(const std::string& file_path);
    std::vector<SectionInfo> parse_sections();
    void detect_packing();
    void detect_obfuscation();
    void analyze_imports();
    void generate_report(const PEHeader& header);

private:
    std::string file_path;
};

} // namespace KernelScanner

#endif
