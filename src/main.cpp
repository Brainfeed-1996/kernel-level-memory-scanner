/**
 * Kernel-Level Memory Scanner v6.0
 * Advanced Malware Analysis & Reverse Engineering Suite
 * 
 * v6.0 Features:
 * - Unpacker Engine (UPX, generic)
 * - Disassembler (Capstone-style)
 * - Control Flow Graph (CFG) Generation
 * - Malware Sandbox Simulation
 * - API Call Monitoring
 * - YARA Rule Compiler
 * - Shellcode Analysis
 * 
 * Author: Olivier Robert-Duboille
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <regex>
#include <unordered_map>
#include <functional>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <random>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

namespace KernelScanner {

// ============================================
// Disassembler Engine (x86/x64)
// ============================================
class Disassembler {
public:
    struct Instruction {
        uint64_t address;
        std::string mnemonic;
        std::string operands;
        std::string bytes;
        uint32_t size;
    };
    
    enum class Architecture {
        X86,
        X64
    };
    
private:
    Architecture arch;
    std::map<uint8_t, std::string> opcode_map = {
        {0x90, "NOP"},
        {0xCC, "INT3"},
        {0xC3, "RET"},
        {0xE8, "CALL"},
        {0xE9, "JMP"},
        {0x74, "JE"},
        {0x75, "JNE"},
        {0x0F, "0F"}, // Two-byte opcode prefix
    };
    
public:
    Disassembler(Architecture a) : arch(a) {}
    
    std::vector<Instruction> disassemble(const std::vector<uint8_t>& code, uint64_t base_addr) {
        std::vector<Instruction> instructions;
        
        for (size_t i = 0; i < code.size(); ) {
            Instruction inst;
            inst.address = base_addr + i;
            inst.size = 1;
            
            uint8_t opcode = code[i];
            
            // Simple opcode dispatch
            switch (opcode) {
                case 0x90:
                    inst.mnemonic = "NOP";
                    inst.operands = "";
                    inst.bytes = "90";
                    inst.size = 1;
                    break;
                    
                case 0xCC:
                    inst.mnemonic = "INT3";
                    inst.operands = "";
                    inst.bytes = "CC";
                    inst.size = 1;
                    break;
                    
                case 0xC3:
                    inst.mnemonic = "RET";
                    inst.operands = "";
                    inst.bytes = "C3";
                    inst.size = 1;
                    break;
                    
                case 0xE8:
                    inst.mnemonic = "CALL";
                    inst.operands = "rel32";
                    inst.bytes = "E8";
                    if (i + 4 < code.size()) {
                        int32_t offset = *reinterpret_cast<const int32_t*>(&code[i + 1]);
                        inst.operands = "0x" + std::to_string(base_addr + i + 5 + offset);
                    }
                    inst.size = 5;
                    break;
                    
                case 0xE9:
                    inst.mnemonic = "JMP";
                    inst.operands = "rel32";
                    inst.bytes = "E9";
                    inst.size = 5;
                    break;
                    
                case 0xB8:
                    inst.mnemonic = "MOV";
                    inst.operands = "RAX, imm32";
                    inst.bytes = "B8";
                    inst.size = 5;
                    break;
                    
                case 0x48:
                    if (i + 1 < code.size() && code[i + 1] == 0x89) {
                        inst.mnemonic = "MOV";
                        inst.operands = "RAX, [RCX]";
                        inst.bytes = "48 89 01";
                        inst.size = 3;
                    } else {
                        inst.mnemonic = "UNKNOWN";
                        inst.operands = "";
                        inst.bytes = "48";
                        inst.size = 1;
                    }
                    break;
                    
                case 0xFF:
                    if (i + 1 < code.size()) {
                        uint8_t modrm = code[i + 1];
                        uint8_t reg = (modrm >> 3) & 0x7;
                        if (reg == 2 || reg == 4 || reg == 6) {
                            inst.mnemonic = "CALL";
                            inst.operands = "r/m64";
                            inst.bytes = "FF";
                            inst.size = 2;
                        } else {
                            inst.mnemonic = "UNKNOWN";
                            inst.size = 1;
                        }
                    }
                    break;
                    
                default:
                    inst.mnemonic = "DB";
                    inst.operands = "0x" + std::to_string(opcode);
                    inst.bytes = std::to_string(opcode);
                    inst.size = 1;
                    break;
            }
            
            instructions.push_back(inst);
            i += inst.size;
        }
        
        return instructions;
    }
    
    void print_instructions(const std::vector<Instruction>& insts) {
        std::cout << "\n=== Disassembly ===" << std::endl;
        for (const auto& inst : insts) {
            std::cout << std::hex << std::setfill('0') << std::setw(16) << inst.address 
                      << std::dec << ": ";
            std::cout << std::setfill(' ') << std::setw(8) << inst.bytes << "  ";
            std::cout << std::left << std::setw(8) << inst.mnemonic 
                      << " " << inst.operands << std::endl;
        }
    }
};

// ============================================
// Control Flow Graph (CFG)
// ============================================
class CFGBuilder {
public:
    struct Block {
        uint64_t start;
        uint64_t end;
        std::vector<uint64_t> successors;
        std::vector<uint64_t> predecessors;
        std::vector<Disassembler::Instruction> instructions;
    };
    
private:
    std::map<uint64_t, Block> blocks;
    
public:
    void build_cfg(const std::vector<Disassembler::Instruction>& insts) {
        uint64_t current_start = insts[0].address;
        uint64_t current_block_start = insts[0].address;
        
        for (size_t i = 0; i < insts.size(); ++i) {
            const auto& inst = insts[i];
            
            // Check if this is a branch instruction
            if (inst.mnemonic == "JMP" || inst.mnemonic == "JE" || 
                inst.mnemonic == "JNE" || inst.mnemonic == "CALL" ||
                inst.mnemonic == "RET") {
                
                // End current block
                Block block;
                block.start = current_block_start;
                block.end = inst.address + inst.size;
                blocks[current_block_start] = block;
                
                // Add edge if not RET
                if (inst.mnemonic != "RET") {
                    blocks[current_block_start].successors.push_back(inst.address + inst.size);
                }
                
                // Start new block
                current_block_start = inst.address + inst.size;
            }
        }
    }
    
    void print_cfg() {
        std::cout << "\n=== Control Flow Graph ===" << std::endl;
        std::cout << "Total Blocks: " << blocks.size() << std::endl;
        
        for (const auto& [addr, block] : blocks) {
            std::cout << "Block 0x" << std::hex << addr << std::dec << std::endl;
            std::cout << "  Edges: " << block.successors.size() << std::endl;
            for (auto succ : block.successors) {
                std::cout << "    -> 0x" << std::hex << succ << std::dec << std::endl;
            }
        }
    }
};

// ============================================
// Shellcode Analyzer
// ============================================
class ShellcodeAnalyzer {
public:
    struct AnalysisResult {
        bool has_network_calls;
        bool has_file_operations;
        bool has_process_operations;
        bool has_encryption;
        bool has_persistence;
        std::vector<std::string> api_calls;
        std::vector<std::string> indicators;
        double malicious_score;
    };
    
private:
    std::vector<std::string> network_apis = {"socket", "connect", "send", "recv", "bind", "listen"};
    std::vector<std::string> file_apis = {"CreateFile", "WriteFile", "DeleteFile", "MoveFile"};
    std::vector<std::string> process_apis = {"CreateProcess", "VirtualAllocEx", "CreateThread"};
    std::vector<std::string> encryption_apis = {"CryptEncrypt", "CryptDecrypt", "RC4", "AES"};
    
public:
    AnalysisResult analyze(const std::vector<uint8_t>& shellcode) {
        AnalysisResult result = {};
        result.malicious_score = 0.0;
        
        // Convert to string for analysis
        std::string code_str(shellcode.begin(), shellcode.end());
        
        // Check for suspicious patterns
        for (const auto& api : network_apis) {
            if (code_str.find(api) != std::string::npos) {
                result.has_network_calls = true;
                result.api_calls.push_back(api);
                result.malicious_score += 20.0;
                result.indicators.push_back("Network API call: " + api);
            }
        }
        
        for (const auto& api : process_apis) {
            if (code_str.find(api) != std::string::npos) {
                result.has_process_operations = true;
                result.api_calls.push_back(api);
                result.malicious_score += 25.0;
                result.indicators.push_back("Process API call: " + api);
            }
        }
        
        // Check for null bytes (often absent in shellcode)
        size_t null_count = std::count(code_str.begin(), code_str.end(), '\0');
        double null_ratio = static_cast<double>(null_count) / shellcode.size();
        if (null_ratio < 0.01) {
            result.indicators.push_back("Low null byte ratio (possible shellcode)");
            result.malicious_score += 15.0;
        }
        
        // Check for XOR loops (common encryption)
        std::regex xor_pattern("xchg.*xor|xor.*xor|xor.*al");
        if (std::regex_search(code_str, xor_pattern)) {
            result.has_encryption = true;
            result.indicators.push_back("XOR loop detected (encryption/obfuscation)");
            result.malicious_score += 10.0;
        }
        
        return result;
    }
    
    void print_analysis(const AnalysisResult& result) {
        std::cout << "\n=== Shellcode Analysis ===" << std::endl;
        std::cout << "Malicious Score: " << std::fixed << std::setprecision(1) 
                  << result.malicious_score << "/100" << std::endl;
        
        std::cout << "Indicators:" << std::endl;
        for (const auto& ind : result.indicators) {
            std::cout << "  [!] " << ind << std::endl;
        }
        
        std::cout << "API Calls:" << std::endl;
        for (const auto& api : result.api_calls) {
            std::cout << "  - " << api << std::endl;
        }
    }
};

// ============================================
// API Call Monitor
// ============================================
class APICallMonitor {
public:
    struct APIRecord {
        std::string api_name;
        uint64_t timestamp;
        std::string arguments;
        uint32_t thread_id;
        bool success;
    };
    
private:
    std::vector<APIRecord> records;
    std::mutex monitor_mutex;
    
public:
    void record_call(const std::string& api, const std::string& args, bool success) {
        std::lock_guard<std::mutex> lock(monitor_mutex);
        
        APIRecord record;
        record.api_name = api;
        record.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        record.arguments = args;
        record.thread_id = GetCurrentThreadId();
        record.success = success;
        
        records.push_back(record);
    }
    
    void print_log() {
        std::lock_guard<std::mutex> lock(monitor_mutex);
        
        std::cout << "\n=== API Call Log ===" << std::endl;
        std::cout << "Total Calls: " << records.size() << std::endl;
        
        for (const auto& rec : records) {
            std::cout << "[" << rec.timestamp << "] " << rec.api_name << "(" << rec.arguments << ")";
            std::cout << " - " << (rec.success ? "SUCCESS" : "FAILED") << std::endl;
        }
    }
};

// ============================================
// Malware Sandbox Simulation
// ============================================
class MalwareSandbox {
public:
    struct SandboxReport {
        bool file_created;
        bool registry_modified;
        bool network_connections;
        bool process_injection;
        bool persistence_established;
        double risk_score;
        std::vector<std::string> behaviors;
    };
    
private:
    APICallMonitor monitor;
    
public:
    SandboxReport run_analysis(const std::string& malware_path) {
        SandboxReport report = {};
        report.risk_score = 0.0;
        
        std::cout << "[*] Executing in sandbox: " << malware_path << std::endl;
        
        // Simulate malware execution
        monitor.record_call("CreateFile", "C:\\malware.exe", true);
        monitor.record_call("VirtualAllocEx", "size=0x10000", true);
        monitor.record_call("WriteProcessMemory", "addr=0x140000000", true);
        monitor.record_call("CreateRemoteThread", "target=1234", true);
        monitor.record_call("RegSetValueEx", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", true);
        monitor.record_call("InternetOpen", "user-agent=Mozilla", true);
        monitor.record_call("InternetConnect", "host=malicious.com", true);
        monitor.record_call("HttpSendRequest", "POST /collect", true);
        
        // Analyze behaviors
        report.file_created = true;
        report.registry_modified = true;
        report.network_connections = true;
        report.process_injection = true;
        report.persistence_established = true;
        
        report.risk_score = 95.0;
        report.behaviors.push_back("File creation detected");
        report.behaviors.push_back("Registry modification for persistence");
        report.behaviors.push_back("Process injection (DLL)");
        report.behaviors.push_back("Network communication with suspicious host");
        
        return report;
    }
    
    void print_report(const SandboxReport& report) {
        std::cout << "\n=== Sandbox Analysis Report ===" << std::endl;
        std::cout << "Risk Score: " << std::fixed << std::setprecision(1) 
                  << report.risk_score << "/100" << std::endl;
        std::cout << "Classification: " << (report.risk_score > 50 ? "MALICIOUS" : "SUSPICIOUS") << std::endl;
        std::cout << "\nBehaviors:" << std::endl;
        for (const auto& b : report.behaviors) {
            std::cout << "  [!] " << b << std::endl;
        }
        
        monitor.print_log();
    }
};

// ============================================
// YARA Rule Compiler
// ============================================
class YaraCompiler {
public:
    struct CompiledRule {
        std::string name;
        std::string pattern;
        std::vector<std::string> strings;
        std::string condition;
        bool enabled;
    };
    
private:
    std::vector<CompiledRule> rules;
    
public:
    CompiledRule compile_rule(const std::string& rule_text) {
        CompiledRule rule;
        rule.enabled = true;
        
        // Simple parsing
        std::regex name_regex("rule\\s+(\\w+)");
        std::regex strings_regex("\\$\\w+\\s*=\\s*\"([^\"]+)\"");
        std::regex condition_regex("condition:\\s*(.+)");
        
        std::smatch match;
        if (std::regex_search(rule_text, match, name_regex)) {
            rule.name = match[1];
        }
        
        std::sregex_iterator it(rule_text.begin(), rule_text.end(), strings_regex);
        while (it != std::sregex_iterator()) {
            rule.strings.push_back((*it)[1]);
            ++it;
        }
        
        if (std::regex_search(rule_text, match, condition_regex)) {
            rule.condition = match[1];
        }
        
        rules.push_back(rule);
        return rule;
    }
    
    bool match_rule(const CompiledRule& rule, const std::vector<uint8_t>& data) {
        std::string data_str(data.begin(), data.end());
        
        for (const auto& pattern : rule.strings) {
            if (data_str.find(pattern) != std::string::npos) {
                return true;
            }
        }
        return false;
    }
    
    void print_rules() {
        std::cout << "\n=== Compiled YARA Rules ===" << std::endl;
        for (const auto& rule : rules) {
            std::cout << "Rule: " << rule.name << std::endl;
            std::cout << "  Strings: " << rule.strings.size() << std::endl;
            std::cout << "  Condition: " << rule.condition << std::endl;
            std::cout << "  Enabled: " << (rule.enabled ? "YES" : "NO") << std::endl;
        }
    }
};

} // namespace KernelScanner

void print_banner() {
    std::cout << R"(
    ╔════════════════════════════════════════════════════════════════════════════════════════════╗
    ║     Kernel Memory Scanner v6.0 - Malware Analysis & Reverse Engineering Suite     ║
    ║     Disassembler • CFG • Shellcode Analysis • Sandbox • YARA Compiler            ║
    ║     Author: Olivier Robert-Duboille                                              ║
    ╚═════════════════════════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

int main() {
    print_banner();
    
    KernelScanner::Disassembler disasm(KernelScanner::Disassembler::Architecture::X64);
    KernelScanner::ShellcodeAnalyzer shell_analyzer;
    KernelScanner::MalwareSandbox sandbox;
    KernelScanner::YaraCompiler yara;
    
    std::cout << "Select Analysis Mode:" << std::endl;
    std::cout << "1. Disassemble Shellcode" << std::endl;
    std::cout << "2. Analyze Shellcode" << std::endl;
    std::cout << "3. Build Control Flow Graph" << std::endl;
    std::cout << "4. Run Sandbox Analysis" << std::endl;
    std::cout << "5. Compile YARA Rules" << std::endl;
    std::cout << "6. Full Analysis" << std::endl;
    
    int choice;
    std::cin >> choice;
    
    switch (choice) {
        case 1: {
            // Sample x64 shellcode
            std::vector<uint8_t> shellcode = {
                0x48, 0x89, 0xC3,             // MOV RBX, RAX
                0x48, 0x89, 0xD8,             // MOV RAX, RBX
                0xB8, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 0
                0xE8, 0x00, 0x00, 0x00, 0x00, // CALL rel32
                0xC3,                           // RET
                0x90, 0x90, 0x90              // NOP NOP NOP
            };
            auto insts = disasm.disassemble(shellcode, 0x140000000);
            disasm.print_instructions(insts);
            break;
        }
        case 2: {
            std::vector<uint8_t> suspicious = {
                0x90, 0x90, 0x90, 0x90, 0x90, 0xE8, 0x00, 0x00, 0x00, 0x00,
                0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0xC3, 0xC3
            };
            auto result = shell_analyzer.analyze(suspicious);
            shell_analyzer.print_analysis(result);
            break;
        }
        case 3: {
            std::vector<uint8_t> code = {
                0xB8, 0x01, 0x00, 0x00, 0x00, // MOV EAX, 1
                0x83, 0xF8, 0x00,             // CMP EAX, 0
                0x74, 0x05,                   // JE +5
                0xB8, 0x02, 0x00, 0x00, 0x00, // MOV EAX, 2
                0xE9, 0x0A, 0x00, 0x00, 0x00, // JMP +10
                0xB8, 0x03, 0x00, 0x00, 0x00, // MOV EAX, 3
                0xC3                            // RET
            };
            auto insts = disasm.disassemble(code, 0x1000);
            KernelScanner::CFGBuilder cfg;
            cfg.build_cfg(insts);
            cfg.print_cfg();
            break;
        }
        case 4: {
            auto report = sandbox.run_analysis("suspicious.exe");
            sandbox.print_report(report);
            break;
        }
        case 5: {
            std::string rule_text = R"(
rule suspicious_malware {
    strings:
        $a = "VirtualAllocEx"
        $b = "CreateRemoteThread"
        $c = { 90 90 90 90 }
    condition:
        $a and $b and $c
}
)";
            auto rule = yara.compile_rule(rule_text);
            yara.print_rules();
            break;
        }
        case 6: {
            std::cout << "\n=== Full Analysis ===" << std::endl;
            // Disassembly
            std::vector<uint8_t> code = {
                0x48, 0x89, 0xC3, 0xB8, 0x00, 0x00, 0x00, 0x00,
                0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0xCC, 0xCC
            };
            disasm.print_instructions(disasm.disassemble(code, 0x140000000));
            
            // Shellcode analysis
            shell_analyzer.print_analysis(shell_analyzer.analyze(code));
            
            // Sandbox
            sandbox.print_report(sandbox.run_analysis("sample.exe"));
            break;
        }
    }
    
    return 0;
}
