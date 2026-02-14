#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class Disassembler {
public:
    struct Instruction {
        uint64_t address;
        std::string mnemonic;
        std::string operands;
        std::vector<uint8_t> raw_bytes;
    };
    
    struct Function {
        uint64_t entry_point;
        std::string name;
        std::vector<Instruction> instructions;
        size_t size;
    };
    
    Disassembler();
    std::vector<Instruction> disassemble_code(const std::vector<uint8_t>& code, uint64_t base_address);
    std::vector<Function> identify_functions(const std::vector<uint8_t>& code, uint64_t base_address);
    void print_disassembly(const std::vector<Instruction>& instructions);

private:
    std::map<std::string, std::string> opcode_map;
};

} // namespace KernelScanner

#endif
