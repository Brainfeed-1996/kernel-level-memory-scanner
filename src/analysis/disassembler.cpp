#include "disassembler.h"

namespace KernelScanner {

Disassembler::Disassembler() {
    // x86/x64 opcode mapping
    opcode_map["90"] = "nop";
    opcode_map["48 89"] = "mov";
    opcode_map["48 8B"] = "mov";
    opcode_map["E8"] = "call";
    opcode_map["E9"] = "jmp";
    opcode_map["74"] = "je";
    opcode_map["75"] = "jne";
    opcode_map["C3"] = "ret";
    opcode_map["CC"] = "int3";
    opcode_map["55"] = "push rbp";
    opcode_map["48 83"] = "add";
    opcode_map["48 81"] = "add";
    opcode_map["33"] = "xor";
    opcode_map["48 33"] = "xor";
    opcode_map["85"] = "test";
    opcode_map["48 85"] = "test";
}

std::vector<Disassembler::Instruction> Disassembler::disassemble_code(
    const std::vector<uint8_t>& code, uint64_t base_address) {
    
    std::cout << "[*] Disassembling code at base: 0x" << std::hex << base_address << std::dec << std::endl;
    
    std::vector<Instruction> instructions;
    uint64_t address = base_address;
    size_t offset = 0;
    
    while (offset < code.size()) {
        Instruction inst;
        inst.address = address;
        inst.raw_bytes.push_back(code[offset]);
        
        // Simple disassembly simulation
        if (code[offset] == 0x90) {
            inst.mnemonic = "nop";
            inst.operands = "";
        } else if (code[offset] == 0xC3) {
            inst.mnemonic = "ret";
            inst.operands = "";
        } else if (code[offset] == 0xCC) {
            inst.mnemonic = "int3";
            inst.operands = "";
        } else if (code[offset] == 0x55) {
            inst.mnemonic = "push";
            inst.operands = "rbp";
        } else if (code[offset] == 0xE8) {
            inst.mnemonic = "call";
            inst.operands = "0x" + std::to_string(rand() % 0x100000);
        } else if (code[offset] == 0xE9) {
            inst.mnemonic = "jmp";
            inst.operands = "0x" + std::to_string(rand() % 0x100000);
        } else if (code[offset] == 0x33) {
            inst.mnemonic = "xor";
            inst.operands = "eax, eax";
        } else {
            inst.mnemonic = "mov";
            inst.operands = "rax, rbx";
        }
        
        instructions.push_back(inst);
        address += inst.raw_bytes.size();
        offset += inst.raw_bytes.size();
        
        if (instructions.size() >= 20) break; // Limit instructions
    }
    
    return instructions;
}

std::vector<Disassembler::Function> Disassembler::identify_functions(
    const std::vector<uint8_t>& code, uint64_t base_address) {
    
    std::vector<Function> functions;
    
    // Simulate function detection
    Function func;
    func.entry_point = base_address + 0x1000;
    func.name = "sub_" + std::to_string(rand() % 0x1000);
    func.size = 256;
    func.instructions = disassemble_code(code, func.entry_point);
    functions.push_back(func);
    
    return functions;
}

void Disassembler::print_disassembly(const std::vector<Instruction>& instructions) {
    std::cout << "\n=== Disassembly ===" << std::endl;
    
    for (const auto& inst : instructions) {
        std::cout << "0x" << std::hex << inst.address << std::dec << ": ";
        
        // Print raw bytes
        for (auto b : inst.raw_bytes) {
            std::cout << std::hex << (int)b << " " << std::dec;
        }
        
        // Pad for alignment
        for (size_t i = inst.raw_bytes.size(); i < 8; ++i) {
            std::cout << "   ";
        }
        
        std::cout << inst.mnemonic << " " << inst.operands << std::endl;
    }
}

} // namespace KernelScanner
