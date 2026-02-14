#ifndef ATTACK_CHAIN_VISUALIZER_H
#define ATTACK_CHAIN_VISUALIZER_H

#include <iostream>
#include <string>
#include <vector>

namespace KernelScanner {

class AttackChainVisualizer {
public:
    struct AttackStage {
        int stage_id;
        std::string name;
        std::string technique;
        std::string timestamp;
        std::string details;
    };
    
    AttackChainVisualizer();
    void build_attack_chain();
    void visualize_attack_chain();

private:
    std::vector<AttackStage> attack_chain;
};

} // namespace KernelScanner

#endif
