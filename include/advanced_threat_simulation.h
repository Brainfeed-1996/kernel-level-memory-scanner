#ifndef ADVANCED_THREAT_SIMULATION_H
#define ADVANCED_THREAT_SIMULATION_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <chrono>

namespace KernelScanner {

// Advanced threat simulation engine for red team exercises
struct ThreatSimulationConfig {
    bool enable_mitre_attck_simulation;
    bool enable_realistic_behaviors;
    bool enable_lateral_movement;
    bool enable_exfiltration;
    int simulation_complexity; // 1-10
    std::vector<std::string> target_tactics;
    std::vector<std::string> target_techniques;
};

struct SimulationScenario {
    std::string scenario_id;
    std::string scenario_name;
    std::string description;
    std::vector<std::string> mitre_tactics;
    std::vector<std::string> mitre_techniques;
    int difficulty_level;
    std::map<std::string, std::string> metadata;
};

struct SimulationResult {
    std::string scenario_id;
    bool detection_triggered;
    std::vector<std::string> triggered_detections;
    std::vector<std::string> evasion_techniques;
    double detection_timing_ms;
    std::string severity_assessment;
    std::map<std::string, double> detection_scores;
};

class AdvancedThreatSimulation {
public:
    AdvancedThreatSimulation();
    ~AdvancedThreatSimulation();

    bool initialize(const ThreatSimulationConfig& config);
    
    // Scenario Management
    std::vector<SimulationScenario> get_available_scenarios();
    SimulationScenario load_scenario(const std::string& scenario_id);
    void create_custom_scenario(const SimulationScenario& scenario);
    
    // Execution
    SimulationResult execute_scenario(const std::string& scenario_id);
    SimulationResult execute_technique(const std::string& technique_id);
    
    // MITRE ATT&CK Simulation
    void simulate_tactic(const std::string& tactic);
    void simulate_technique(const std::string& technique_id);
    void simulate_full_chain();
    
    // Red Team Operations
    void simulate_initial_access();
    void simulate_execution();
    void simulate_persistence();
    void simulate_privilege_escalation();
    void simulate_defense_evasion();
    void simulate_credential_access();
    void simulate_discovery();
    void simulate_lateral_movement();
    void simulate_collection();
    void simulate_exfiltration();
    void simulate_impact();
    
    // Custom Behavior Simulation
    void register_custom_behavior(
        const std::string& name,
        std::function<void()> behavior_func
    );
    
    // Reporting
    void generate_simulation_report(const SimulationResult& result);
    void export_to_json(const std::string& filename);
    void export_to_csv(const std::string& filename);

private:
    bool initialized_;
    ThreatSimulationConfig config_;
    std::map<std::string, SimulationScenario> scenarios_;
    std::vector<SimulationResult> history_;
    
    void initialize_default_scenarios();
    SimulationResult run_detection_evaluation();
    std::vector<std::string> get_associated_techniques(const std::string& tactic);
};

} // namespace KernelScanner

#endif // ADVANCED_THREAT_SIMULATION_H
