#ifndef THREAT_HUNTING_ENGINE_H
#define THREAT_HUNTING_ENGINE_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Analysis {

struct ThreatHunt {
    std::string hunt_id;
    std::string hypothesis;
    std::vector<std::string> data_sources;
    std::vector<std::string> ioc_patterns;
    std::vector<std::string> ttps;
    uint64_t start_time;
    uint64_t end_time;
    int findings_count;
    double confidence_score;
};

struct IOCMatch {
    std::string ioc_type;
    std::string ioc_value;
    std::string source_file;
    uint64_t timestamp;
    std::string related_ttps;
    double severity;
};

struct HuntReport {
    std::string hunt_id;
    std::string summary;
    std::vector<IOCMatch> iocs_found;
    std::vector<std::string>ttps_identified;
    std::vector<std::string> recommendations;
    double overall_risk_score;
};

class ThreatHuntingEngine {
public:
    ThreatHuntingEngine();
    ~ThreatHuntingEngine();
    
    bool initialize();
    ThreatHunt create_hunt(const std::string& hypothesis);
    std::vector<IOCMatch> execute_hunt(const ThreatHunt& hunt);
    bool validate_hypothesis(const std::string& hypothesis);
    std::vector<HuntReport> generate_hunt_reports();
    void add_ioc_pattern(const std::string& ioc_type, const std::string& pattern);
    void add_mitre_technique(const std::string& technique_id, const std::string& description);
    void generate_threat_intelligence_report();
    
private:
    bool initialized_;
    std::unordered_map<std::string, std::vector<std::string>> ioc_patterns_;
    std::unordered_map<std::string, std::string> mitre_techniques_;
    std::vector<ThreatHunt> completed_hunts_;
    std::vector<HuntReport> reports_;
    
    bool search_logs(const std::vector<std::string>& data_sources);
    bool correlate_events(const std::vector<IOCMatch>& iocs);
    double calculate_risk_score(const std::vector<IOCMatch>& iocs);
};

} // namespace Analysis

#endif // THREAT_HUNTING_ENGINE_H
