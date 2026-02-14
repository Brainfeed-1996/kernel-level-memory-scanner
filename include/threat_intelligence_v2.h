#ifndef THREAT_INTELLIGENCE_V2_H
#define THREAT_INTELLIGENCE_V2_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <chrono>

namespace Analysis {

struct ThreatIntelIndicator {
    std::string indicator_type;
    std::string indicator_value;
    std::string threat_type;
    std::string threat_actor;
    std::string campaign;
    std::string malware_family;
    std::vector<std::string>ttps;
    uint64_t first_seen;
    uint64_t last_seen;
    uint32_t confidence_score;
    uint32_t severity;
    std::string source;
    bool is_active;
    std::vector<std::string> tags;
};

struct ThreatActor {
    std::string actor_id;
    std::string actor_name;
    std::string actor_type; // nation_state, criminal, hacktivist
    std::string target_sectors;
    std::vector<std::string> known_ttps;
    std::vector<std::string> malware_families;
    std::vector<std::string> infrastructure;
    uint32_t sophistication;
    std::string primary_motivation;
    double risk_score;
};

struct Campaign {
    std::string campaign_id;
    std::string campaign_name;
    std::string threat_actor;
    std::string target_region;
    std::vector<std::string> target_sectors;
    uint64_t start_date;
    uint64_t end_date;
    std::vector<std::string>ttps;
    std::vector<ThreatIntelIndicator> indicators;
    uint32_t impact_score;
};

struct MalwareFamily {
    std::string family_id;
    std::string family_name;
    std::string malware_type;
    std::vector<std::string>ttps;
    std::vector<std::string> yara_rules;
    std::vector<std::string> hashes;
    std::vector<std::string> c2_domains;
    std::vector<std::string> file_paths;
    std::string detection_name;
    uint32_t sophistication;
    uint32_t popularity;
};

struct Vulnerability {
    std::string cve_id;
    std::string cvss_score;
    std::string severity; // Critical, High, Medium, Low
    std::string description;
    std::string affected_systems;
    std::vector<std::string> epss;
    bool has_exploit;
    std::string patch_available;
};

class ThreatIntelligenceV2 {
public:
    ThreatIntelligenceV2();
    ~ThreatIntelligenceV2();
    
    bool initialize();
    
    // IOC lookup
    std::vector<ThreatIntelIndicator> lookup_ioc(const std::string& ioc_type, const std::string& value);
    bool check_ip_reputation(const std::string& ip);
    bool check_domain_reputation(const std::string& domain);
    bool check_hash_reputation(const std::string& hash);
    
    // Threat actor analysis
    std::vector<ThreatActor> get_known_threat_actors();
    ThreatActor get_threat_actor(const std::string& actor_id);
    std::vector<ThreatActor> find_actors_by_motive(const std::string& motivation);
    
    // Campaign tracking
    std::vector<Campaign> get_active_campaigns();
    Campaign get_campaign(const std::string& campaign_id);
    std::vector<Campaign> find_campaigns_by_actor(const std::string& actor_name);
    
    // Malware analysis
    std::vector<MalwareFamily> get_known_malware();
    MalwareFamily get_malware_family(const std::string& family_id);
    std::vector<std::string> generate_yara_rules(const std::string& family_name);
    
    // Vulnerability tracking
    std::vector<Vulnerability> get_critical_vulnerabilities();
    Vulnerability get_vulnerability(const std::string& cve_id);
    std::vector<Vulnerability> find_vulnerabilities_by_product(const std::string& product);
    
    // Intelligence sharing
    void submit_ioc(const ThreatIntelIndicator& indicator);
    std::vector<ThreatIntelIndicator> get_shared_intelligence();
    
    // Analytics
    uint32_t calculate_risk_score(const std::vector<ThreatIntelIndicator>& indicators);
    void generate_threat_report();
    
private:
    bool initialized_;
    std::unordered_map<std::string, ThreatIntelIndicator> ioc_database_;
    std::unordered_map<std::string, ThreatActor> threat_actors_;
    std::unordered_map<std::string, Campaign> campaigns_;
    std::unordered_map<std::string, MalwareFamily> malware_families_;
    std::unordered_map<std::string, Vulnerability> vulnerabilities_;
    
    bool load_ioc_database();
    bool load_threat_actors();
    bool load_campaigns();
    bool load_malware_families();
    bool load_vulnerabilities();
};

} // namespace Analysis

#endif // THREAT_INTELLIGENCE_V2_H
