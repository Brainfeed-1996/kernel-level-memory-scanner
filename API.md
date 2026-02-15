# API Reference

## Table des Matières
1. [MemoryScanner Class](#memoryscanner-class)
2. [ScannerConfig](#scannerconfig)
3. [ScanResult](#scanresult)
4. [Detection Structures](#detection-structures)
5. [Enumerations](#enumerations)
6. [Utilities](#utilities)

---

## 1. MemoryScanner Class

```cpp
namespace KernelScanner {

class MemoryScanner {
public:
    // Constructors
    MemoryScanner();
    explicit MemoryScanner(const ScannerConfig& config);
    
    // Destructor
    ~MemoryScanner();
    
    // ==================== Initialization ====================
    
    /**
     * @brief Initialize the scanner with configuration
     * @param config Scanner configuration
     * @return true if initialization successful
     */
    bool initialize(const ScannerConfig& config);
    
    /**
     * @brief Shutdown the scanner and release resources
     */
    void shutdown();
    
    /**
     * @brief Check if scanner is initialized
     */
    bool is_initialized() const;
    
    /**
     * @brief Get the last error message
     */
    std::string get_last_error() const;
    
    // ==================== Scanning ====================
    
    /**
     * @brief Perform a full system scan
     * @return ScanResult containing all detections
     */
    ScanResult full_system_scan();
    
    /**
     * @brief Scan a specific process by PID
     * @param pid Process ID to scan
     * @return Optional result if scan successful
     */
    std::optional<ProcessScanResult> scan_process(uint32_t pid);
    
    /**
     * @brief Scan multiple processes
     * @param pids List of process IDs
     * @return Vector of scan results
     */
    std::vector<ProcessScanResult> scan_processes(const std::vector<uint32_t>& pids);
    
    /**
     * @brief Analyze a memory dump file
     * @param dump_path Path to the dump file
     * @return Optional result if analysis successful
     */
    std::optional<DumpAnalysisResult> analyze_memory_dump(const std::string& dump_path);
    
    /**
     * @brief Perform a custom scan with filters
     * @param filter Scan filter configuration
     * @return ScanResult
     */
    ScanResult custom_scan(const ScanFilter& filter);
    
    /**
     * @brief Perform a kernel memory scan
     * @return KernelScanResult
     */
    KernelScanResult scan_kernel_memory();
    
    // ==================== Analysis ====================
    
    /**
     * @brief Perform behavioral analysis on a process
     * @param pid Process ID
     * @return BehavioralAnalysis result
     */
    BehavioralAnalysis analyze_behavior(uint32_t pid);
    
    /**
     * @brief Analyze process memory regions
     * @param pid Process ID
     * @return MemoryAnalysisResult
     */
    MemoryAnalysisResult analyze_process_memory(uint32_t pid);
    
    /**
     * @brief Perform deep code analysis
     * @param address Memory address to analyze
     * @param size Size of the region
     * @return CodeAnalysisResult
     */
    CodeAnalysisResult analyze_code(LPCVOID address, SIZE_T size);
    
    // ==================== YARA Integration ====================
    
    /**
     * @brief Load YARA rules from a directory
     * @param rules_path Path to rules directory
     * @return Number of rules loaded
     */
    size_t load_yara_rules(const std::string& rules_path);
    
    /**
     * @brief Load YARA rules from a string
     * @param rules_string YARA rules as string
     * @return Number of rules loaded
     */
    size_t load_yara_rules_string(const std::string& rules_string);
    
    /**
     * @brief Scan a process with YARA rules
     * @param pid Process ID
     * @return YaraScanResult
     */
    YaraScanResult scan_with_yara(uint32_t pid);
    
    /**
     * @brief Scan memory with YARA rules
     * @param address Memory address
     * @param size Size to scan
     * @return YaraScanResult
     */
    YaraScanResult scan_memory_with_yara(LPCVOID address, SIZE_T size);
    
    // ==================== ML Integration ====================
    
    /**
     * @brief Load ML model from file
     * @param model_path Path to model file
     * @return true if loaded successfully
     */
    bool load_ml_model(const std::string& model_path);
    
    /**
     * @brief Run ML classification on process features
     * @param features Process features vector
     * @return MLClassificationResult
     */
    MLClassificationResult classify_with_ml(const std::vector<float>& features);
    
    /**
     * @brief Detect anomalies using ML
     * @param data Input data for anomaly detection
     * @return AnomalyDetectionResult
     */
    AnomalyDetectionResult detect_anomalies(const std::vector<float>& data);
    
    // ==================== Reporting ====================
    
    /**
     * @brief Generate forensic report
     * @param result Scan result
     * @param format Report format
     * @param output_path Output file path
     */
    void generate_forensic_report(const ScanResult& result,
                                  ReportFormat format,
                                  const std::string& output_path);
    
    /**
     * @brief Generate process-specific report
     * @param result Process scan result
     * @param format Report format
     * @param output_path Output file path
     */
    void generate_process_report(const ProcessScanResult& result,
                                 ReportFormat format,
                                 const std::string& output_path);
    
    // ==================== SIEM Export ====================
    
    /**
     * @brief Export results to SIEM
     * @param result Scan result
     * @param config SIEM configuration
     * @return true if export successful
     */
    bool export_to_siem(const ScanResult& result, const SIEMConfig& config);
    
    /**
     * @brief Export to Splunk HEC
     * @param result Scan result
     * @param endpoint Splunk HEC endpoint
     * @param token HEC token
     * @return true if successful
     */
    bool export_to_splunk(const ScanResult& result,
                          const std::string& endpoint,
                          const std::string& token);
    
    /**
     * @brief Export to Elasticsearch
     * @param result Scan result
     * @param endpoint ES endpoint
     * @param index Index name
     * @return true if successful
     */
    bool export_to_elasticsearch(const ScanResult& result,
                                 const std::string& endpoint,
                                 const std::string& index);
    
    // ==================== Threat Intelligence ====================
    
    /**
     * @brief Update threat intelligence database
     * @param sources List of feed URLs
     * @return Number of IOCs updated
     */
    size_t update_threat_intelligence(const std::vector<std::string>& sources);
    
    /**
     * @brief Check if IOC matches known threats
     * @param ioc IOC to check
     * @return ThreatMatchResult
     */
    ThreatMatchResult check_ioc(const IOC& ioc);
    
    /**
     * @brief Query threat intelligence
     * @param query Search query
     * @return Vector of matching threats
     */
    std::vector<ThreatIntelResult> query_threat_intel(const std::string& query);
    
    // ==================== Utility ====================
    
    /**
     * @brief Get scanner version
     */
    std::string get_version() const;
    
    /**
     * @brief Get supported platforms
     */
    std::vector<Platform> get_supported_platforms() const;
    
    /**
     * @brief Get available detection modules
     */
    std::vector<std::string> get_available_modules() const;
    
    /**
     * @brief Health check
     */
    bool health_check() const;
};

} // namespace KernelScanner
```

---

## 2. ScannerConfig

```cpp
struct ScannerConfig {
    // Scan Options
    bool enable_deep_scan = false;
    bool enable_kernel_scan = false;
    bool use_yara = true;
    bool use_neural_network = false;
    bool enable_behavioral_analysis = false;
    
    // Performance
    int max_threads = std::thread::hardware_concurrency();
    int scan_timeout_seconds = 300;
    size_t max_memory_mb = 0;  // 0 = unlimited
    
    // Sensitivity
    Sensitivity sensitivity = Sensitivity::NORMAL;
    
    // Threat Intelligence
    ThreatIntelligenceLevel threat_intelligence_level = ThreatIntelligenceLevel::STANDARD;
    std::string custom_rules_path;
    std::vector<std::string> threat_feed_urls;
    
    // SIEM
    bool enable_siem_export = false;
    SIEMConfig siem_config;
    
    // Logging
    LogLevel log_level = LogLevel::INFO;
    std::string log_file;
    
    // Callbacks
    std::function<void(const ScanProgress&)> progress_callback;
    std::function<void(const Detection&)> detection_callback;
};

enum class Sensitivity {
    LOW = 0,
    NORMAL = 1,
    HIGH = 2,
    PARANOID = 3
};

enum class ThreatIntelligenceLevel {
    DISABLED = 0,
    BASIC = 1,
    STANDARD = 2,
    ADVANCED = 3
};

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

struct SIEMConfig {
    SIEMType type = SIEMType::NONE;
    std::string endpoint;
    std::string token;
    std::string index;
    bool verify_ssl = true;
    int batch_size = 100;
    int retry_count = 3;
};

enum class SIEMType {
    NONE = 0,
    SPLUNK = 1,
    ELASTICSEARCH = 2,
    SUMOLOGIC = 3,
    QRADAR = 4,
    CUSTOM = 5
};
```

---

## 3. ScanResult

```cpp
struct ScanResult {
    // Timing
    double scan_duration_seconds = 0.0;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    
    // Scope
    int64_t memory_scanned_bytes = 0;
    int processes_scanned = 0;
    int kernel_regions_scanned = 0;
    
    // Results
    int total_detections = 0;
    Severity severity_summary = Severity::INFO;
    std::vector<Detection> detections;
    
    // Indicators
    std::vector<IOC> iocs;
    std::vector<IOA> ioas;
    
    // MITRE ATT&CK
    std::vector<MITREMapping> mitre_mappings;
    
    // Statistics
    ScanStatistics statistics;
    
    // Metadata
    std::string scanner_version;
    Platform platform = Platform::UNKNOWN;
    std::string os_version;
};

struct ScanStatistics {
    int true_positives = 0;
    int false_positives = 0;
    int true_negatives = 0;
    double detection_rate = 0.0;
    double false_positive_rate = 0.0;
};
```

---

## 4. Detection Structures

```cpp
struct Detection {
    // Identification
    std::string id;
    std::string name;
    std::string description;
    
    // Classification
    DetectionCategory category = DetectionCategory::UNKNOWN;
    Severity severity = Severity::INFO;
    ConfidenceLevel confidence = ConfidenceLevel::MEDIUM;
    
    // MITRE ATT&CK
    std::string mitre_tactic;
    std::string mitre_technique;
    std::string mitre_technique_id;
    
    // Context
    uint32_t process_pid = 0;
    std::string process_name;
    ProcessInfo process_info;
    
    // Technical Details
    std::vector<Indicator> indicators;
    std::vector<Evidence> evidence;
    
    // Remediation
    std::vector<std::string> recommended_actions;
    RiskAssessment risk_assessment;
};

enum class Severity {
    CRITICAL = 5,
    HIGH = 4,
    MEDIUM = 3,
    LOW = 2,
    INFO = 1,
    SAFE = 0
};

enum class ConfidenceLevel {
    CRITICAL = 100,
    HIGH = 90,
    MEDIUM = 70,
    LOW = 50,
    UNCERTAIN = 25
};

enum class DetectionCategory {
    CODE_INJECTION,
    PROCESS_HOLLOWING,
    PERSISTENCE,
    ROOTKIT,
    RANSOMWARE,
    C2_COMMUNICATION,
    FILESLESS_ATTACK,
    LATERAL_MOVEMENT,
    PRIVILEGE_ESCALATION,
    DATA_EXFILTRATION,
    CREDENTIAL_THEFT,
    DEFENSE_EVASION,
    ANTI_DEBUG,
    EDR_BYPASS,
    UNKNOWN
};

struct ProcessInfo {
    uint32_t pid = 0;
    std::string name;
    std::string path;
    std::string command_line;
    std::string user;
    std::string parent_process;
    uint64_t start_time = 0;
    std::vector<MemoryRegion> memory_regions;
};

struct Indicator {
    std::string type;
    std::string value;
    std::string context;
    double weight = 1.0;
};

struct Evidence {
    std::string type;
    std::string description;
    std::string location;
    std::vector<uint8_t> data;
};

struct RiskAssessment {
    int score = 0;  // 0-100
    std::string impact;
    std::string likelihood;
    std::vector<std::string> affected_systems;
};
```

---

## 5. Enumerations

```cpp
enum class Platform {
    UNKNOWN = 0,
    WINDOWS = 1,
    LINUX = 2,
    MACOS = 3
};

enum class Architecture {
    UNKNOWN = 0,
    X86 = 1,
    X64 = 2,
    ARM32 = 3,
    ARM64 = 4
};

enum class ReportFormat {
    JSON = 0,
    XML = 1,
    HTML = 2,
    PDF = 3,
    MARKDOWN = 4,
    STIX2 = 5,
    CSV = 6
};

enum class MemoryProtection {
    READ = 1,
    WRITE = 2,
    EXECUTE = 4
};

enum class InjectionType {
    UNKNOWN = 0,
    CLASSIC_DLL,
    REFLECTIVE_DLL,
    PROCESS_INJECTION,
    APC_INJECTION,
    THREAD_HIJACKING,
    EXTRA_WINDOW_MEMORY,
    PROCESS_DOPPELGANGING
};

enum class PersistenceType {
    UNKNOWN = 0,
    REGISTRY_RUN_KEYS,
    STARTUP_FOLDER,
    SCHEDULED_TASK,
    SERVICE,
    WMI_EVENT_SUBSCRIPTION,
    AUTORUN_INF,
    BOOTKIT,
    KERNEL_CALLBACK
};

enum class RootkitType {
    UNKNOWN = 0,
    IAT_HOOK,
    EAT_HOOK,
    INLINE_HOOK,
    DKOM,
    SYSCALL_HOOK,
    KERNEL_OBJECT_HOOK
};
```

---

## 6. Utilities

### 6.1 IOC Structure

```cpp
struct IOC {
    IOCType type;
    std::string value;
    std::string source;
    std::string description;
    int64_t first_seen = 0;
    int64_t last_seen = 0;
    int confidence = 100;
    std::vector<std::string> tags;
};

enum class IOCType {
    IP_ADDRESS,
    DOMAIN,
    URL,
    FILE_HASH_MD5,
    FILE_HASH_SHA1,
    FILE_HASH_SHA256,
    EMAIL,
    REGISTRY_KEY,
    FILE_PATH,
    MUTEX,
    COMMAND_LINE,
    YARA_RULE
};
```

### 6.2 MITRE ATT&CK Mapping

```cpp
struct MITREMapping {
    std::string tactic;
    std::string technique_id;
    std::string technique_name;
    std::string subtechnique_id;
    std::string subtechnique_name;
    std::vector<Detection*> detections;
    double coverage_score = 1.0;
};
```

### 6.3 Helper Functions

```cpp
namespace Utils {
    std::string severity_to_string(Severity severity);
    Severity string_to_severity(const std::string& str);
    
    std::string format_timestamp(std::chrono::system_clock::time_point tp);
    
    bool is_valid_pid(uint32_t pid);
    
    std::vector<uint32_t> get_all_pids();
    
    MemoryProtection protection_flags_to_enum(uint32_t flags);
    
    std::vector<MemoryRegion> enumerate_process_memory(uint32_t pid);
}
```

---

## 7. Complete Usage Example

```cpp
#include "memory_scanner.h"
#include <iostream>

int main() {
    // Configure scanner
    KernelScanner::ScannerConfig config;
    config.enable_deep_scan = true;
    config.use_yara = true;
    config.use_neural_network = true;
    config.enable_behavioral_analysis = true;
    config.threat_intelligence_level = KernelScanner::ThreatIntelligenceLevel::ADVANCED;
    config.max_threads = 8;
    
    // Setup callbacks
    config.progress_callback = [](const KernelScanner::ScanProgress& progress) {
        std::cout << std::format("Progress: {}%", progress.percentage) << std::endl;
    };
    
    config.detection_callback = [](const KernelScanner::Detection& detection) {
        std::cout << std::format("[{}] {}", 
            detection.severity, 
            detection.name) << std::endl;
    };
    
    // Initialize
    KernelScanner::MemoryScanner scanner;
    if (!scanner.initialize(config)) {
        std::cerr << "Failed to initialize: " << scanner.get_last_error() << std::endl;
        return 1;
    }
    
    // Load YARA rules
    size_t rules_loaded = scanner.load_yara_rules("./rules");
    std::cout << "Loaded " << rules_loaded << " YARA rules" << std::endl;
    
    // Load ML model
    if (scanner.load_ml_model("./models/detection.pt")) {
        std::cout << "ML model loaded" << std::endl;
    }
    
    // Perform scan
    auto result = scanner.full_system_scan();
    
    // Generate report
    scanner.generate_forensic_report(result,
                                     KernelScanner::ReportFormat::JSON,
                                     "./report.json");
    
    // Export to SIEM
    KernelScanner::SIEMConfig siem;
    siem.type = KernelScanner::SIEMType::SPLUNK;
    siem.endpoint = "https://splunk:8088";
    siem.token = "YOUR_TOKEN";
    
    scanner.export_to_siem(result, siem);
    
    return 0;
}
```