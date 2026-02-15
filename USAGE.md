# Guide d'Utilisation

## Table des Matières
1. [Installation](#1-installation)
2. [Configuration](#2-configuration)
3. [Utilisation Basique](#3-utilisation-basique)
4. [Utilisation Avancée](#4-utilisation-avancée)
5. [API Reference](#5-api-reference)
6. [CLI Reference](#6-cli-reference)
7. [Export & Intégrations](#7-export--intégrations)

---

## 1. Installation

### 1.1 Prérequis

```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake libboost-all-dev python3-dev python3-pip

# Windows (Visual Studio 2019+)
# Install Visual Studio with C++ desktop development workload

# macOS
brew install cmake boost python3
```

### 1.2 Installation depuis les Sources

```bash
git clone https://github.com/Brainfeed-1996/kernel-level-memory-scanner.git
cd kernel-level-memory-scanner

# Créer le build directory
mkdir build && cd build

# Configurer avec CMake
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=ON

# Compiler
cmake --build . --parallel $(nproc)

# Installer (optionnel)
sudo make install
```

### 1.3 Installation avec Docker

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential cmake libboost-all-dev python3-dev python3-pip

WORKDIR /app
COPY . .
RUN mkdir build && cd build && cmake .. && make

CMD ["./bin/memory_scanner"]
```

---

## 2. Configuration

### 2.1 Fichier de Configuration Principal

```json
{
  "scanner": {
    "deep_scan": true,
    "use_yara": true,
    "use_neural_network": true,
    "enable_behavioral_analysis": true,
    "enable_kernel_scan": true,
    "max_threads": 16,
    "timeout_seconds": 300
  },
  "detection": {
    "all_modules": true,
    "excluded_modules": [],
    "sensitivity": "high",
    "custom_yara_rules_path": "/etc/memory-scanner/rules"
  },
  "threat_intelligence": {
    "enabled": true,
    "feed_urls": [
      "https://example.com/iocs.json",
      "https://example.com/yara/rules"
    ],
    "local_database": "/var/lib/memory-scanner/ti.db"
  },
  "reporting": {
    "format": "json",
    "output_path": "/var/log/memory-scanner",
    "siem_export": {
      "enabled": true,
      "type": "splunk",
      "endpoint": "https://splunk:8088",
      "token": "YOUR_TOKEN"
    }
  },
  "logging": {
    "level": "info",
    "file": "/var/log/memory-scanner/scanner.log"
  }
}
```

### 2.2 Configuration par Programme

```cpp
#include "memory_scanner.h"

int main() {
    // Configuration du scanner
    KernelScanner::ScannerConfig config;
    
    // Options de scan
    config.enable_deep_scan = true;
    config.enable_kernel_scan = true;
    config.use_yara = true;
    config.use_neural_network = true;
    config.enable_behavioral_analysis = true;
    
    // Paramètres de performance
    config.max_threads = std::thread::hardware_concurrency();
    config.scan_timeout_seconds = 300;
    
    // Sensitivity
    config.sensitivity = KernelScanner::Sensitivity::HIGH;
    
    // Threat Intelligence
    config.threat_intelligence_level = KernelScanner::INTELLIGENCE_ADVANCED;
    config.enable_yara = true;
    config.custom_rules_path = "./rules";
    
    // SIEM Export
    config.enable_siem_export = true;
    config.siem_type = KernelScanner::SIEMConfig::splunk;
    config.siem_endpoint = "https://splunk:8088";
    config.siem_token = "YOUR_TOKEN";
    
    // Logging
    config.log_level = KernelScanner::LogLevel::INFO;
    config.log_file = "./scanner.log";
    
    // Initialisation
    KernelScanner::MemoryScanner scanner;
    if (!scanner.initialize(config)) {
        std::cerr << "Erreur d'initialisation: " << scanner.get_last_error() << std::endl;
        return 1;
    }
    
    return 0;
}
```

---

## 3. Utilisation Basique

### 3.1 Scan Complet du Système

```cpp
#include "memory_scanner.h"
#include <iostream>

int main() {
    KernelScanner::ScannerConfig config;
    config.enable_deep_scan = true;
    config.use_yara = true;
    config.use_neural_network = true;
    config.enable_behavioral_analysis = true;
    config.threat_intelligence_level = KernelScanner::INTELLIGENCE_ADVANCED;
    config.enable_kernel_scan = true;
    config.max_threads = std::thread::hardware_concurrency();
    
    KernelScanner::MemoryScanner scanner;
    if (!scanner.initialize(config)) {
        std::cerr << "Erreur d'initialisation" << std::endl;
        return 1;
    }
    
    // Scan complet du système
    auto result = scanner.full_system_scan();
    
    // Affichage des résultats
    std::cout << "Scan terminé en " << result.scan_duration_seconds << "s" << std::endl;
    std::cout << "Détections: " << result.detections.size() << std::endl;
    std::cout << "Sévérité: " << result.severity_summary << std::endl;
    
    // Afficher les détections
    for (const auto& detection : result.detections) {
        std::cout << "[" << detection.severity << "] "
                  << detection.name << std::endl;
        std::cout << "  Technique: " << detection.mitre_technique << std::endl;
        std::cout << "  Confiance: " << detection.confidence << "%" << std::endl;
    }
    
    return 0;
}
```

### 3.2 Scan d'un Processus Spécifique

```cpp
// Scan d'un processus par PID
auto process_result = scanner.scan_process(1234);

if (process_result.has_value()) {
    std::cout << "Processus scanné: " << process_result->process_name << std::endl;
    std::cout << " Détections: " << process_result->detections.size() << std::endl;
}
```

### 3.3 Scan d'un Memory Dump

```cpp
// Analyse d'un fichier de dump mémoire
auto dump_result = scanner.analyze_memory_dump("./evidence.dump");

if (dump_result.has_value()) {
    scanner.generate_forensic_report(dump_result.value(), 
                                     KernelScanner::ReportFormat::JSON);
}
```

---

## 4. Utilisation Avancée

### 4.1 Scan Personnalisé avec Filtres

```cpp
KernelScanner::ScanFilter filter;
filter.pid_range = {1000, 5000};  // PIDs spécifiques
filter.exclude_system_processes = true;
filter.only_trusted_publishers = false;
filter.scan_kernel_memory = true;
filter.scan_hidden_regions = true;

auto result = scanner.custom_scan(filter);
```

### 4.2 Analyse Comportementale

```cpp
// Activation de l'analyse comportementale
config.enable_behavioral_analysis = true;
config.behavioral_ml_model_path = "./models/behavioral.pt";

// Analyse comportementale d'un processus
auto behavior = scanner.analyze_behavior(process_pid);

std::cout << "Score de risque comportemental: " << behavior.risk_score << std::endl;
std::cout << "Comportements suspects détectés:" << std::endl;
for (const auto& behavior : behavior.suspicious_behaviors) {
    std::cout << "  - " << behavior.description << std::endl;
}
```

### 4.3 Intégration YARA

```cpp
// Charger des règles YARA personnalisées
scanner.load_yara_rules("./custom_rules/yara/");

// Scanner avec YARA
auto result = scanner.scan_with_yara(process_pid);

// Vérifier les matches
for (const auto& match : result.yara_matches) {
    std::cout << "Rule: " << match.rule_name << std::endl;
    std::cout << "Tags: " << match.tags << std::endl;
    std::cout << "Strings: " << match.strings << std::endl;
}
```

---

## 5. API Reference

### 5.1 Classe Principale: MemoryScanner

```cpp
class MemoryScanner {
public:
    // Initialisation
    bool initialize(const ScannerConfig& config);
    void shutdown();
    
    // Scans
    ScanResult full_system_scan();
    std::optional<ProcessScanResult> scan_process(uint32_t pid);
    std::optional<DumpAnalysisResult> analyze_memory_dump(const std::string& dump_path);
    ScanResult custom_scan(const ScanFilter& filter);
    
    // Analyse comportementale
    BehavioralAnalysis analyze_behavior(uint32_t pid);
    
    // YARA
    void load_yara_rules(const std::string& rules_path);
    YaraScanResult scan_with_yara(uint32_t pid);
    
    // Rapports
    void generate_forensic_report(const ScanResult& result, 
                                  ReportFormat format,
                                  const std::string& output_path);
    
    // SIEM Export
    void export_to_siem(const ScanResult& result, const SIEMConfig& config);
};
```

### 5.2 Structures de Données

```cpp
struct ScannerConfig {
    bool enable_deep_scan;
    bool enable_kernel_scan;
    bool use_yara;
    bool use_neural_network;
    bool enable_behavioral_analysis;
    int max_threads;
    Sensitivity sensitivity;
    ThreatIntelligenceLevel threat_intelligence_level;
    SIEMConfig siem_config;
};

struct ScanResult {
    double scan_duration_seconds;
    int64_t memory_scanned_bytes;
    int detections_count;
    Severity severity_summary;
    std::vector<Detection> detections;
    std::vector<IOC> iocs;
    std::vector<MITREMapping> mitre_mappings;
};

struct Detection {
    std::string id;
    std::string name;
    std::string description;
    Severity severity;
    double confidence;
    std::string mitre_technique;
    std::string category;
    ProcessInfo affected_process;
    std::vector<Indicator> indicators;
};
```

---

## 6. CLI Reference

### 6.1 Commandes Principales

```bash
# Scan complet du système
memory-scanner --full-scan

# Scan d'un processus spécifique
memory-scanner --pid 1234

# Analyse d'un memory dump
memory-scanner --analyze-dump memory.dump

# Scan avec règles YARA personnalisées
memory-scanner --yara-rules custom_rules/ --full-scan

# Export vers SIEM
memory-scanner --siem splunk --endpoint https://splunk:8088 --token TOKEN

# Génération de rapport
memory-scanner --full-scan --report json --output results.json

# Mode verbose
memory-scanner --full-scan --verbose --log-level debug
```

### 6.2 Options Disponibles

| Option | Description |
|--------|-------------|
| `--full-scan` | Scan complet du système |
| `--pid <PID>` | Scanner un processus spécifique |
| `--analyze-dump <file>` | Analyser un fichier dump |
| `--yara-rules <path>` | Charger des règles YARA |
| `--output <path>` | Fichier de sortie |
| `--format <json/xml/html>` | Format du rapport |
| `--siem <type>` | Type de SIEM (splunk, elk, sumo) |
| `--verbose` | Mode verbeux |
| `--config <file>` | Fichier de configuration |

---

## 7. Export & Intégrations

### 7.1 Export JSON

```cpp
scanner.generate_forensic_report(result, 
                                 KernelScanner::ReportFormat::JSON,
                                 "./report.json");
```

### 7.2 Export SIEM (Splunk)

```cpp
KernelScanner::SIEMConfig siem_config;
siem_config.type = KernelScanner::SIEMConfig::splunk;
siem_config.endpoint = "https://splunk:8088";
siem_config.token = "YOUR_HEC_TOKEN";
siem_config.index = "security";
siem_config.sourcetype = "memory_scanner";

scanner.export_to_siem(result, siem_config);
```

### 7.3 Export ELK Stack

```cpp
KernelScanner::SIEMConfig elk_config;
elk_config.type = KernelScanner::SIEMConfig::elasticsearch;
elk_config.endpoint = "http://elasticsearch:9200";
elk_config.index = "memory-scanner";
elk_config.auth = "elastic:password";

scanner.export_to_siem(result, elk_config);
```

---

## 8. Exemples Complets

### 8.1 Exemple de Detection Complete

```cpp
#include "memory_scanner.h"
#include <iostream>
#include <fstream>

int main() {
    std::cout << "=== Kernel-Level Memory Scanner ===" << std::endl;
    
    // Configuration
    KernelScanner::ScannerConfig config;
    config.enable_deep_scan = true;
    config.use_yara = true;
    config.use_neural_network = true;
    config.enable_behavioral_analysis = true;
    config.threat_intelligence_level = KernelScanner::INTELLIGENCE_ADVANCED;
    config.max_threads = 16;
    
    // Initialisation
    KernelScanner::MemoryScanner scanner;
    if (!scanner.initialize(config)) {
        std::cerr << "Erreur d'initialisation" << std::endl;
        return 1;
    }
    
    // Scan complet
    std::cout << "Démarrage du scan complet..." << std::endl;
    auto result = scanner.full_system_scan();
    
    // Statistiques
    std::cout << "\n=== Résultats du Scan ===" << std::endl;
    std::cout << "Durée: " << result.scan_duration_seconds << "s" << std::endl;
    std::cout << "Mémoire scannée: " << (result.memory_scanned_bytes / 1024 / 1024) << " MB" << std::endl;
    std::cout << "Détections: " << result.detections.size() << std::endl;
    
    // Par sévérité
    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& det : result.detections) {
        switch (det.severity) {
            case KernelScanner::Severity::CRITICAL: critical++; break;
            case KernelScanner::Severity::HIGH: high++; break;
            case KernelScanner::Severity::MEDIUM: medium++; break;
            case KernelScanner::Severity::LOW: low++; break;
        }
    }
    
    std::cout << "  CRITICAL: " << critical << std::endl;
    std::cout << "  HIGH: " << high << std::endl;
    std::cout << "  MEDIUM: " << medium << std::endl;
    std::cout << "  LOW: " << low << std::endl;
    
    // Génération rapport
    scanner.generate_forensic_report(result, 
                                     KernelScanner::ReportFormat::JSON,
                                     "./scan_report.json");
    
    std::cout << "\nRapport généré: ./scan_report.json" << std::endl;
    
    return 0;
}
```