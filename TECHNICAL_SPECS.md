# 🔧 Spécifications Techniques - API & Architecture Technique

## Table des Matières
1. [Architecture Technique](#architecture-technique)
2. [API Reference](#api-reference)
3. [Spécifications](#spécifications)
4. [Installation Avancée](#installation-avancée)

---

## 1. Architecture Technique

### 1.1 Stack Technique

| Composant | Technologie | Version |
|-----------|-------------|---------|
| **Langage** | C++20 | GCC 13+ / Clang 16+ / MSVC 2022+ |
| **Build System** | CMake | 3.16+ |
| **ML Framework** | PyTorch / TensorFlow | 2.x |
| **Pattern Matching** | YARA | 4.x |
| **Serialization** | nlohmann/json | 3.10+ |
| **Networking** | Boost.Asio / libcurl | 1.75+ |
| **Logging** | spdlog | 1.11+ |

### 1.2 Architecture Modulaire

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Architecture Overview                        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                    INTERFACE LAYER                              ││
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐              ││
│  │  │   CLI   │ │  REST   │ │  gRPC   │ │ Python  │              ││
│  │  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘              ││
│  └───────┼───────────┼───────────┼───────────┼────────────────────┘│
│          │           │           │           │                      │
├──────────┼───────────┼───────────┼───────────┼──────────────────────┤
│          ▼           ▼           ▼           ▼                      │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                   ORCHESTRATION LAYER                          ││
│  │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐             ││
│  │  │  Scanner    │ │  Analyzer   │ │  Reporter   │             ││
│  │  │  Manager    │ │  Pipeline   │ │  Engine     │             ││
│  │  └─────────────┘ └─────────────┘ └─────────────┘             ││
│  └─────────────────────────────────────────────────────────────────┘│
│          │                    │                    │                │
├──────────┼────────────────────┼────────────────────┼────────────────┤
│          ▼                    ▼                    ▼                │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                      CORE MODULES                               ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          ││
│  │  │Detection │ │Analysis  │ │   ML     │ │   TI     │          ││
│  │  │(27 mods) │ │(21 mods) │ │ Engine   │ │ Engine   │          ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘          ││
│  └─────────────────────────────────────────────────────────────────┘│
│          │                    │                    │                │
├──────────┼────────────────────┼────────────────────┼────────────────┤
│          ▼                    ▼                    ▼                │
│  ┌─────────────────────────────────────────────────────────────────┐│
│  │                   PLATFORM LAYER                                ││
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          ││
│  │  │ Windows  │ │  Linux   │ │  macOS   │ │  Cross   │          ││
│  │  │  Kernel  │ │  /dev/   │ │  IOKit   │ │  Abst.   │          ││
│  │  │   DSE    │ │   mem    │ │   PMAP   │ │          │          ││
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘          ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Flux de Données Détaillé

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Data Flow Pipeline                            │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Input      │────▶│  Preprocess  │────▶│   Analysis   │
│  (Memory/    │     │  (Parsing,   │     │  (YARA, ML,  │
│   Process)   │     │   Filtering) │     │   Heuristics)│
└──────────────┘     └──────────────┘     └──────┬───────┘
                                                 │
                    ┌─────────────────────────────┼─────────────┐
                    │                             │             │
                    ▼                             ▼             ▼
           ┌──────────────┐              ┌──────────────┐ ┌──────────┐
           │   Match      │              │  Correlation  │ │   ML    │
           │   Engine     │              │   Engine      │ │ Classify │
           └──────┬───────┘              └──────┬───────┘ └────┬─────┘
                  │                             │              │
                  └─────────────────────────────┼──────────────┘
                                                ▼
                                    ┌──────────────────┐
                                    │   Detection      │
                                    │   Aggregation    │
                                    └────────┬─────────┘
                                             │
                   ┌──────────────────────────┼────────────────────┐
                   │                          │                    │
                   ▼                          ▼                    ▼
           ┌──────────────┐           ┌──────────────┐     ┌──────────────┐
           │   Report     │           │   Alert      │     │    Export   │
           │   Generator  │           │   Manager    │     │   (SIEM)    │
           └──────────────┘           └──────────────┘     └──────────────┘
```

---

## 2. API Reference

### 2.1 Core Classes

#### MemoryScanner

```cpp
namespace KernelScanner {

class MemoryScanner {
public:
    /**
     * @brief Constructeur
     */
    MemoryScanner();
    
    /**
     * @brief Destructeur
     */
    ~MemoryScanner();
    
    /**
     * @brief Initialise le scanner avec la configuration
     * @param config Configuration du scanner
     * @return true si succès
     */
    bool initialize(const ScannerConfig& config);
    
    /**
     * @brief Scan complet du système
     * @return Résultat du scan
     */
    ScanResult full_system_scan();
    
    /**
     * @brief Scan d'un processus spécifique
     * @param pid PID du processus
     * @return Résultat du scan
     */
    ScanResult scan_process(int pid);
    
    /**
     * @brief Scan mémoire d'un processus
     * @param pid PID du processus
     * @param regionType Type de région mémoire
     * @return Résultat du scan mémoire
     */
    MemoryScanResult scan_process_memory(
        int pid, 
        MemoryRegionType regionType = MemoryRegionType::All
    );
    
    /**
     * @brief Scan avec YARA
     * @param target Cible (fichier ou mémoire)
     * @return Résultats YARA
     */
    YaraResult scan_with_yara(const std::string& target);
    
    /**
     * @brief Charge les règles YARA
     * @param rulesPath Chemin vers les règles
     * @return true si succès
     */
    bool load_yara_rules(const std::string& rulesPath);
    
    /**
     * @brief Analyse réseau
     * @return Résultat de l'analyse réseau
     */
    NetworkAnalysisResult scan_network_connections();
    
    /**
     * @brief Génère un rapport forensique
     * @param result Résultat du scan
     * @param format Format du rapport
     * @param outputPath Chemin de sortie
     */
    void generate_forensic_report(
        const ScanResult& result,
        ReportFormat format,
        const std::string& outputPath = ""
    );
    
    /**
     * @brief Retourne les statistiques du scanner
     * @return Statistiques
     */
    ScannerStats get_stats() const;
    
    /**
     * @brief Nettoie les ressources
     */
    void shutdown();
};
} // namespace KernelScanner
```

#### Structures

```cpp
// Configuration du scanner
struct ScannerConfig {
    // Options de scan
    bool enable_deep_scan = false;
    bool use_yara = false;
    bool use_neural_network = false;
    bool enable_c2_detection = false;
    bool use_kernel_mode = false;
    
    // Modules actifs
    std::vector<std::string> enabled_modules;
    
    // Chemins
    std::string yara_rules_path;
    std::string ml_models_path;
    std::string output_path;
    
    // Performance
    int max_threads = 4;
    size_t max_memory_mb = 512;
    
    // Logging
    LogLevel log_level = LogLevel::Info;
    std::string log_file;
};

// Résultat de scan
struct ScanResult {
    std::vector<Detection> detections;
    int64_t scan_duration_ms;
    std::string scan_timestamp;
    std::vector<std::string> iocs;
    std::vector<std::string> mitre_techniques;
    std::map<std::string, std::string> metadata;
    
    // Statistiques
    size_t total_scanned_objects;
    size_t total_matches;
    float average_confidence;
};

// Détection individuelle
struct Detection {
    std::string id;
    std::string type;
    std::string severity;  // info, low, medium, high, critical
    std::string category;  // injection, persistence, rootkit, etc.
    std::string description;
    std::string source_module;
    std::string mitre_technique;
    float confidence;  // 0.0 - 1.0
    std::string recommended_action;
    
    // Métadonnées additionnelles
    std::map<std::string, std::string> metadata;
    std::vector<IOC> iocs;
};

// Indicator of Compromise
struct IOC {
    std::string type;  // ip, domain, hash, registry, file
    std::string value;
    std::string context;
};
```

### 2.2 Enums

```cpp
enum class MemoryRegionType {
    All,
    Private,
    Shared,
    Executable,
    Writable,
    Code
};

enum class ReportFormat {
    JSON,
    XML,
    HTML,
    PDF,
    MISP,
    STIX2_1,
    TAXII2_1
};

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
    Critical
};

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};
```

### 2.3 API REST

#### Endpoints

```
POST /api/v1/scan
    Body: {"target": "process_name|pid|all", "options": {...}}
    Response: {"scan_id": "uuid", "status": "started"}

GET /api/v1/scan/{scan_id}
    Response: {"status": "completed", "result": {...}}

GET /api/v1/detections
    Query: ?severity=high&category=rootkit
    Response: {"detections": [...]}

GET /api/v1/detections/{id}
    Response: {"detection": {...}}

POST /api/v1/yara/scan
    Body: {"target": "...", "rules": "..."}
    Response: {"matches": [...]}

GET /api/v1/stats
    Response: {"scans": N, "detections": N, "uptime": ...}

GET /api/v1/config
    Response: {"config": {...}}

PUT /api/v1/config
    Body: {"config": {...}}
    Response: {"status": "updated"}
```

---

## 3. Spécifications

### 3.1 Performance

| Métrique | Spécification |
|----------|---------------|
| **Full System Scan** | < 30 secondes |
| **Process Scan** | < 2 secondes |
| **Memory Scan** | < 5 secondes par processus |
| **YARA Scan** | > 500 MB/s |
| **ML Inference** | < 100ms par objet |
| **Detection Accuracy** | > 99% |
| **False Positive Rate** | < 0.3% |

### 3.2 Ressources

| Ressource | Minimum | Recommandé |
|-----------|---------|------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 4 GB | 8+ GB |
| **Disk** | 1 GB | 5+ GB |
| **Network** | 100 Mbps | 1 Gbps |

### 3.3 Plateformes Supportées

| OS | Architecture | Status |
|----|--------------|--------|
| **Windows 10/11** | x64 | ✅ Stable |
| **Windows Server 2019+** | x64 | ✅ Stable |
| **Ubuntu 20.04+** | x64, ARM64 | ✅ Stable |
| **Debian 11+** | x64, ARM64 | ✅ Stable |
| **RHEL 8+** | x64 | ✅ Stable |
| **macOS 11+** | x64, ARM64 | ✅ Beta |

### 3.4 Formats Supportés

| Type | Formats |
|------|---------|
| **Mémoire** | raw, lime, affine, hibernation |
| **Fichiers** | PE, ELF, Mach-O, APK |
| **Rapports** | JSON, XML, HTML, PDF, MISP, STIX |
| **Network** | PCAP, NetFlow, DNS queries |

---

## 4. Installation Avancée

### 4.1 Build Custom

```bash
# Configuration avec options avancées
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_YARA=ON \
    -DWITH_ML=ON \
    -DWITH_PYTHON=ON \
    -DWITH_REST_API=ON \
    -DWITH_TLS=ON \
    -DYARA_INCLUDE_PATH=/usr/include \
    -DPYTHON_INCLUDE_PATH=/usr/include/python3.11 \
    -DPYTORCH_INCLUDE_PATH=/usr/include/torch

# Build avec sanitizer (debug)
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined"

# Build minimal
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DWITH_YARA=ON \
    -DWITH_ML=OFF
```

### 4.2 Options CMake

| Option | Description | Défaut |
|--------|-------------|--------|
| `WITH_YARA` | Activer support YARA | ON |
| `WITH_ML` | Activer ML (PyTorch) | ON |
| `WITH_PYTHON` | Activer Python bindings | OFF |
| `WITH_REST_API` | Activer API REST | OFF |
| `WITH_TLS` | Activer TLS/HTTPS | OFF |
| `WITH_TESTS` | Build tests | OFF |
| `WITH_DOCS` | Build documentation | OFF |

### 4.3 Installation Python

```python
# Via pip
pip install kernel-scanner

# Via conda
conda install -c conda-forge kernel-scanner

# Utilisation Python
from kernel_scanner import Scanner

scanner = Scanner()
result = scanner.scan_process("notepad.exe")
print(result.detections)
```

### 4.4 Docker

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libboost-all-dev \
    libyara-dev \
    python3-dev \
    python3-pip \
    libcurl4-openssl-dev

WORKDIR /app
COPY . .
RUN mkdir build && cd build && cmake .. && make

ENTRYPOINT ["./build/kernel-scanner"]
```

```bash
# Build Docker
docker build -t kernel-scanner:latest .

# Run
docker run -it \
    --privileged \
    -v /path/to/rules:/rules \
    kernel-scanner:latest --target all
```

### 4.5 Configuration Avancée

```yaml
# Configuration avancées
scanner:
  # Threading
  threading:
    max_workers: 8
    queue_size: 1000
    timeout_ms: 30000
  
  # Memory
  memory:
    max_heap_mb: 2048
    enable_mmap: true
    prefetch_pages: true
  
  # Detection
  detection:
    confidence_threshold: 0.75
    auto_enable_modules: true
    correlation_enabled: true
    
  # ML
  ml:
    model_path: ./models/detector.pt
    batch_size: 32
    device: cuda  # cpu, cuda, mps
    
  # YARA
  yara:
    rules_dir: ./rules
    cache_enabled: true
    max_rules_memory_mb: 512
    
  # Network
  network:
    capture_packets: false
    dns_analysis: true
    c2_detection: true
```

---

## 5. Tests & Validation

### 5.1 Tests Unitaires

```bash
# Build avec tests
cmake .. -DWITH_TESTS=ON
cmake --build .

# Exécuter tests
ctest --output-on-failure
./tests/scanner_test
```

### 5.2 Benchmarks

```bash
# Run benchmarks
./bin/benchmark --iterations=100 --target=all

# Output
# Memory Scan:     1.2ms avg
# Process Scan:   45ms avg  
# Full System:    28s avg
# YARA Scan:      450 MB/s
# ML Inference:   45ms avg
```

---

## Annexe: References

- [README.md](README.md) - Overview
- [ARCHITECTURE.md](ARCHITECTURE.md) - Architecture
- [FEATURES.md](FEATURES.md) - Features
- [USAGE.md](USAGE.md) - Guide utilisation

---

*Dernière mise à jour: v25.0*
