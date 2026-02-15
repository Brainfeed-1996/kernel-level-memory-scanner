# Guide de Contribution

## Table des Matières
1. [Introduction](#1-introduction)
2. [Environnement de Développement](#2-environnement-de-développement)
3. [Structure du Projet](#3-structure-du-projet)
4. [Processus de Contribution](#4-processus-de-contribution)
5. [Standards de Code](#5-standards-de-code)
6. [Tests](#6-tests)
7. [Documentation](#7-documentation)
8. [Soumettre une Pull Request](#8-soumettre-une-pull-request)

---

## 1. Introduction

Merci de votre intérêt pour contribuer au **Kernel-Level Memory Scanner**! Ce document fournit les lignes directrices pour contribuer au projet.

### 1.1 Types de Contributions Bienvenues

- 🐛 **Rapports de bugs** et corrections
- ✨ **Nouvelles fonctionnalités** et améliorations
- 📚 **Documentation** et traductions
- 🎨 **Améliorations UI/UX**
- ⚡ **Optimisations de performance**
- 🧪 **Tests** et validation

---

## 2. Environnement de Développement

### 2.1 Outils Requis

```bash
# Compilateurs
- GCC 11+ (Linux)
- Clang 14+ (macOS/Linux)
- MSVC 2019+ (Windows)

# Build System
- CMake 3.16+
- Git

# Outils de développement
- Doxygen (documentation)
- clang-tidy (analyse statique)
- cppcheck (analyse statique)
```

### 2.2 Installation de l'Environnement

```bash
# Cloner le repository
git clone https://github.com/Brainfeed-1996/kernel-level-memory-scanner.git
cd kernel-level-memory-scanner

# Créer l'environnement de développement
./scripts/setup_dev_env.sh

# Installer les dépendances
./scripts/install_deps.sh
```

### 2.3 Configuration IDE

#### Visual Studio Code
```json
{
  "C_Cpp.default.compilerPath": "/usr/bin/g++",
  "C_Cpp.codeAnalysis.clangtidy.enabled": true,
  "cmake.configureSettings": {
    "CMAKE_BUILD_TYPE": "Debug"
  }
}
```

#### CLion
- Ouvrir le projet CMake
- Configurer le build type en Debug
- Activer les tests unitaires

---

## 3. Structure du Projet

```
kernel-level-memory-scanner/
├── include/
│   ├── memory_scanner.h
│   ├── scanner_config.h
│   ├── detection/
│   │   ├── code_injection.h
│   │   ├── process_hollowing.h
│   │   ├── rootkit_detector.h
│   │   └── ...
│   ├── analysis/
│   │   ├── memory_forensics.h
│   │   ├── network_analyzer.h
│   │   └── ...
│   └── utils/
│       ├── yara_wrapper.h
│       ├── ml_engine.h
│       └── ...
├── src/
│   ├── memory_scanner.cpp
│   ├── scanner_config.cpp
│   ├── detection/
│   │   ├── code_injection.cpp
│   │   └── ...
│   └── ...
├── tests/
│   ├── unit_tests/
│   ├── integration_tests/
│   └── e2e_tests/
├── CMakeLists.txt
├── docs/
│   ├── ARCHITECTURE.md
│   ├── FEATURES.md
│   ├── USAGE.md
│   └── API.md
├── scripts/
├── tools/
└── README.md
```

### 3.1 Conventions de Nommage

| Type | Convention | Exemple |
|------|-----------|---------|
| Classes | PascalCase | `CodeInjectionDetector` |
| Fonctions | snake_case | `detect_injection()` |
| Variables | snake_case | `detection_count` |
| Constantes | UPPER_SNAKE_CASE | `MAX_THREADS` |
| Headers | snake_case | `code_injection.h` |
| Namespaces | snake_case | `kernel_scanner` |

---

## 4. Processus de Contribution

### 4.1 Workflow Git

```bash
# 1. Créer une branche
git checkout -b feature/my-new-feature

# 2. Faire les modifications
# ... code, tests, documentation ...

# 3. Commit avec un message descriptif
git add .
git commit -m "feat(detection): add new syscall hooking detection module

- Implement syscall number verification
- Add function address validation
- Include unit tests with 100% coverage
- Update documentation

Closes #123"

# 4. Pusher sur votre fork
git push origin feature/my-new-feature

# 5. Créer une Pull Request
```

### 4.2 Conventions de Commit

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

#### Types de Commit
- `feat`: Nouvelle fonctionnalité
- `fix`: Correction de bug
- `docs`: Changements de documentation
- `style`: Formatage de code
- `refactor`: Refactorisation
- `test`: Ajout de tests
- `perf`: Optimisation de performance
- `chore`: Tâches de maintenance

#### Exemples
```
feat(detection): add ransomware encryption detection
fix(kernel): resolve null pointer in callback enumeration
docs(readme): update installation instructions
refactor(analysis): improve memory carving efficiency
test(injection): add comprehensive unit tests
perf(yara): optimize rule matching algorithm
```

---

## 5. Standards de Code

### 5.1 Style C++20

```cpp
// ✅ Bon
class CodeInjectionDetector {
public:
    explicit CodeInjectionDetector(const ScannerConfig& config) 
        : config_(config) {}
    
    auto detect() -> std::vector<InjectionDetection> {
        auto detections = std::vector<InjectionDetection>{};
        // Implementation
        return detections;
    }

private:
    const ScannerConfig& config_;
    static constexpr size_t MAX_BUFFER_SIZE = 4096;
};

// ❌ Mauvais
class codeInjectionDetector {
public:
    codeInjectionDetector(const ScannerConfig& config) {
        this->config = config;
    }
    
    std::vector<InjectionDetection> detect() {
        std::vector<InjectionDetection> detections;
        // Implementation
        return detections;
    }
    
private:
    ScannerConfig config;
};
```

### 5.2 Modern C++20 Features

```cpp
// Concepts
template <typename T>
concept Scannable = requires(T t) {
    t.scan();
    t.get_result();
};

// Ranges
auto results = processes 
    | std::views::filter([](const auto& p) { return p.is_suspicious(); })
    | std::views::transform([](const auto& p) { return p.analyze(); });

// std::format
auto message = std::format("Detection: {} (confidence: {:.1f}%)", 
                          name, confidence);

// constexpr std::string_view
constexpr auto MODULE_NAME = "CodeInjectionDetector";
```

### 5.3 Gestion des Erreurs

```cpp
// ✅ Bon - Utilisation de std::expected (C++23) ou std::optional
auto detect_injection(uint32_t pid) -> std::optional<DetectionResult> {
    if (!is_valid_pid(pid)) {
        return std::nullopt;
    }
    
    // ...
    return result;
}

// ✅ Bon - Exceptions pour erreurs critiques
void initialize_scanner() {
    if (!allocate_resources()) {
        throw ScannerInitializationError("Failed to allocate memory");
    }
}

// ❌ Mauvais - Codes d'erreur
int detect_injection(uint32_t pid, DetectionResult* result) {
    if (!is_valid_pid(pid)) {
        return ERROR_INVALID_PID;  // Non type-safe
    }
    // ...
    return SUCCESS;
}
```

### 5.4 Documentation du Code

```cpp
/**
 * @brief Detects code injection techniques in a process
 * 
 * This function analyzes memory regions for signs of code injection,
 * including reflective DLL loading, APC injection, and thread hijacking.
 * 
 * @param pid Process ID to analyze
 * @param deep_scan Enable deep analysis (slower but more thorough)
 * @return std::vector<InjectionDetection> List of detected injections
 * 
 * @throws std::invalid_argument If pid is invalid
 * @throws ScannerException If scan fails
 * 
 * @note Requires PROCESS_VM_READ permission on Windows
 * @see CodeInjectionDetector::analyze_process_memory()
 */
auto detect_code_injection(uint32_t pid, bool deep_scan = false) 
    -> std::vector<InjectionDetection>;
```

---

## 6. Tests

### 6.1 Structure des Tests

```
tests/
├── unit_tests/
│   ├── detection/
│   │   ├── test_code_injection.cpp
│   │   ├── test_process_hollowing.cpp
│   │   └── ...
│   ├── analysis/
│   └── utils/
├── integration_tests/
│   ├── test_full_scan.cpp
│   └── test_memory_dump_analysis.cpp
└── e2e_tests/
    └── test_real_system_scan.cpp
```

### 6.2 Exemple de Test Unitaire

```cpp
#include <gtest/gtest.h>
#include <code_injection_detector.h>

using namespace KernelScanner;

class CodeInjectionTest : public ::testing::Test {
protected:
    void SetUp() override {
        detector_ = std::make_unique<CodeInjectionDetector>(config_);
    }
    
    ScannerConfig config_;
    std::unique_ptr<CodeInjectionDetector> detector_;
};

TEST_F(CodeInjectionTest, DetectsReflectiveDLLInjection) {
    // Setup - Inject test payload
    auto test_pid = create_test_process_with_payload();
    
    // Execute
    auto detections = detector_->detect();
    
    // Verify
    ASSERT_FALSE(detections.empty());
    EXPECT_EQ(detections[0].type, InjectionType::REFLECTIVE_DLL);
    EXPECT_GE(detections[0].confidence, 0.95);
}

TEST_F(CodeInjectionTest, NoFalsePositivesOnCleanProcess) {
    auto test_pid = create_clean_process();
    
    auto detections = detector_->detect();
    
    EXPECT_TRUE(detections.empty());
}
```

### 6.3 Exécuter les Tests

```bash
# Créer le build avec les tests
cmake .. -DBUILD_TESTS=ON
cmake --build . --target memory_scanner_tests

# Exécuter tous les tests
ctest --output-on-failure

# Exécuter un test spécifique
./tests/unit_tests/test_code_injection --gtest_filter=CodeInjectionTest.*

# Couverture de code
cmake .. -DCODE_COVERAGE=ON
cmake --build .
cmake --coverage .
```

---

## 7. Documentation

### 7.1 Standards de Documentation

- **README.md**: Vue d'ensemble, installation rapide
- **ARCHITECTURE.md**: Architecture technique détaillée
- **FEATURES.md**: Liste complète des fonctionnalités
- **USAGE.md**: Guide d'utilisation
- **API.md**: Référence API
- **CONTRIBUTING.md**: Guide de contribution
- **CHANGELOG.md**: Historique des modifications

### 7.2 Style de Documentation

```markdown
# Titre Principal

## Sous-section

### Point clé

- Description
-另一个点

```cpp
// Code example
int example();
```

> Note ou avertissement important
```

---

## 8. Soumettre une Pull Request

### 8.1 Checklist Avant Soumission

- [ ] Tests unitaires ajoutés/mis à jour
- [ ] Tests passent localement (`ctest`)
- [ ] Code formatting vérifié (`clang-format`)
- [ ] Analyse statique passée (`clang-tidy`)
- [ ] Documentation mise à jour
- [ ] Changelog mis à jour
- [ ] Messages de commit clairs

### 8.2 Template de Pull Request

```markdown
## Description
Brief description of the changes

## Type de Changement
- [ ] 🐛 Bug fix
- [ ] ✨ New feature
- [ ] 📚 Documentation
- [ ] ⚡ Performance improvement
- [ ] 🔧 Code refactoring

## Tests
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated

## Screenshots (if applicable)
Add screenshots to demonstrate changes

## Related Issues
Closes #123
```

---

## 9. Code of Conduct

### 9.1 Nos Engagements

Dans l'intérêt de favoriser un environnement ouvert et accueillant, nous nous engageons à faire de la participation à ce projet une expérience exempte de harcèlement pour tous, peu importe le niveau d'expérience.

### 9.2 Standards de Comportement

- Utiliser un langage accueillant et inclusif
- Être respectueux des différents points de vue
- Accepter gracieusement les critiques constructives
- Se concentrer sur ce qui est meilleur pour la communauté
- Faire preuve d'empathie envers les autres membres

---

## 10. Contact

- **Repository**: https://github.com/Brainfeed-1996/kernel-level-memory-scanner
- **Issues**: https://github.com/Brainfeed-1996/kernel-level-memory-scanner/issues
- **Discussions**: https://github.com/Brainfeed-1996/kernel-level-memory-scanner/discussions

---

Merci de contribuer à ce projet! 🎉