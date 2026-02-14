#ifndef YARA_COMPILER_H
#define YARA_COMPILER_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class YARACompiler {
public:
    struct YARARule {
        std::string name;
        std::string namespace_name;
        std::string rule_content;
        std::vector<std::string> strings;
        std::string condition;
        bool compiled;
    };
    
    YARACompiler();
    YARARule create_rule(const std::string& name, const std::string& content);
    bool compile_rule(YARARule& rule);
    bool scan_file(const std::string& file_path, const std::vector<YARARule>& rules);
    void print_compilation_result(const YARARule& rule);

private:
    std::vector<YARARule> compiled_rules;
};

} // namespace KernelScanner

#endif
