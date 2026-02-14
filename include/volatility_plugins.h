#ifndef VOLATILITY_PLUGINS_H
#define VOLATILITY_PLUGINS_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class VolatilityPlugins {
public:
    struct PluginResult {
        std::string plugin_name;
        std::vector<std::map<std::string, std::string>> results;
        bool success;
    };
    
    VolatilityPlugins();
    PluginResult run_pslist();
    PluginResult run_psscan();
    PluginResult run_malfind();
    PluginResult run_ldrmodules();
    PluginResult run_hidden_modules();
    PluginResult run_callbacks();
    void print_results(const PluginResult& result);

private:
    std::string memory_dump_path;
};

} // namespace KernelScanner

#endif
