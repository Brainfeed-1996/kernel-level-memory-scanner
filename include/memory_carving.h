#ifndef MEMORY_CARVING_H
#define MEMORY_CARVING_H

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>

namespace KernelScanner {

class MemoryCarving {
public:
    struct CarvedObject {
        std::string type;
        uintptr_t address;
        size_t size;
        std::vector<uint8_t> data;
    };
    
    MemoryCarving();
    std::vector<CarvedObject> carve_pe_files();
    std::vector<CarvedObject> carve_urls();
    std::vector<CarvedObject> carve_strings();
    std::vector<CarvedObject> carve_ip_addresses();
    void print_carving_results(const std::vector<CarvedObject>& objects);

private:
    std::vector<CarvedObject> carved_objects;
};

} // namespace KernelScanner

#endif
