#ifndef MEMORY_FORENSICS_H
#define MEMORY_FORENSICS_H

#include <iostream>
#include <string>
#include <vector>
#include <map>

namespace KernelScanner {

class MemoryForensicsTimeline {
public:
    struct TimelineEvent {
        uint64_t timestamp;
        std::string event_type;
        std::string process_name;
        uint32_t pid;
        std::string details;
        int severity; // 0-10
    };
    
    MemoryForensicsTimeline();
    void add_event(const TimelineEvent& event);
    void generate_timeline();
    void export_timeline(const std::string& filename);

private:
    std::vector<TimelineEvent> events;
    std::map<uint64_t, std::vector<TimelineEvent>> timeline;
};

} // namespace KernelScanner

#endif
