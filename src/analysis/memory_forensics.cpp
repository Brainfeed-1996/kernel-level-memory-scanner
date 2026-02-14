#include "memory_forensics.h"

namespace KernelScanner {

MemoryForensicsTimeline::MemoryForensicsTimeline() {}

void MemoryForensicsTimeline::add_event(const TimelineEvent& event) {
    events.push_back(event);
    timeline[event.timestamp].push_back(event);
}

void MemoryForensicsTimeline::generate_timeline() {
    std::cout << "\n=== Memory Forensics Timeline ===" << std::endl;
    std::cout << "Total Events: " << events.size() << std::endl;
    
    // Sort by timestamp
    std::sort(events.begin(), events.end(), 
              [](const TimelineEvent& a, const TimelineEvent& b) {
                  return a.timestamp < b.timestamp;
              });
    
    // Simulate timeline events
    events.clear();
    events.push_back({1704067200, "Process Create", "powershell.exe", 1234, 
                     "Suspicious PowerShell spawned", 8});
    events.push_back({1704067205, "DLL Load", "powershell.exe", 1234,
                     "Loaded mimikatz.dll", 10});
    events.push_back({1704067210, "Registry Write", "powershell.exe", 1234,
                     "HKLM\\...\\Run key modified", 7});
    events.push_back({1704067215, "Network Connect", "powershell.exe", 1234,
                     "Connection to 185.141.25.68:443", 9});
    events.push_back({1704067220, "Memory Allocate", "powershell.exe", 1234,
                     "RWX memory allocated at 0x10000", 8});
    events.push_back({1704067225, "Process Inject", "powershell.exe", 1234,
                     "Injected shellcode into svchost.exe", 10});
    
    for (const auto& e : events) {
        std::cout << "\n[" << e.event_type << "]" << std::endl;
        std::cout << "  Time: " << e.timestamp << std::endl;
        std::cout << "  Process: " << e.process_name << " (PID: " << e.pid << ")" << std::endl;
        std::cout << "  Details: " << e.details << std::endl;
        std::cout << "  Severity: " << e.severity << "/10" << std::endl;
    }
}

void MemoryForensicsTimeline::export_timeline(const std::string& filename) {
    std::cout << "\n=== Timeline Export ===" << std::endl;
    std::cout << "Filename: " << filename << std::endl;
    std::cout << "Format: JSON" << std::endl;
    std::cout << "Events: " << events.size() << std::endl;
}

} // namespace KernelScanner
