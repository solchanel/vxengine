#pragma once
/**
 * VXEngine Behavioral JSON Report
 *
 * Records API calls, file/registry/network/memory activity during emulation
 * and exports a structured JSON report. No external JSON library required.
 */

#include <string>
#include <vector>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>

namespace vx {

class BehaviorReport {
public:
    BehaviorReport() = default;

    // API call record
    struct APICall {
        uint64_t insn_count = 0;
        std::string dll;
        std::string func;
        uint64_t retval = 0;
    };

    // File activity record
    struct FileRecord {
        std::string operation;  // "open", "read", "write", "close", "delete", "find"
        std::string path;
        uint32_t size = 0;
    };

    // Registry activity record
    struct RegistryRecord {
        std::string operation;  // "open", "query", "set", "create", "delete", "enum"
        std::string key_path;
        std::string value_name;
    };

    // Network IOC record
    struct NetworkRecord {
        std::string type;       // "connect", "dns", "http_request", "send", "recv"
        std::string host;
        uint16_t port = 0;
        std::string url;
        std::string method;     // "GET", "POST", etc.
    };

    // Memory operation record
    struct MemoryRecord {
        std::string operation;  // "alloc", "free", "protect"
        uint64_t address = 0;
        uint32_t size = 0;
        uint32_t protection = 0;
    };

    // Recording methods
    void record_api(const std::string& dll, const std::string& func, uint64_t retval);
    void record_file(const std::string& op, const std::string& path, uint32_t size = 0);
    void record_registry(const std::string& op, const std::string& key, const std::string& value = "");
    void record_network(const std::string& type, const std::string& host, uint16_t port,
                        const std::string& url = "", const std::string& method = "");
    void record_memory(const std::string& op, uint64_t addr, uint32_t size, uint32_t prot = 0);

    // Set sample info
    void set_sample_name(const std::string& name) { sample_name_ = name; }
    void set_insn_count(uint64_t count) { total_insns_ = count; }

    // Export
    std::string to_json() const;
    bool export_json(const std::string& path) const;

    // Accessors
    const std::vector<APICall>& api_calls() const { return api_calls_; }
    const std::vector<NetworkRecord>& network_iocs() const { return network_records_; }
    size_t api_call_count() const { return api_calls_.size(); }

    // Clear all records
    void clear();

private:
    std::string sample_name_;
    uint64_t total_insns_ = 0;

    std::vector<APICall> api_calls_;
    std::vector<FileRecord> file_records_;
    std::vector<RegistryRecord> registry_records_;
    std::vector<NetworkRecord> network_records_;
    std::vector<MemoryRecord> memory_records_;

    // JSON helpers (no external dependency)
    static std::string escape_json(const std::string& s);
    static std::string to_hex(uint64_t val);
};

} // namespace vx
