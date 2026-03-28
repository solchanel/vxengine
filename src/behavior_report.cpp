/**
 * VXEngine Behavioral JSON Report — Implementation
 *
 * Manually serializes emulation activity into a structured JSON report
 * without any external JSON library dependency.
 */

#include "behavior_report.h"

namespace vx {

// ============================================================
// Recording methods
// ============================================================

void BehaviorReport::record_api(const std::string& dll, const std::string& func,
                                 uint64_t retval) {
    APICall call;
    call.insn_count = total_insns_;
    call.dll = dll;
    call.func = func;
    call.retval = retval;
    api_calls_.push_back(std::move(call));
}

void BehaviorReport::record_file(const std::string& op, const std::string& path,
                                  uint32_t size) {
    FileRecord rec;
    rec.operation = op;
    rec.path = path;
    rec.size = size;
    file_records_.push_back(std::move(rec));
}

void BehaviorReport::record_registry(const std::string& op, const std::string& key,
                                      const std::string& value) {
    RegistryRecord rec;
    rec.operation = op;
    rec.key_path = key;
    rec.value_name = value;
    registry_records_.push_back(std::move(rec));
}

void BehaviorReport::record_network(const std::string& type, const std::string& host,
                                     uint16_t port, const std::string& url,
                                     const std::string& method) {
    NetworkRecord rec;
    rec.type = type;
    rec.host = host;
    rec.port = port;
    rec.url = url;
    rec.method = method;
    network_records_.push_back(std::move(rec));
}

void BehaviorReport::record_memory(const std::string& op, uint64_t addr,
                                    uint32_t size, uint32_t prot) {
    MemoryRecord rec;
    rec.operation = op;
    rec.address = addr;
    rec.size = size;
    rec.protection = prot;
    memory_records_.push_back(std::move(rec));
}

// ============================================================
// Clear
// ============================================================

void BehaviorReport::clear() {
    sample_name_.clear();
    total_insns_ = 0;
    api_calls_.clear();
    file_records_.clear();
    registry_records_.clear();
    network_records_.clear();
    memory_records_.clear();
}

// ============================================================
// JSON helpers
// ============================================================

std::string BehaviorReport::escape_json(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"':  out << "\\\""; break;
            case '\n': out << "\\n";  break;
            case '\r': out << "\\r";  break;
            case '\t': out << "\\t";  break;
            default:
                if (c < 0x20) {
                    // Control character -> \uXXXX
                    out << "\\u"
                        << std::hex << std::setw(4) << std::setfill('0')
                        << static_cast<unsigned>(c);
                } else {
                    out << c;
                }
                break;
        }
    }
    return out.str();
}

std::string BehaviorReport::to_hex(uint64_t val) {
    std::ostringstream ss;
    ss << "0x" << std::hex << val;
    return ss.str();
}

// ============================================================
// JSON serialization
// ============================================================

std::string BehaviorReport::to_json() const {
    std::ostringstream js;
    js << "{\n";

    // --- analysis section ---
    js << "  \"analysis\": {\n";
    js << "    \"sample\": \"" << escape_json(sample_name_) << "\",\n";
    js << "    \"total_instructions\": " << total_insns_ << ",\n";
    js << "    \"total_api_calls\": " << api_calls_.size() << "\n";
    js << "  },\n";

    // --- api_calls ---
    js << "  \"api_calls\": [\n";
    for (size_t i = 0; i < api_calls_.size(); ++i) {
        const auto& c = api_calls_[i];
        js << "    {\n";
        js << "      \"dll\": \"" << escape_json(c.dll) << "\",\n";
        js << "      \"function\": \"" << escape_json(c.func) << "\",\n";
        js << "      \"return_value\": \"" << to_hex(c.retval) << "\"\n";
        js << "    }";
        if (i + 1 < api_calls_.size()) js << ",";
        js << "\n";
    }
    js << "  ],\n";

    // --- file_activity ---
    js << "  \"file_activity\": [\n";
    for (size_t i = 0; i < file_records_.size(); ++i) {
        const auto& f = file_records_[i];
        js << "    {\n";
        js << "      \"operation\": \"" << escape_json(f.operation) << "\",\n";
        js << "      \"path\": \"" << escape_json(f.path) << "\",\n";
        js << "      \"size\": " << f.size << "\n";
        js << "    }";
        if (i + 1 < file_records_.size()) js << ",";
        js << "\n";
    }
    js << "  ],\n";

    // --- registry_activity ---
    js << "  \"registry_activity\": [\n";
    for (size_t i = 0; i < registry_records_.size(); ++i) {
        const auto& r = registry_records_[i];
        js << "    {\n";
        js << "      \"operation\": \"" << escape_json(r.operation) << "\",\n";
        js << "      \"key\": \"" << escape_json(r.key_path) << "\",\n";
        js << "      \"value\": \"" << escape_json(r.value_name) << "\"\n";
        js << "    }";
        if (i + 1 < registry_records_.size()) js << ",";
        js << "\n";
    }
    js << "  ],\n";

    // --- network_iocs ---
    js << "  \"network_iocs\": [\n";
    for (size_t i = 0; i < network_records_.size(); ++i) {
        const auto& n = network_records_[i];
        js << "    {\n";
        js << "      \"type\": \"" << escape_json(n.type) << "\",\n";
        js << "      \"host\": \"" << escape_json(n.host) << "\",\n";
        js << "      \"port\": " << n.port << ",\n";
        js << "      \"url\": \"" << escape_json(n.url) << "\",\n";
        js << "      \"method\": \"" << escape_json(n.method) << "\"\n";
        js << "    }";
        if (i + 1 < network_records_.size()) js << ",";
        js << "\n";
    }
    js << "  ],\n";

    // --- memory_activity ---
    js << "  \"memory_activity\": [\n";
    for (size_t i = 0; i < memory_records_.size(); ++i) {
        const auto& m = memory_records_[i];
        js << "    {\n";
        js << "      \"operation\": \"" << escape_json(m.operation) << "\",\n";
        js << "      \"address\": \"" << to_hex(m.address) << "\",\n";
        js << "      \"size\": " << m.size << ",\n";
        js << "      \"protection\": " << m.protection << "\n";
        js << "    }";
        if (i + 1 < memory_records_.size()) js << ",";
        js << "\n";
    }
    js << "  ]\n";

    js << "}\n";
    return js.str();
}

// ============================================================
// File export
// ============================================================

bool BehaviorReport::export_json(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) {
        return false;
    }
    file << to_json();
    return file.good();
}

} // namespace vx
