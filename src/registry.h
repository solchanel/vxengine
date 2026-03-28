#pragma once
/**
 * VXEngine In-Memory Windows Registry Hive
 *
 * Provides a fully in-memory registry with:
 *   - Predefined hive roots (HKLM, HKCU, HKCR, HKU)
 *   - Handle-based open/close/create/delete key operations
 *   - Value read/write/enumerate operations
 *   - Case-insensitive key and value name lookup
 *   - Default entries that defeat common VM/sandbox detection
 *   - Access logging for behavioral analysis
 */

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <cstdint>
#include <algorithm>
#include <cctype>

namespace vx {

// Case-insensitive string comparator for registry paths/names
struct CaseInsensitiveLess {
    bool operator()(const std::string& a, const std::string& b) const {
        std::string la = a, lb = b;
        std::transform(la.begin(), la.end(), la.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        std::transform(lb.begin(), lb.end(), lb.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return la < lb;
    }
};

struct RegistryValue {
    uint32_t type;  // REG_SZ=1, REG_EXPAND_SZ=2, REG_BINARY=3, REG_DWORD=4, REG_MULTI_SZ=7, REG_QWORD=11
    std::vector<uint8_t> data;
};

struct RegistryKey {
    std::string name;
    std::map<std::string, RegistryValue, CaseInsensitiveLess> values;
    std::map<std::string, std::unique_ptr<RegistryKey>, CaseInsensitiveLess> subkeys;
};

class Registry {
public:
    Registry();

    // Predefined hive handles (match Windows constants)
    static constexpr uint32_t HKEY_CLASSES_ROOT  = 0x80000000;
    static constexpr uint32_t HKEY_CURRENT_USER  = 0x80000001;
    static constexpr uint32_t HKEY_LOCAL_MACHINE = 0x80000002;
    static constexpr uint32_t HKEY_USERS         = 0x80000003;

    // Handle-based access (returns handle, or 0 on failure)
    uint32_t open_key(uint32_t parent_handle, const std::string& subkey_path);
    uint32_t create_key(uint32_t parent_handle, const std::string& subkey_path);
    void close_key(uint32_t handle);
    bool delete_key(uint32_t parent_handle, const std::string& subkey_name);

    // Value operations
    bool query_value(uint32_t key_handle, const std::string& value_name,
                     uint32_t* out_type, std::vector<uint8_t>* out_data);
    bool set_value(uint32_t key_handle, const std::string& value_name,
                   uint32_t type, const std::vector<uint8_t>& data);
    bool enum_key(uint32_t key_handle, uint32_t index, std::string* out_name);
    bool enum_value(uint32_t key_handle, uint32_t index,
                    std::string* out_name, uint32_t* out_type,
                    std::vector<uint8_t>* out_data);

    // Access log for behavioral report
    struct RegAccess {
        std::string operation;
        std::string key_path;
        std::string value_name;
    };
    const std::vector<RegAccess>& access_log() const { return log_; }

private:
    RegistryKey hklm_, hkcu_, hkcr_, hku_;
    std::map<uint32_t, std::pair<RegistryKey*, std::string>> open_handles_;
    uint32_t next_handle_ = 0x80001000;
    std::vector<RegAccess> log_;

    void populate_defaults();
    RegistryKey* resolve_path(RegistryKey* root, const std::string& path,
                              bool create_if_missing = false);
    RegistryKey* handle_to_key(uint32_t handle);
    RegistryKey* hive_for_predefined(uint32_t predefined_handle);
    std::string handle_to_path(uint32_t handle);

    // Helper: split path by backslash
    static std::vector<std::string> split_path(const std::string& path);
};

} // namespace vx
