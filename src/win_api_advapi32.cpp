/**
 * VXEngine advapi32.dll Registry API Stubs
 *
 * Implements:
 *   - In-memory Registry class (hive storage, handle management, defaults)
 *   - 15 advapi32 registry API handlers for the engine.h APIDispatcher
 *     RegOpenKeyExA/W, RegCloseKey, RegQueryValueExA/W, RegSetValueExA/W,
 *     RegCreateKeyExA/W, RegDeleteKeyA/W, RegEnumKeyExA/W, RegEnumValueA/W
 *
 * All handlers follow stdcall convention: the handler adjusts ESP to pop args,
 * then the dispatcher pops the return address and jumps back.
 */

#include "registry.h"
#include "../include/vxengine/engine.h"
#include <cstring>
#include <iostream>

namespace vx {

// ============================================================
// Registry implementation
// ============================================================

Registry::Registry() {
    hklm_.name = "HKEY_LOCAL_MACHINE";
    hkcu_.name = "HKEY_CURRENT_USER";
    hkcr_.name = "HKEY_CLASSES_ROOT";
    hku_.name  = "HKEY_USERS";
    populate_defaults();
}

std::vector<std::string> Registry::split_path(const std::string& path) {
    std::vector<std::string> parts;
    std::string current;
    for (char c : path) {
        if (c == '\\') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }
    return parts;
}

RegistryKey* Registry::hive_for_predefined(uint32_t predefined_handle) {
    switch (predefined_handle) {
        case HKEY_LOCAL_MACHINE: return &hklm_;
        case HKEY_CURRENT_USER:  return &hkcu_;
        case HKEY_CLASSES_ROOT:  return &hkcr_;
        case HKEY_USERS:         return &hku_;
        default: return nullptr;
    }
}

RegistryKey* Registry::resolve_path(RegistryKey* root, const std::string& path,
                                     bool create_if_missing) {
    if (path.empty()) return root;

    auto parts = split_path(path);
    RegistryKey* current = root;

    for (const auto& part : parts) {
        auto it = current->subkeys.find(part);
        if (it != current->subkeys.end()) {
            current = it->second.get();
        } else if (create_if_missing) {
            auto key = std::make_unique<RegistryKey>();
            key->name = part;
            RegistryKey* raw = key.get();
            current->subkeys[part] = std::move(key);
            current = raw;
        } else {
            return nullptr;
        }
    }
    return current;
}

RegistryKey* Registry::handle_to_key(uint32_t handle) {
    // Check predefined handles first
    RegistryKey* hive = hive_for_predefined(handle);
    if (hive) return hive;

    auto it = open_handles_.find(handle);
    if (it != open_handles_.end()) {
        return it->second.first;
    }
    return nullptr;
}

std::string Registry::handle_to_path(uint32_t handle) {
    switch (handle) {
        case HKEY_LOCAL_MACHINE: return "HKLM";
        case HKEY_CURRENT_USER:  return "HKCU";
        case HKEY_CLASSES_ROOT:  return "HKCR";
        case HKEY_USERS:         return "HKU";
        default: break;
    }
    auto it = open_handles_.find(handle);
    if (it != open_handles_.end()) {
        return it->second.second;
    }
    return "<unknown>";
}

uint32_t Registry::open_key(uint32_t parent_handle, const std::string& subkey_path) {
    RegistryKey* parent = handle_to_key(parent_handle);
    if (!parent) return 0;

    RegistryKey* target = resolve_path(parent, subkey_path, false);
    if (!target) return 0;

    uint32_t h = next_handle_++;
    std::string full_path = handle_to_path(parent_handle);
    if (!subkey_path.empty()) {
        full_path += "\\" + subkey_path;
    }
    open_handles_[h] = {target, full_path};

    log_.push_back({"OpenKey", full_path, ""});
    return h;
}

uint32_t Registry::create_key(uint32_t parent_handle, const std::string& subkey_path) {
    RegistryKey* parent = handle_to_key(parent_handle);
    if (!parent) return 0;

    RegistryKey* target = resolve_path(parent, subkey_path, true);
    if (!target) return 0;

    uint32_t h = next_handle_++;
    std::string full_path = handle_to_path(parent_handle);
    if (!subkey_path.empty()) {
        full_path += "\\" + subkey_path;
    }
    open_handles_[h] = {target, full_path};

    log_.push_back({"CreateKey", full_path, ""});
    return h;
}

void Registry::close_key(uint32_t handle) {
    // Don't close predefined handles
    if (handle >= HKEY_CLASSES_ROOT && handle <= HKEY_USERS) return;
    open_handles_.erase(handle);
}

bool Registry::delete_key(uint32_t parent_handle, const std::string& subkey_name) {
    RegistryKey* parent = handle_to_key(parent_handle);
    if (!parent) return false;

    // Find the immediate parent of the target key
    auto parts = split_path(subkey_name);
    if (parts.empty()) return false;

    RegistryKey* container = parent;
    for (size_t i = 0; i + 1 < parts.size(); ++i) {
        auto it = container->subkeys.find(parts[i]);
        if (it == container->subkeys.end()) return false;
        container = it->second.get();
    }

    auto it = container->subkeys.find(parts.back());
    if (it == container->subkeys.end()) return false;

    std::string full_path = handle_to_path(parent_handle) + "\\" + subkey_name;
    log_.push_back({"DeleteKey", full_path, ""});

    container->subkeys.erase(it);
    return true;
}

bool Registry::query_value(uint32_t key_handle, const std::string& value_name,
                            uint32_t* out_type, std::vector<uint8_t>* out_data) {
    RegistryKey* key = handle_to_key(key_handle);
    if (!key) return false;

    auto it = key->values.find(value_name);
    if (it == key->values.end()) return false;

    if (out_type) *out_type = it->second.type;
    if (out_data) *out_data = it->second.data;

    log_.push_back({"QueryValue", handle_to_path(key_handle), value_name});
    return true;
}

bool Registry::set_value(uint32_t key_handle, const std::string& value_name,
                          uint32_t type, const std::vector<uint8_t>& data) {
    RegistryKey* key = handle_to_key(key_handle);
    if (!key) return false;

    key->values[value_name] = {type, data};

    log_.push_back({"SetValue", handle_to_path(key_handle), value_name});
    return true;
}

bool Registry::enum_key(uint32_t key_handle, uint32_t index, std::string* out_name) {
    RegistryKey* key = handle_to_key(key_handle);
    if (!key) return false;

    if (index >= key->subkeys.size()) return false;

    auto it = key->subkeys.begin();
    std::advance(it, index);
    if (out_name) *out_name = it->first;
    return true;
}

bool Registry::enum_value(uint32_t key_handle, uint32_t index,
                           std::string* out_name, uint32_t* out_type,
                           std::vector<uint8_t>* out_data) {
    RegistryKey* key = handle_to_key(key_handle);
    if (!key) return false;

    if (index >= key->values.size()) return false;

    auto it = key->values.begin();
    std::advance(it, index);
    if (out_name) *out_name = it->first;
    if (out_type) *out_type = it->second.type;
    if (out_data) *out_data = it->second.data;
    return true;
}

// ============================================================
// Default registry values (anti-VM / realistic environment)
// ============================================================

// Helper: create a REG_SZ value from a string (includes null terminator)
static RegistryValue make_reg_sz(const std::string& str) {
    RegistryValue val;
    val.type = 1; // REG_SZ
    val.data.assign(str.begin(), str.end());
    val.data.push_back(0); // null terminator
    return val;
}

// Helper: create a REG_DWORD value
static RegistryValue make_reg_dword(uint32_t v) {
    RegistryValue val;
    val.type = 4; // REG_DWORD
    val.data.resize(4);
    std::memcpy(val.data.data(), &v, 4);
    return val;
}

void Registry::populate_defaults() {
    // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
    {
        auto* key = resolve_path(&hklm_,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", true);
        key->values["ProductName"]    = make_reg_sz("Windows 10 Pro");
        key->values["CurrentBuild"]   = make_reg_sz("19045");
        key->values["CurrentVersion"] = make_reg_sz("6.3");
    }

    // HKLM\HARDWARE\DESCRIPTION\System
    {
        auto* key = resolve_path(&hklm_,
            "HARDWARE\\DESCRIPTION\\System", true);
        key->values["SystemBiosVersion"] = make_reg_sz("LENOVO - 1390");
    }

    // HKLM\SOFTWARE\Microsoft\Cryptography
    {
        auto* key = resolve_path(&hklm_,
            "SOFTWARE\\Microsoft\\Cryptography", true);
        key->values["MachineGuid"] = make_reg_sz("a1b2c3d4-e5f6-7890-abcd-ef1234567890");
    }

    // HKLM\SYSTEM\CurrentControlSet\Services (empty, but exists)
    resolve_path(&hklm_, "SYSTEM\\CurrentControlSet\\Services", true);

    // HKLM\SYSTEM\CurrentControlSet\Enum\IDE (exists)
    resolve_path(&hklm_, "SYSTEM\\CurrentControlSet\\Enum\\IDE", true);

    // HKCU\SOFTWARE (exists)
    resolve_path(&hkcu_, "SOFTWARE", true);
}

// ============================================================
// Guest memory helpers
// ============================================================

// Read null-terminated ASCII string from guest memory
static std::string read_guest_string(VirtualMemory& vmem, uint64_t addr,
                                      size_t max_len = 1024) {
    std::string result;
    for (size_t i = 0; i < max_len; ++i) {
        uint8_t ch = 0;
        vmem.read(addr + i, &ch, 1);
        if (ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

// Read null-terminated wide (UTF-16LE) string, return as ASCII
static std::string read_guest_wstring(VirtualMemory& vmem, uint64_t addr,
                                       size_t max_chars = 512) {
    std::string result;
    for (size_t i = 0; i < max_chars; ++i) {
        uint16_t wch = 0;
        vmem.read(addr + i * 2, &wch, 2);
        if (wch == 0) break;
        result += static_cast<char>(wch & 0xFF); // Truncate to ASCII
    }
    return result;
}

// Write ASCII string to guest memory (with null terminator)
static void write_guest_string(VirtualMemory& vmem, uint64_t addr,
                                const std::string& str) {
    vmem.write(addr, str.c_str(), str.size() + 1);
}

// Write wide string to guest memory (UTF-16LE with null terminator)
static void write_guest_wstring(VirtualMemory& vmem, uint64_t addr,
                                 const std::string& str) {
    for (size_t i = 0; i < str.size(); ++i) {
        uint16_t wch = static_cast<uint8_t>(str[i]);
        vmem.write(addr + i * 2, &wch, 2);
    }
    uint16_t null_term = 0;
    vmem.write(addr + str.size() * 2, &null_term, 2);
}

// ============================================================
// Windows error codes used by registry APIs
// ============================================================

static constexpr uint32_t ERROR_SUCCESS        = 0;
static constexpr uint32_t ERROR_FILE_NOT_FOUND = 2;
static constexpr uint32_t ERROR_NO_MORE_ITEMS  = 259;

// REG_CREATED_NEW_KEY disposition
static constexpr uint32_t REG_CREATED_NEW_KEY  = 1;

// ============================================================
// register_advapi32_apis — main entry point
// ============================================================

void register_advapi32_apis(APIDispatcher& api, Registry& reg) {

    // ================================================================
    // RegOpenKeyExA (5 args, 20 bytes)
    // LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions,
    //                    REGSAM samDesired, PHKEY phkResult)
    // ================================================================
    api.register_api("RegOpenKeyExA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // Args are above return address: esp+0 = retaddr, esp+4 = hKey, ...
            uint32_t hKey       = vmem.read32(esp + 4);
            uint32_t lpSubKey   = vmem.read32(esp + 8);
            // ulOptions (esp+12) and samDesired (esp+16) are ignored
            uint32_t phkResult  = vmem.read32(esp + 20);

            std::string subkey = read_guest_string(vmem, lpSubKey);
            uint32_t handle = reg.open_key(hKey, subkey);

            if (handle != 0 && phkResult != 0) {
                vmem.write32(phkResult, handle);
            }

            // Stdcall: pop 5 args
            cpu.set_sp(cpu.sp() + 20);

            return (handle != 0) ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegOpenKeyExW (5 args, 20 bytes)
    // ================================================================
    api.register_api("RegOpenKeyExW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey       = vmem.read32(esp + 4);
            uint32_t lpSubKey   = vmem.read32(esp + 8);
            uint32_t phkResult  = vmem.read32(esp + 20);

            std::string subkey = read_guest_wstring(vmem, lpSubKey);
            uint32_t handle = reg.open_key(hKey, subkey);

            if (handle != 0 && phkResult != 0) {
                vmem.write32(phkResult, handle);
            }

            cpu.set_sp(cpu.sp() + 20);
            return (handle != 0) ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegCloseKey (1 arg, 4 bytes)
    // LONG RegCloseKey(HKEY hKey)
    // ================================================================
    api.register_api("RegCloseKey",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey = vmem.read32(esp + 4);
            reg.close_key(hKey);
            cpu.set_sp(cpu.sp() + 4);
            return ERROR_SUCCESS;
        });

    // ================================================================
    // RegQueryValueExA (6 args, 24 bytes)
    // LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved,
    //                       LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
    // ================================================================
    api.register_api("RegQueryValueExA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey        = vmem.read32(esp + 4);
            uint32_t lpValueName = vmem.read32(esp + 8);
            // lpReserved (esp+12) ignored
            uint32_t lpType      = vmem.read32(esp + 16);
            uint32_t lpData      = vmem.read32(esp + 20);
            uint32_t lpcbData    = vmem.read32(esp + 24);

            std::string value_name = read_guest_string(vmem, lpValueName);

            uint32_t type = 0;
            std::vector<uint8_t> data;
            bool found = reg.query_value(hKey, value_name, &type, &data);

            if (found) {
                if (lpType != 0) {
                    vmem.write32(lpType, type);
                }
                if (lpcbData != 0) {
                    uint32_t buf_size = vmem.read32(lpcbData);
                    vmem.write32(lpcbData, static_cast<uint32_t>(data.size()));
                    if (lpData != 0 && buf_size >= data.size() && !data.empty()) {
                        vmem.write(lpData, data.data(), data.size());
                    }
                }
            }

            cpu.set_sp(cpu.sp() + 24);
            return found ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegQueryValueExW (6 args, 24 bytes)
    // ================================================================
    api.register_api("RegQueryValueExW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey        = vmem.read32(esp + 4);
            uint32_t lpValueName = vmem.read32(esp + 8);
            uint32_t lpType      = vmem.read32(esp + 16);
            uint32_t lpData      = vmem.read32(esp + 20);
            uint32_t lpcbData    = vmem.read32(esp + 24);

            std::string value_name = read_guest_wstring(vmem, lpValueName);

            uint32_t type = 0;
            std::vector<uint8_t> data;
            bool found = reg.query_value(hKey, value_name, &type, &data);

            if (found) {
                if (lpType != 0) {
                    vmem.write32(lpType, type);
                }
                if (lpcbData != 0) {
                    // For wide variant, data size in bytes for REG_SZ is the
                    // wide-char representation size
                    uint32_t wide_size = static_cast<uint32_t>(data.size()) * 2;
                    if (type == 1 || type == 2 || type == 7) {
                        // REG_SZ / REG_EXPAND_SZ / REG_MULTI_SZ: convert to wide bytes
                        uint32_t buf_size = vmem.read32(lpcbData);
                        vmem.write32(lpcbData, wide_size);
                        if (lpData != 0 && buf_size >= wide_size) {
                            // Write data as wide chars (each byte -> uint16_t)
                            for (size_t i = 0; i < data.size(); ++i) {
                                uint16_t wch = data[i];
                                vmem.write(lpData + i * 2, &wch, 2);
                            }
                        }
                    } else {
                        // Binary / DWORD / QWORD: write as-is
                        uint32_t buf_size = vmem.read32(lpcbData);
                        vmem.write32(lpcbData, static_cast<uint32_t>(data.size()));
                        if (lpData != 0 && buf_size >= data.size() && !data.empty()) {
                            vmem.write(lpData, data.data(), data.size());
                        }
                    }
                }
            }

            cpu.set_sp(cpu.sp() + 24);
            return found ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegSetValueExA (6 args, 24 bytes)
    // LONG RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved,
    //                     DWORD dwType, const BYTE* lpData, DWORD cbData)
    // ================================================================
    api.register_api("RegSetValueExA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey        = vmem.read32(esp + 4);
            uint32_t lpValueName = vmem.read32(esp + 8);
            // Reserved (esp+12) ignored
            uint32_t dwType      = vmem.read32(esp + 16);
            uint32_t lpData      = vmem.read32(esp + 20);
            uint32_t cbData      = vmem.read32(esp + 24);

            std::string value_name = read_guest_string(vmem, lpValueName);

            std::vector<uint8_t> data(cbData);
            if (cbData > 0 && lpData != 0) {
                vmem.read(lpData, data.data(), cbData);
            }

            reg.set_value(hKey, value_name, dwType, data);

            cpu.set_sp(cpu.sp() + 24);
            return ERROR_SUCCESS;
        });

    // ================================================================
    // RegSetValueExW (6 args, 24 bytes)
    // ================================================================
    api.register_api("RegSetValueExW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey        = vmem.read32(esp + 4);
            uint32_t lpValueName = vmem.read32(esp + 8);
            uint32_t dwType      = vmem.read32(esp + 16);
            uint32_t lpData      = vmem.read32(esp + 20);
            uint32_t cbData      = vmem.read32(esp + 24);

            std::string value_name = read_guest_wstring(vmem, lpValueName);

            std::vector<uint8_t> data(cbData);
            if (cbData > 0 && lpData != 0) {
                vmem.read(lpData, data.data(), cbData);
            }

            reg.set_value(hKey, value_name, dwType, data);

            cpu.set_sp(cpu.sp() + 24);
            return ERROR_SUCCESS;
        });

    // ================================================================
    // RegCreateKeyExA (9 args, 36 bytes)
    // LONG RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved,
    //     LPSTR lpClass, DWORD dwOptions, REGSAM samDesired,
    //     LPSECURITY_ATTRIBUTES lpSA, PHKEY phkResult, LPDWORD lpdwDisposition)
    // ================================================================
    api.register_api("RegCreateKeyExA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey            = vmem.read32(esp + 4);
            uint32_t lpSubKey        = vmem.read32(esp + 8);
            // Reserved(esp+12), lpClass(esp+16), dwOptions(esp+20),
            // samDesired(esp+24), lpSA(esp+28) ignored
            uint32_t phkResult       = vmem.read32(esp + 32);
            uint32_t lpdwDisposition = vmem.read32(esp + 36);

            std::string subkey = read_guest_string(vmem, lpSubKey);
            uint32_t handle = reg.create_key(hKey, subkey);

            if (handle != 0 && phkResult != 0) {
                vmem.write32(phkResult, handle);
            }
            if (lpdwDisposition != 0) {
                vmem.write32(lpdwDisposition, REG_CREATED_NEW_KEY);
            }

            cpu.set_sp(cpu.sp() + 36);
            return ERROR_SUCCESS;
        });

    // ================================================================
    // RegCreateKeyExW (9 args, 36 bytes)
    // ================================================================
    api.register_api("RegCreateKeyExW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey            = vmem.read32(esp + 4);
            uint32_t lpSubKey        = vmem.read32(esp + 8);
            uint32_t phkResult       = vmem.read32(esp + 32);
            uint32_t lpdwDisposition = vmem.read32(esp + 36);

            std::string subkey = read_guest_wstring(vmem, lpSubKey);
            uint32_t handle = reg.create_key(hKey, subkey);

            if (handle != 0 && phkResult != 0) {
                vmem.write32(phkResult, handle);
            }
            if (lpdwDisposition != 0) {
                vmem.write32(lpdwDisposition, REG_CREATED_NEW_KEY);
            }

            cpu.set_sp(cpu.sp() + 36);
            return ERROR_SUCCESS;
        });

    // ================================================================
    // RegDeleteKeyA (2 args, 8 bytes)
    // LONG RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
    // ================================================================
    api.register_api("RegDeleteKeyA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey     = vmem.read32(esp + 4);
            uint32_t lpSubKey = vmem.read32(esp + 8);

            std::string subkey = read_guest_string(vmem, lpSubKey);
            bool ok = reg.delete_key(hKey, subkey);

            cpu.set_sp(cpu.sp() + 8);
            return ok ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegDeleteKeyW (2 args, 8 bytes)
    // ================================================================
    api.register_api("RegDeleteKeyW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey     = vmem.read32(esp + 4);
            uint32_t lpSubKey = vmem.read32(esp + 8);

            std::string subkey = read_guest_wstring(vmem, lpSubKey);
            bool ok = reg.delete_key(hKey, subkey);

            cpu.set_sp(cpu.sp() + 8);
            return ok ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
        });

    // ================================================================
    // RegEnumKeyExA (8 args, 32 bytes)
    // LONG RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName,
    //     LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass,
    //     LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
    // ================================================================
    api.register_api("RegEnumKeyExA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey      = vmem.read32(esp + 4);
            uint32_t dwIndex   = vmem.read32(esp + 8);
            uint32_t lpName    = vmem.read32(esp + 12);
            uint32_t lpcchName = vmem.read32(esp + 16);
            // lpReserved(esp+20), lpClass(esp+24), lpcchClass(esp+28),
            // lpftLastWriteTime(esp+32) ignored

            std::string name;
            bool ok = reg.enum_key(hKey, dwIndex, &name);

            if (ok) {
                if (lpName != 0) {
                    write_guest_string(vmem, lpName, name);
                }
                if (lpcchName != 0) {
                    vmem.write32(lpcchName, static_cast<uint32_t>(name.size()));
                }
            }

            cpu.set_sp(cpu.sp() + 32);
            return ok ? ERROR_SUCCESS : ERROR_NO_MORE_ITEMS;
        });

    // ================================================================
    // RegEnumKeyExW (8 args, 32 bytes)
    // ================================================================
    api.register_api("RegEnumKeyExW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey      = vmem.read32(esp + 4);
            uint32_t dwIndex   = vmem.read32(esp + 8);
            uint32_t lpName    = vmem.read32(esp + 12);
            uint32_t lpcchName = vmem.read32(esp + 16);

            std::string name;
            bool ok = reg.enum_key(hKey, dwIndex, &name);

            if (ok) {
                if (lpName != 0) {
                    write_guest_wstring(vmem, lpName, name);
                }
                if (lpcchName != 0) {
                    // lpcchName is in characters (not bytes) for W variant
                    vmem.write32(lpcchName, static_cast<uint32_t>(name.size()));
                }
            }

            cpu.set_sp(cpu.sp() + 32);
            return ok ? ERROR_SUCCESS : ERROR_NO_MORE_ITEMS;
        });

    // ================================================================
    // RegEnumValueA (8 args, 32 bytes)
    // LONG RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName,
    //     LPDWORD lpcchValueName, LPDWORD lpReserved, LPDWORD lpType,
    //     LPBYTE lpData, LPDWORD lpcbData)
    // ================================================================
    api.register_api("RegEnumValueA",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey           = vmem.read32(esp + 4);
            uint32_t dwIndex        = vmem.read32(esp + 8);
            uint32_t lpValueName    = vmem.read32(esp + 12);
            uint32_t lpcchValueName = vmem.read32(esp + 16);
            // lpReserved (esp+20) ignored
            uint32_t lpType         = vmem.read32(esp + 24);
            uint32_t lpData         = vmem.read32(esp + 28);
            uint32_t lpcbData       = vmem.read32(esp + 32);

            std::string name;
            uint32_t type = 0;
            std::vector<uint8_t> data;
            bool ok = reg.enum_value(hKey, dwIndex, &name, &type, &data);

            if (ok) {
                if (lpValueName != 0) {
                    write_guest_string(vmem, lpValueName, name);
                }
                if (lpcchValueName != 0) {
                    vmem.write32(lpcchValueName, static_cast<uint32_t>(name.size()));
                }
                if (lpType != 0) {
                    vmem.write32(lpType, type);
                }
                if (lpcbData != 0) {
                    uint32_t buf_size = vmem.read32(lpcbData);
                    vmem.write32(lpcbData, static_cast<uint32_t>(data.size()));
                    if (lpData != 0 && buf_size >= data.size() && !data.empty()) {
                        vmem.write(lpData, data.data(), data.size());
                    }
                }
            }

            cpu.set_sp(cpu.sp() + 32);
            return ok ? ERROR_SUCCESS : ERROR_NO_MORE_ITEMS;
        });

    // ================================================================
    // RegEnumValueW (8 args, 32 bytes)
    // ================================================================
    api.register_api("RegEnumValueW",
        [&reg](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t hKey           = vmem.read32(esp + 4);
            uint32_t dwIndex        = vmem.read32(esp + 8);
            uint32_t lpValueName    = vmem.read32(esp + 12);
            uint32_t lpcchValueName = vmem.read32(esp + 16);
            uint32_t lpType         = vmem.read32(esp + 24);
            uint32_t lpData         = vmem.read32(esp + 28);
            uint32_t lpcbData       = vmem.read32(esp + 32);

            std::string name;
            uint32_t type = 0;
            std::vector<uint8_t> data;
            bool ok = reg.enum_value(hKey, dwIndex, &name, &type, &data);

            if (ok) {
                if (lpValueName != 0) {
                    write_guest_wstring(vmem, lpValueName, name);
                }
                if (lpcchValueName != 0) {
                    vmem.write32(lpcchValueName, static_cast<uint32_t>(name.size()));
                }
                if (lpType != 0) {
                    vmem.write32(lpType, type);
                }
                if (lpcbData != 0) {
                    // For wide string types, report wide byte count
                    uint32_t report_size = static_cast<uint32_t>(data.size());
                    if (type == 1 || type == 2 || type == 7) {
                        report_size *= 2;
                    }
                    uint32_t buf_size = vmem.read32(lpcbData);
                    vmem.write32(lpcbData, report_size);
                    if (lpData != 0 && buf_size >= report_size) {
                        if (type == 1 || type == 2 || type == 7) {
                            // Write as wide chars
                            for (size_t i = 0; i < data.size(); ++i) {
                                uint16_t wch = data[i];
                                vmem.write(lpData + i * 2, &wch, 2);
                            }
                        } else if (!data.empty()) {
                            vmem.write(lpData, data.data(), data.size());
                        }
                    }
                }
            }

            cpu.set_sp(cpu.sp() + 32);
            return ok ? ERROR_SUCCESS : ERROR_NO_MORE_ITEMS;
        });

} // register_advapi32_apis

} // namespace vx
