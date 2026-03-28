/**
 * VXEngine Virtual Filesystem Implementation
 *
 * Sandboxed filesystem with predefined Windows system files,
 * handle-based I/O, glob pattern matching, and access logging.
 */

#include "vfs.h"
#include <cctype>
#include <cstring>
#include <iostream>

namespace vx {

// ============================================================
// Path utilities
// ============================================================

std::string VirtualFileSystem::normalize(const std::string& path) {
    std::string result = path;

    // Convert forward slashes to backslashes
    for (auto& c : result) {
        if (c == '/') c = '\\';
    }

    // Strip common NT/device prefixes
    const char* prefixes[] = { "\\\\?\\", "\\??\\", "\\\\.\\", nullptr };
    for (int i = 0; prefixes[i]; ++i) {
        size_t plen = std::strlen(prefixes[i]);
        if (result.size() >= plen && result.compare(0, plen, prefixes[i]) == 0) {
            result = result.substr(plen);
            break;
        }
    }

    // Lowercase
    for (auto& c : result) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Strip trailing backslash (unless it's the root like "c:\")
    while (result.size() > 3 && result.back() == '\\') {
        result.pop_back();
    }

    return result;
}

std::string VirtualFileSystem::extract_filename(const std::string& path) {
    auto pos = path.rfind('\\');
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

std::string VirtualFileSystem::extract_directory(const std::string& path) {
    auto pos = path.rfind('\\');
    if (pos == std::string::npos) return "";
    return path.substr(0, pos);
}

// ============================================================
// Constructor — populate default filesystem
// ============================================================

VirtualFileSystem::VirtualFileSystem() {
    // Standard Windows directories
    add_directory("c:\\windows");
    add_directory("c:\\windows\\system32");
    add_directory("c:\\windows\\system32\\drivers");
    add_directory("c:\\windows\\system32\\drivers\\etc");
    add_directory("c:\\temp");

    // Standard hosts file
    std::string hosts_content =
        "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
        "#\r\n"
        "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
        "#\r\n"
        "# This file contains the mappings of IP addresses to host names. Each\r\n"
        "# entry should be kept on an individual line. The IP address should\r\n"
        "# be placed in the first column followed by the corresponding host name.\r\n"
        "#\r\n"
        "# localhost name resolution is handled within DNS itself.\r\n"
        "#\t127.0.0.1       localhost\r\n"
        "#\t::1             localhost\r\n"
        "\r\n"
        "127.0.0.1       localhost\r\n";

    add_file("c:\\windows\\system32\\drivers\\etc\\hosts", hosts_content);
}

// ============================================================
// Configuration
// ============================================================

void VirtualFileSystem::add_file(const std::string& path, const std::vector<uint8_t>& content) {
    std::string norm = normalize(path);
    FileEntry entry;
    entry.normalized_path = norm;
    entry.content = content;
    entry.is_directory = false;
    entry.read_only = false;
    files_[norm] = std::move(entry);
}

void VirtualFileSystem::add_file(const std::string& path, const std::string& text_content) {
    std::vector<uint8_t> data(text_content.begin(), text_content.end());
    add_file(path, data);
}

void VirtualFileSystem::add_directory(const std::string& path) {
    std::string norm = normalize(path);
    FileEntry entry;
    entry.normalized_path = norm;
    entry.is_directory = true;
    entry.read_only = true;
    files_[norm] = std::move(entry);
}

void VirtualFileSystem::map_host_file(const std::string& virt_path, const std::string& host_path) {
    std::string norm = normalize(virt_path);
    FileEntry entry;
    entry.normalized_path = norm;
    entry.is_directory = false;
    entry.read_only = true;
    entry.host_path = host_path;
    files_[norm] = std::move(entry);
}

// ============================================================
// File operations
// ============================================================

VirtualFileSystem::FileEntry* VirtualFileSystem::find_entry(const std::string& path) {
    std::string norm = normalize(path);
    auto it = files_.find(norm);
    if (it == files_.end()) return nullptr;
    return &it->second;
}

bool VirtualFileSystem::load_host_file(FileEntry& entry) {
    if (entry.host_path.empty()) return true;  // Nothing to load
    if (!entry.content.empty()) return true;    // Already loaded

    std::ifstream ifs(entry.host_path, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        std::cerr << "[vfs] WARNING: Failed to load host file: " << entry.host_path << "\n";
        return false;
    }

    auto size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    entry.content.resize(static_cast<size_t>(size));
    ifs.read(reinterpret_cast<char*>(entry.content.data()), size);
    return true;
}

uint32_t VirtualFileSystem::open(const std::string& path, uint32_t desired_access,
                                  uint32_t creation_disposition) {
    std::string norm = normalize(path);

    log_.push_back({"open", norm, 0});

    FileEntry* entry = find_entry(norm);

    // Creation disposition constants (Windows):
    // CREATE_NEW(1), CREATE_ALWAYS(2), OPEN_EXISTING(3), OPEN_ALWAYS(4), TRUNCATE_EXISTING(5)
    switch (creation_disposition) {
        case 1: // CREATE_NEW — fail if exists
            if (entry) return INVALID_HANDLE;
            // Create new empty file
            add_file(norm, std::vector<uint8_t>{});
            entry = find_entry(norm);
            break;

        case 2: // CREATE_ALWAYS — create or truncate
            if (entry) {
                entry->content.clear();
            } else {
                add_file(norm, std::vector<uint8_t>{});
                entry = find_entry(norm);
            }
            break;

        case 3: // OPEN_EXISTING — fail if not found
            if (!entry) return INVALID_HANDLE;
            break;

        case 4: // OPEN_ALWAYS — create if needed
            if (!entry) {
                add_file(norm, std::vector<uint8_t>{});
                entry = find_entry(norm);
            }
            break;

        case 5: // TRUNCATE_EXISTING — fail if not found, else truncate
            if (!entry) return INVALID_HANDLE;
            entry->content.clear();
            break;

        default:
            // Treat as OPEN_EXISTING
            if (!entry) return INVALID_HANDLE;
            break;
    }

    if (!entry) return INVALID_HANDLE;

    // Lazy-load host-mapped files
    if (!entry->host_path.empty()) {
        load_host_file(*entry);
    }

    // Allocate handle
    uint32_t handle = next_file_handle_++;
    OpenFile of;
    of.path = norm;
    of.position = 0;
    of.access = desired_access;
    open_files_[handle] = std::move(of);

    return handle;
}

bool VirtualFileSystem::read(uint32_t handle, uint8_t* buf, uint32_t count,
                              uint32_t* bytes_read) {
    auto it = open_files_.find(handle);
    if (it == open_files_.end()) return false;

    OpenFile& of = it->second;
    FileEntry* entry = find_entry(of.path);
    if (!entry || entry->is_directory) return false;

    uint32_t content_size = static_cast<uint32_t>(entry->content.size());
    uint32_t available = (of.position < content_size) ? (content_size - of.position) : 0;
    uint32_t to_read = std::min(count, available);

    if (to_read > 0) {
        std::memcpy(buf, entry->content.data() + of.position, to_read);
        of.position += to_read;
    }

    if (bytes_read) *bytes_read = to_read;

    log_.push_back({"read", of.path, to_read});
    return true;
}

bool VirtualFileSystem::write(uint32_t handle, const uint8_t* buf, uint32_t count,
                               uint32_t* bytes_written) {
    auto it = open_files_.find(handle);
    if (it == open_files_.end()) return false;

    OpenFile& of = it->second;
    FileEntry* entry = find_entry(of.path);
    if (!entry || entry->is_directory) return false;

    // Expand content if needed
    uint32_t end_pos = of.position + count;
    if (end_pos > static_cast<uint32_t>(entry->content.size())) {
        entry->content.resize(end_pos);
    }

    std::memcpy(entry->content.data() + of.position, buf, count);
    of.position += count;

    if (bytes_written) *bytes_written = count;

    log_.push_back({"write", of.path, count});
    return true;
}

uint32_t VirtualFileSystem::get_size(uint32_t handle) {
    auto it = open_files_.find(handle);
    if (it == open_files_.end()) return INVALID_HANDLE;

    FileEntry* entry = find_entry(it->second.path);
    if (!entry) return INVALID_HANDLE;

    return static_cast<uint32_t>(entry->content.size());
}

bool VirtualFileSystem::set_pointer(uint32_t handle, int32_t distance, uint32_t method) {
    auto it = open_files_.find(handle);
    if (it == open_files_.end()) return false;

    OpenFile& of = it->second;
    FileEntry* entry = find_entry(of.path);
    if (!entry) return false;

    int64_t new_pos = 0;
    uint32_t content_size = static_cast<uint32_t>(entry->content.size());

    switch (method) {
        case 0: // FILE_BEGIN
            new_pos = distance;
            break;
        case 1: // FILE_CURRENT
            new_pos = static_cast<int64_t>(of.position) + distance;
            break;
        case 2: // FILE_END
            new_pos = static_cast<int64_t>(content_size) + distance;
            break;
        default:
            return false;
    }

    if (new_pos < 0) new_pos = 0;
    of.position = static_cast<uint32_t>(new_pos);
    return true;
}

uint32_t VirtualFileSystem::get_pointer(uint32_t handle) {
    auto it = open_files_.find(handle);
    if (it == open_files_.end()) return INVALID_HANDLE;
    return it->second.position;
}

void VirtualFileSystem::close(uint32_t handle) {
    auto it = open_files_.find(handle);
    if (it != open_files_.end()) {
        log_.push_back({"close", it->second.path, 0});
        open_files_.erase(it);
    }
}

bool VirtualFileSystem::file_exists(const std::string& path) {
    std::string norm = normalize(path);
    return files_.find(norm) != files_.end();
}

uint32_t VirtualFileSystem::get_attributes(const std::string& path) {
    std::string norm = normalize(path);
    auto it = files_.find(norm);
    if (it == files_.end()) return INVALID_HANDLE; // INVALID_FILE_ATTRIBUTES

    if (it->second.is_directory) return 0x10; // FILE_ATTRIBUTE_DIRECTORY
    return 0x80; // FILE_ATTRIBUTE_NORMAL
}

// ============================================================
// FindFirstFile / FindNextFile
// ============================================================

bool VirtualFileSystem::matches_pattern(const std::string& name, const std::string& pattern) {
    // Simple glob matcher: * matches any sequence, ? matches one char
    // Both name and pattern should already be lowercase
    size_t ni = 0, pi = 0;
    size_t star_p = std::string::npos, star_n = 0;

    while (ni < name.size()) {
        if (pi < pattern.size() && (pattern[pi] == '?' || pattern[pi] == name[ni])) {
            ++ni;
            ++pi;
        } else if (pi < pattern.size() && pattern[pi] == '*') {
            star_p = pi;
            star_n = ni;
            ++pi;
        } else if (star_p != std::string::npos) {
            pi = star_p + 1;
            ++star_n;
            ni = star_n;
        } else {
            return false;
        }
    }

    // Consume trailing *
    while (pi < pattern.size() && pattern[pi] == '*') ++pi;
    return pi == pattern.size();
}

uint32_t VirtualFileSystem::find_first(const std::string& pattern, std::string* found_name,
                                        uint32_t* attrs, uint32_t* file_size) {
    std::string norm_pattern = normalize(pattern);
    std::string dir = extract_directory(norm_pattern);
    std::string file_pattern = extract_filename(norm_pattern);

    log_.push_back({"find", norm_pattern, 0});

    // Collect all matching entries
    FindContext ctx;
    ctx.pattern = norm_pattern;
    ctx.current_index = 0;

    for (const auto& [path, entry] : files_) {
        std::string entry_dir = extract_directory(path);
        std::string entry_name = extract_filename(path);

        if (entry_dir == dir && matches_pattern(entry_name, file_pattern)) {
            ctx.matches.push_back(path);
        }
    }

    if (ctx.matches.empty()) {
        return INVALID_HANDLE;
    }

    // Return the first match
    const std::string& first_path = ctx.matches[0];
    FileEntry* entry = find_entry(first_path);

    if (found_name) *found_name = extract_filename(first_path);
    if (attrs) {
        *attrs = entry->is_directory ? 0x10u : 0x80u;
    }
    if (file_size) {
        *file_size = entry->is_directory ? 0 : static_cast<uint32_t>(entry->content.size());
    }

    ctx.current_index = 1;

    uint32_t find_handle = next_find_handle_++;
    find_contexts_[find_handle] = std::move(ctx);
    return find_handle;
}

bool VirtualFileSystem::find_next(uint32_t find_handle, std::string* found_name,
                                   uint32_t* attrs, uint32_t* file_size) {
    auto it = find_contexts_.find(find_handle);
    if (it == find_contexts_.end()) return false;

    FindContext& ctx = it->second;
    if (ctx.current_index >= ctx.matches.size()) return false;

    const std::string& match_path = ctx.matches[ctx.current_index];
    FileEntry* entry = find_entry(match_path);
    if (!entry) return false;

    if (found_name) *found_name = extract_filename(match_path);
    if (attrs) {
        *attrs = entry->is_directory ? 0x10u : 0x80u;
    }
    if (file_size) {
        *file_size = entry->is_directory ? 0 : static_cast<uint32_t>(entry->content.size());
    }

    ctx.current_index++;
    return true;
}

void VirtualFileSystem::find_close(uint32_t find_handle) {
    find_contexts_.erase(find_handle);
}

// ============================================================
// Handle validation
// ============================================================

bool VirtualFileSystem::is_vfs_handle(uint32_t handle) const {
    return open_files_.count(handle) > 0 || find_contexts_.count(handle) > 0;
}

} // namespace vx
