#pragma once
/**
 * VXEngine Virtual Filesystem Layer
 *
 * Provides a sandboxed filesystem for emulated binaries:
 *   - Pre-populated fake files (hosts, system dirs)
 *   - File open/read/write/close with handle tracking
 *   - FindFirstFile/FindNextFile pattern matching
 *   - Host file mapping (lazy-load real files into VFS)
 *   - Full access logging for behavioral analysis
 */

#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <fstream>

namespace vx {

class VirtualFileSystem {
public:
    VirtualFileSystem();

    // ===== Configuration =====

    /// Add a virtual file with binary content
    void add_file(const std::string& path, const std::vector<uint8_t>& content);

    /// Add a virtual file with text content
    void add_file(const std::string& path, const std::string& text_content);

    /// Add a virtual directory
    void add_directory(const std::string& path);

    /// Map a virtual path to a real host file (lazy-loaded on first access)
    void map_host_file(const std::string& virt_path, const std::string& host_path);

    // ===== File operations =====

    static constexpr uint32_t INVALID_HANDLE = 0xFFFFFFFF;

    /// Open a file. Returns handle or INVALID_HANDLE.
    uint32_t open(const std::string& path, uint32_t desired_access, uint32_t creation_disposition);

    /// Read from an open file. Returns true on success.
    bool read(uint32_t handle, uint8_t* buf, uint32_t count, uint32_t* bytes_read);

    /// Write to an open file. Returns true on success.
    bool write(uint32_t handle, const uint8_t* buf, uint32_t count, uint32_t* bytes_written);

    /// Get file size for an open file handle.
    uint32_t get_size(uint32_t handle);

    /// Set file pointer. method: FILE_BEGIN(0), FILE_CURRENT(1), FILE_END(2).
    bool set_pointer(uint32_t handle, int32_t distance, uint32_t method);

    /// Get current file pointer position.
    uint32_t get_pointer(uint32_t handle);

    /// Close a file handle.
    void close(uint32_t handle);

    /// Check if a file exists in the VFS.
    bool file_exists(const std::string& path);

    /// Get file attributes. Returns INVALID_FILE_ATTRIBUTES (0xFFFFFFFF) if not found.
    uint32_t get_attributes(const std::string& path);

    // ===== FindFirstFile / FindNextFile =====

    /// Start a file search. Returns find handle or INVALID_HANDLE.
    uint32_t find_first(const std::string& pattern, std::string* found_name,
                        uint32_t* attrs, uint32_t* file_size);

    /// Continue a file search. Returns true if another match found.
    bool find_next(uint32_t find_handle, std::string* found_name,
                   uint32_t* attrs, uint32_t* file_size);

    /// Close a find handle.
    void find_close(uint32_t find_handle);

    // ===== Path normalization =====

    /// Normalize a path: lowercase, backslashes, strip prefixes/trailing slashes.
    static std::string normalize(const std::string& path);

    // ===== Access log =====

    struct FileAccess {
        std::string operation;  // "open", "read", "write", "close", "find"
        std::string path;
        uint32_t size;
    };

    const std::vector<FileAccess>& access_log() const { return log_; }

    // ===== Handle validation =====

    /// Check if a handle belongs to VFS (file or find handle).
    bool is_vfs_handle(uint32_t handle) const;

private:
    struct FileEntry {
        std::string normalized_path;
        std::vector<uint8_t> content;
        bool is_directory = false;
        bool read_only = false;
        std::string host_path;  // Non-empty if mapped to host file
    };

    struct OpenFile {
        std::string path;
        uint32_t position = 0;
        uint32_t access = 0;
    };

    struct FindContext {
        std::string pattern;
        std::vector<std::string> matches;
        size_t current_index = 0;
    };

    std::map<std::string, FileEntry> files_;       // normalized path -> entry
    std::map<uint32_t, OpenFile> open_files_;
    std::map<uint32_t, FindContext> find_contexts_;
    uint32_t next_file_handle_ = 0x300;
    uint32_t next_find_handle_ = 0x500;
    std::vector<FileAccess> log_;

    FileEntry* find_entry(const std::string& path);
    bool load_host_file(FileEntry& entry);
    bool matches_pattern(const std::string& name, const std::string& pattern);
    static std::string extract_filename(const std::string& path);
    static std::string extract_directory(const std::string& path);
};

} // namespace vx
