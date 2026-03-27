#pragma once
/**
 * VXEngine Shadow PTE Virtual Memory Manager
 *
 * EPT-style split-view memory:
 *   - Execute view: CPU instruction fetches see hooked code
 *   - Read view: Data reads see original unmodified code
 *   - Completely invisible to integrity checks
 *
 * Features:
 *   - Split-view pages (stealth hooks)
 *   - Copy-on-write
 *   - Watchpoints (address range monitoring)
 *   - Fake VirtualQuery attributes
 *   - Memory access logging
 */

#include "vxengine.h"
#include <unordered_map>
#include <mutex>
#include <algorithm>

namespace vx {

class VirtualMemory {
public:
    VirtualMemory() = default;
    ~VirtualMemory() = default;

    // No copy, allow move
    VirtualMemory(const VirtualMemory&) = delete;
    VirtualMemory& operator=(const VirtualMemory&) = delete;
    VirtualMemory(VirtualMemory&&) = default;
    VirtualMemory& operator=(VirtualMemory&&) = default;

    // ===== Basic memory operations =====

    /// Map a new memory region with given permissions
    bool map(uint64_t addr, uint64_t size, uint8_t perms = PERM_RWX);

    /// Unmap a memory region
    bool unmap(uint64_t addr, uint64_t size);

    /// Check if an address is mapped
    bool is_mapped(uint64_t addr) const;

    /// Read bytes from memory (respects split-view: returns read_view for split pages)
    bool read(uint64_t addr, void* buf, size_t size) const;

    /// Read bytes as instruction fetch (returns exec_view for split pages)
    bool fetch(uint64_t addr, void* buf, size_t size) const;

    /// Write bytes to memory (writes to exec_view for split pages)
    bool write(uint64_t addr, const void* buf, size_t size);

    /// Change permissions on a region
    bool protect(uint64_t addr, uint64_t size, uint8_t perms);

    /// Get page entry (for inspection)
    const PageEntry* get_page(uint64_t addr) const;

    // ===== SHADOW PTE: Split-View Pages (THE KEY FEATURE) =====

    /// Convert a page into a split-view page.
    /// After this call:
    ///   - fetch() returns exec_view (modifiable, for hooks)
    ///   - read()  returns read_view (frozen original, passes integrity checks)
    bool split_page(uint64_t addr);

    /// Unsplit a page (merge exec_view back, remove read_view)
    bool unsplit_page(uint64_t addr);

    /// Check if a page is split
    bool is_split(uint64_t addr) const;

    /// Install a stealth hook: writes hook_bytes to exec_view ONLY.
    /// Data reads still return original bytes.
    /// Example: install_stealth_hook(0x401000, {0xE9, ...}) for JMP
    bool install_stealth_hook(uint64_t addr, const std::vector<uint8_t>& hook_bytes);

    /// Install stealth INT3 (CC) at addr. Invisible to integrity checks.
    /// Like an unlimited hardware breakpoint.
    bool install_stealth_int3(uint64_t addr);

    /// Remove stealth hook at addr (restore exec_view from original)
    bool remove_stealth_hook(uint64_t addr, size_t size);

    /// Full stealth protection for a region:
    /// Splits all pages, sets fake VQ attrs, prepares for hooking
    bool protect_region(uint64_t addr, uint64_t size);

    // ===== FAKE MEMORY ATTRIBUTES =====

    /// Set fake VirtualQuery results for a page
    void set_fake_attrs(uint64_t addr, uint32_t protect, uint32_t type);

    /// Get fake attrs (returns true if faked, fills out_protect/out_type)
    bool get_fake_attrs(uint64_t addr, uint32_t& out_protect, uint32_t& out_type) const;

    // ===== COPY-ON-WRITE =====

    /// Mark pages as COW. First write creates a private copy.
    bool cow_protect(uint64_t addr, uint64_t size);

    // ===== WATCHPOINTS =====

    struct Watchpoint {
        uint64_t addr;
        uint64_t size;
        AccessType type;
        MemCallback callback;
        bool enabled = true;
    };

    /// Set a watchpoint on a memory range
    HookID add_watchpoint(uint64_t addr, uint64_t size,
                          MemCallback callback,
                          AccessType type = AccessType::WRITE);

    /// Remove a watchpoint
    bool remove_watchpoint(HookID id);

    /// Enable/disable a watchpoint
    void enable_watchpoint(HookID id, bool enable);

    /// Fire watchpoints for an access (called by CPU engine)
    bool fire_watchpoints(uint64_t addr, uint32_t size,
                          uint64_t value, AccessType type);

    // ===== MEMORY ACCESS LOG =====

    /// Enable/disable access logging
    void set_logging(bool enable);

    /// Get access log
    const std::vector<MemAccess>& access_log() const { return access_log_; }

    /// Clear access log
    void clear_log() { access_log_.clear(); }

    // ===== BULK OPERATIONS =====

    /// Read a DWORD
    uint32_t read32(uint64_t addr) const;

    /// Read a QWORD
    uint64_t read64(uint64_t addr) const;

    /// Write a DWORD
    void write32(uint64_t addr, uint32_t val);

    /// Write a QWORD
    void write64(uint64_t addr, uint64_t val);

    /// Read a null-terminated string
    std::string read_string(uint64_t addr, size_t max_len = 4096) const;

    /// Write a string (with null terminator)
    void write_string(uint64_t addr, const std::string& str);

    /// Fill memory with a byte value
    void memset(uint64_t addr, uint8_t val, size_t size);

    /// Copy memory within virtual space
    void memcpy(uint64_t dst, uint64_t src, size_t size);

    // ===== INSPECTION =====

    /// Dump all mapped regions
    std::vector<std::pair<uint64_t, uint64_t>> mapped_regions() const;

    /// Get total mapped bytes
    size_t total_mapped() const;

    /// Get all split pages
    std::vector<uint64_t> split_pages() const;

    /// Get all watchpoints
    std::vector<Watchpoint> watchpoints() const;

private:
    /// Page table: page-aligned address -> PageEntry
    std::unordered_map<uint64_t, PageEntry> pages_;

    /// Watchpoints
    std::unordered_map<HookID, Watchpoint> watchpoints_;
    HookID next_wp_id_ = 1;

    /// Access log
    std::vector<MemAccess> access_log_;
    bool logging_enabled_ = false;

    /// Get or create page
    PageEntry& ensure_page(uint64_t addr);

    /// Get page for address (nullptr if not mapped)
    PageEntry* find_page(uint64_t addr);
    const PageEntry* find_page(uint64_t addr) const;

    /// Log a memory access
    void log_access(uint64_t addr, uint32_t size, uint64_t value,
                    uint64_t old_value, AccessType type);
};

} // namespace vx
