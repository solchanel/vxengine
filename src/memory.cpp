/**
 * VXEngine Shadow PTE Virtual Memory Manager — Implementation
 *
 * The core innovation: EPT-style split-view pages where CPU instruction
 * fetches see different data than data reads. This makes all hooks
 * completely invisible to the emulated program.
 */

#include "vxengine/memory.h"
#include <cstring>
#include <cassert>
#include <algorithm>

namespace vx {

// ============================================================
// Internal helpers
// ============================================================

PageEntry* VirtualMemory::find_page(uint64_t addr) {
    uint64_t page_addr = addr & PAGE_MASK;
    auto it = pages_.find(page_addr);
    return it != pages_.end() ? &it->second : nullptr;
}

const PageEntry* VirtualMemory::find_page(uint64_t addr) const {
    uint64_t page_addr = addr & PAGE_MASK;
    auto it = pages_.find(page_addr);
    return it != pages_.end() ? &it->second : nullptr;
}

PageEntry& VirtualMemory::ensure_page(uint64_t addr) {
    uint64_t page_addr = addr & PAGE_MASK;
    auto [it, inserted] = pages_.emplace(page_addr, PageEntry{});
    if (inserted) {
        it->second.addr = page_addr;
        it->second.size = PAGE_SIZE;
        it->second.perms = PERM_RWX;
        it->second.data.resize(PAGE_SIZE, 0);
    }
    return it->second;
}

void VirtualMemory::log_access(uint64_t addr, uint32_t size, uint64_t value,
                                uint64_t old_value, AccessType type) {
    if (logging_enabled_) {
        access_log_.push_back({addr, size, value, old_value, type});
    }
}

// ============================================================
// Basic memory operations
// ============================================================

bool VirtualMemory::map(uint64_t addr, uint64_t size, uint8_t perms) {
    addr &= PAGE_MASK;
    size = (size + PAGE_SIZE - 1) & PAGE_MASK;

    for (uint64_t p = addr; p < addr + size; p += PAGE_SIZE) {
        auto& page = ensure_page(p);
        page.perms = perms;
        page.data.resize(PAGE_SIZE, 0);
    }
    return true;
}

bool VirtualMemory::unmap(uint64_t addr, uint64_t size) {
    addr &= PAGE_MASK;
    size = (size + PAGE_SIZE - 1) & PAGE_MASK;

    for (uint64_t p = addr; p < addr + size; p += PAGE_SIZE) {
        pages_.erase(p);
    }
    return true;
}

bool VirtualMemory::is_mapped(uint64_t addr) const {
    return find_page(addr) != nullptr;
}

bool VirtualMemory::read(uint64_t addr, void* buf, size_t size) const {
    uint8_t* out = static_cast<uint8_t*>(buf);

    while (size > 0) {
        const PageEntry* page = find_page(addr);
        if (!page) return false;

        uint32_t offset = addr & (PAGE_SIZE - 1);
        uint32_t chunk = std::min<uint32_t>(static_cast<uint32_t>(size),
                                             PAGE_SIZE - offset);

        // KEY: For split pages, data reads return read_view (original bytes)
        if (page->split && !page->read_view.empty()) {
            std::memcpy(out, page->read_view.data() + offset, chunk);
        } else {
            std::memcpy(out, page->data.data() + offset, chunk);
        }

        addr += chunk;
        out += chunk;
        size -= chunk;
    }
    return true;
}

bool VirtualMemory::fetch(uint64_t addr, void* buf, size_t size) const {
    uint8_t* out = static_cast<uint8_t*>(buf);

    while (size > 0) {
        const PageEntry* page = find_page(addr);
        if (!page) return false;

        uint32_t offset = addr & (PAGE_SIZE - 1);
        uint32_t chunk = std::min<uint32_t>(static_cast<uint32_t>(size),
                                             PAGE_SIZE - offset);

        // KEY: Instruction fetches ALWAYS read from data (exec_view)
        // This is where our hooks live — the CPU sees hooked code
        std::memcpy(out, page->data.data() + offset, chunk);

        addr += chunk;
        out += chunk;
        size -= chunk;
    }
    return true;
}

bool VirtualMemory::write(uint64_t addr, const void* buf, size_t size) {
    const uint8_t* in = static_cast<const uint8_t*>(buf);

    while (size > 0) {
        PageEntry* page = find_page(addr);
        if (!page) {
            // Auto-map on write (like Unicorn's hook_mem_invalid)
            map(addr & PAGE_MASK, PAGE_SIZE, PERM_RWX);
            page = find_page(addr);
            if (!page) return false;
        }

        // Copy-on-write: create private copy on first write
        if (page->cow && !page->dirty) {
            page->original = page->data;  // Save original
            page->cow = false;
            page->dirty = true;
        }

        uint32_t offset = addr & (PAGE_SIZE - 1);
        uint32_t chunk = std::min<uint32_t>(static_cast<uint32_t>(size),
                                             PAGE_SIZE - offset);

        // Read old value for logging/watchpoints
        uint64_t old_val = 0;
        if (logging_enabled_ || !watchpoints_.empty()) {
            std::memcpy(&old_val, page->data.data() + offset,
                       std::min<size_t>(chunk, 8));
        }

        // Write to exec_view (data vector)
        std::memcpy(page->data.data() + offset, in, chunk);
        page->dirty = true;
        page->accessed = true;

        // Log access
        uint64_t new_val = 0;
        std::memcpy(&new_val, in, std::min<size_t>(chunk, 8));
        log_access(addr, chunk, new_val, old_val, AccessType::WRITE);

        // Fire watchpoints
        fire_watchpoints(addr, chunk, new_val, AccessType::WRITE);

        addr += chunk;
        in += chunk;
        size -= chunk;
    }
    return true;
}

bool VirtualMemory::protect(uint64_t addr, uint64_t size, uint8_t perms) {
    addr &= PAGE_MASK;
    size = (size + PAGE_SIZE - 1) & PAGE_MASK;

    for (uint64_t p = addr; p < addr + size; p += PAGE_SIZE) {
        PageEntry* page = find_page(p);
        if (page) page->perms = perms;
    }
    return true;
}

const PageEntry* VirtualMemory::get_page(uint64_t addr) const {
    return find_page(addr);
}

// ============================================================
// SHADOW PTE: Split-View Pages
// ============================================================

bool VirtualMemory::split_page(uint64_t addr) {
    PageEntry* page = find_page(addr);
    if (!page) return false;
    if (page->split) return true;  // Already split

    // Save current content as read_view (what data reads will return)
    page->read_view = page->data;
    // Save pristine copy
    page->original = page->data;
    // Mark as split
    page->split = true;

    // Now: page->data = exec_view (CPU fetches see this, can be hooked)
    //      page->read_view = frozen original (data reads see this)
    return true;
}

bool VirtualMemory::unsplit_page(uint64_t addr) {
    PageEntry* page = find_page(addr);
    if (!page || !page->split) return false;

    // Merge: restore exec_view from read_view (undo all hooks)
    page->data = page->read_view;
    page->read_view.clear();
    page->split = false;
    return true;
}

bool VirtualMemory::is_split(uint64_t addr) const {
    const PageEntry* page = find_page(addr);
    return page && page->split;
}

bool VirtualMemory::install_stealth_hook(uint64_t addr,
                                          const std::vector<uint8_t>& hook_bytes) {
    // Auto-split the page if not already split
    if (!is_split(addr)) {
        if (!split_page(addr)) return false;
    }

    PageEntry* page = find_page(addr);
    if (!page) return false;

    uint32_t offset = addr & (PAGE_SIZE - 1);
    if (offset + hook_bytes.size() > PAGE_SIZE) return false;

    // Write hook bytes to exec_view ONLY (page->data)
    // read_view remains untouched (shows original bytes)
    std::memcpy(page->data.data() + offset, hook_bytes.data(), hook_bytes.size());
    return true;
}

bool VirtualMemory::install_stealth_int3(uint64_t addr) {
    return install_stealth_hook(addr, {0xCC});
}

bool VirtualMemory::remove_stealth_hook(uint64_t addr, size_t size) {
    PageEntry* page = find_page(addr);
    if (!page || !page->split) return false;

    uint32_t offset = addr & (PAGE_SIZE - 1);
    if (offset + size > PAGE_SIZE) return false;

    // Restore exec_view from read_view (original bytes)
    std::memcpy(page->data.data() + offset,
                page->read_view.data() + offset, size);
    return true;
}

bool VirtualMemory::protect_region(uint64_t addr, uint64_t size) {
    addr &= PAGE_MASK;
    size = (size + PAGE_SIZE - 1) & PAGE_MASK;

    for (uint64_t p = addr; p < addr + size; p += PAGE_SIZE) {
        split_page(p);
        // Set fake VirtualQuery attrs to look normal
        set_fake_attrs(p, 0x20, 0x1000);  // PAGE_EXECUTE_READ, MEM_IMAGE
    }
    return true;
}

// ============================================================
// Fake Memory Attributes
// ============================================================

void VirtualMemory::set_fake_attrs(uint64_t addr, uint32_t protect, uint32_t type) {
    PageEntry* page = find_page(addr);
    if (page) {
        page->fake_protect = protect;
        page->fake_type = type;
    }
}

bool VirtualMemory::get_fake_attrs(uint64_t addr,
                                    uint32_t& out_protect,
                                    uint32_t& out_type) const {
    const PageEntry* page = find_page(addr);
    if (page && page->fake_protect != 0) {
        out_protect = page->fake_protect;
        out_type = page->fake_type;
        return true;
    }
    return false;
}

// ============================================================
// Copy-on-Write
// ============================================================

bool VirtualMemory::cow_protect(uint64_t addr, uint64_t size) {
    addr &= PAGE_MASK;
    size = (size + PAGE_SIZE - 1) & PAGE_MASK;

    for (uint64_t p = addr; p < addr + size; p += PAGE_SIZE) {
        PageEntry* page = find_page(p);
        if (page) {
            page->cow = true;
            page->original = page->data;  // Save for later comparison
        }
    }
    return true;
}

// ============================================================
// Watchpoints
// ============================================================

HookID VirtualMemory::add_watchpoint(uint64_t addr, uint64_t size,
                                      MemCallback callback, AccessType type) {
    HookID id = next_wp_id_++;
    watchpoints_[id] = {addr, size, type, std::move(callback), true};
    return id;
}

bool VirtualMemory::remove_watchpoint(HookID id) {
    return watchpoints_.erase(id) > 0;
}

void VirtualMemory::enable_watchpoint(HookID id, bool enable) {
    auto it = watchpoints_.find(id);
    if (it != watchpoints_.end()) {
        it->second.enabled = enable;
    }
}

bool VirtualMemory::fire_watchpoints(uint64_t addr, uint32_t size,
                                      uint64_t value, AccessType type) {
    bool any_fired = false;

    for (auto& [id, wp] : watchpoints_) {
        if (!wp.enabled) continue;

        // Check if access overlaps with watchpoint range
        if (addr + size > wp.addr && addr < wp.addr + wp.size) {
            // Check access type match
            uint8_t wp_type = static_cast<uint8_t>(wp.type);
            uint8_t acc_type = static_cast<uint8_t>(type);
            if (wp_type & acc_type) {
                if (wp.callback) {
                    bool result = wp.callback(addr, size, value, type);
                    any_fired = true;
                    if (!result) break;  // Callback says stop
                }
            }
        }
    }
    return any_fired;
}

// ============================================================
// Logging
// ============================================================

void VirtualMemory::set_logging(bool enable) {
    logging_enabled_ = enable;
    if (!enable) access_log_.clear();
}

// ============================================================
// Convenience operations
// ============================================================

uint32_t VirtualMemory::read32(uint64_t addr) const {
    uint32_t val = 0;
    read(addr, &val, 4);
    return val;
}

uint64_t VirtualMemory::read64(uint64_t addr) const {
    uint64_t val = 0;
    read(addr, &val, 8);
    return val;
}

void VirtualMemory::write32(uint64_t addr, uint32_t val) {
    write(addr, &val, 4);
}

void VirtualMemory::write64(uint64_t addr, uint64_t val) {
    write(addr, &val, 8);
}

std::string VirtualMemory::read_string(uint64_t addr, size_t max_len) const {
    std::string result;
    result.reserve(256);

    for (size_t i = 0; i < max_len; ++i) {
        uint8_t byte = 0;
        if (!read(addr + i, &byte, 1)) break;
        if (byte == 0) break;
        result.push_back(static_cast<char>(byte));
    }
    return result;
}

void VirtualMemory::write_string(uint64_t addr, const std::string& str) {
    write(addr, str.data(), str.size() + 1);  // Include null terminator
}

void VirtualMemory::memset(uint64_t addr, uint8_t val, size_t size) {
    std::vector<uint8_t> buf(std::min<size_t>(size, PAGE_SIZE), val);
    size_t remaining = size;
    uint64_t pos = addr;

    while (remaining > 0) {
        size_t chunk = std::min(remaining, buf.size());
        write(pos, buf.data(), chunk);
        pos += chunk;
        remaining -= chunk;
    }
}

void VirtualMemory::memcpy(uint64_t dst, uint64_t src, size_t size) {
    std::vector<uint8_t> buf(std::min<size_t>(size, PAGE_SIZE * 4));
    size_t remaining = size;
    uint64_t src_pos = src, dst_pos = dst;

    while (remaining > 0) {
        size_t chunk = std::min(remaining, buf.size());
        read(src_pos, buf.data(), chunk);
        write(dst_pos, buf.data(), chunk);
        src_pos += chunk;
        dst_pos += chunk;
        remaining -= chunk;
    }
}

// ============================================================
// Inspection
// ============================================================

std::vector<std::pair<uint64_t, uint64_t>> VirtualMemory::mapped_regions() const {
    // Coalesce contiguous pages into regions
    std::vector<uint64_t> addrs;
    addrs.reserve(pages_.size());
    for (const auto& [addr, _] : pages_) {
        addrs.push_back(addr);
    }
    std::sort(addrs.begin(), addrs.end());

    std::vector<std::pair<uint64_t, uint64_t>> regions;
    if (addrs.empty()) return regions;

    uint64_t start = addrs[0];
    uint64_t end = start + PAGE_SIZE;

    for (size_t i = 1; i < addrs.size(); ++i) {
        if (addrs[i] == end) {
            end += PAGE_SIZE;
        } else {
            regions.push_back({start, end - start});
            start = addrs[i];
            end = start + PAGE_SIZE;
        }
    }
    regions.push_back({start, end - start});
    return regions;
}

size_t VirtualMemory::total_mapped() const {
    return pages_.size() * PAGE_SIZE;
}

std::vector<uint64_t> VirtualMemory::split_pages() const {
    std::vector<uint64_t> result;
    for (const auto& [addr, page] : pages_) {
        if (page.split) result.push_back(addr);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<VirtualMemory::Watchpoint> VirtualMemory::watchpoints() const {
    std::vector<Watchpoint> result;
    for (const auto& [id, wp] : watchpoints_) {
        result.push_back(wp);
    }
    return result;
}

} // namespace vx
