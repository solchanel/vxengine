/**
 * VXEngine Windows API Dispatcher Implementation
 *
 * Sentinel-driven dispatch + 50 native API implementations.
 *
 * Dispatch flow:
 *   1. CPU hits sentinel address -> SENTINEL_HIT
 *   2. handle_sentinel() looks up sentinel -> (dll, func_name)
 *   3. Finds registered handler (native C++ or Lua)
 *   4. Handler reads args from stack, computes result
 *   5. Sets EAX to return value, pops stdcall args, returns to caller
 */

#include "../include/vxengine/win_api.h"
#include <algorithm>
#include <cstring>
#include <cctype>
#include <ctime>
#include <cstdio>

namespace vx {

// ============================================================
// Lua handler wrapper (opaque, avoids sol2 in header)
// ============================================================

struct APIDispatcher::LuaHandler {
    // In a full build with sol2, this would hold sol::function
    // For now, it's a placeholder that compiles standalone
    std::string name;
};

// ============================================================
// Construction
// ============================================================

APIDispatcher::APIDispatcher(X86Backend& cpu, VirtualMemory& vmem,
                             EmulatedHeap& heap)
    : cpu_(cpu)
    , vmem_(vmem)
    , heap_(heap)
{
}

// ============================================================
// Sentinel management
// ============================================================

void APIDispatcher::load_sentinels(const PELoader::SentinelMap& map) {
    sentinel_map_ = map;
}

bool APIDispatcher::is_sentinel(uint64_t addr) const {
    return sentinel_map_.count(addr) > 0;
}

std::pair<std::string, std::string> APIDispatcher::lookup_sentinel(uint64_t addr) const {
    auto it = sentinel_map_.find(addr);
    if (it != sentinel_map_.end()) return it->second;
    return {"", ""};
}

// ============================================================
// Handler registration
// ============================================================

void APIDispatcher::register_native(const std::string& name,
                                    NativeAPIHandler handler) {
    native_handlers_[normalize(name)] = std::move(handler);
}

void APIDispatcher::register_lua_api(const std::string& name,
                                     const std::string& handler_key) {
    // Store the Lua handler key — when this API is called, the engine
    // looks up handler_key in the Lua state and calls it
    auto lh = std::make_shared<LuaHandler>();
    lh->name = handler_key;
    lua_handlers_[normalize(name)] = lh;
}

// ============================================================
// Helpers
// ============================================================

std::string APIDispatcher::normalize(const std::string& name) {
    std::string lower = name;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return lower;
}

uint32_t APIDispatcher::stack_arg(int index) const {
    // stdcall: args at [ESP+4], [ESP+8], [ESP+12], ...
    // ESP currently points to the return address
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    return vmem_.read32(esp + 4 + index * 4);
}

void APIDispatcher::stdcall_return(uint32_t retval, uint32_t num_bytes) {
    cpu_.set_reg(X86_EAX, retval);

    // Pop return address
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    uint32_t ret_addr = vmem_.read32(esp);

    // Adjust ESP: pop return address + clean num_bytes of args
    cpu_.set_sp(esp + 4 + num_bytes);

    // Jump to return address
    cpu_.set_pc(ret_addr);
}

void APIDispatcher::cdecl_return(uint32_t retval) {
    cpu_.set_reg(X86_EAX, retval);

    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    uint32_t ret_addr = vmem_.read32(esp);

    // cdecl: only pop return address, caller cleans args
    cpu_.set_sp(esp + 4);
    cpu_.set_pc(ret_addr);
}

// ============================================================
// Dispatch
// ============================================================

bool APIDispatcher::handle_sentinel(uint64_t sentinel_addr) {
    auto it = sentinel_map_.find(sentinel_addr);
    if (it == sentinel_map_.end()) return false;

    const std::string& func_name = it->second.second;
    std::string key = normalize(func_name);

    // Try native handler first
    auto native_it = native_handlers_.find(key);
    if (native_it != native_handlers_.end()) {
        // Handler returns number of stack bytes to clean (stdcall)
        // But the handler itself calls stdcall_return or cdecl_return internally
        native_it->second(cpu_, vmem_, heap_);
        return true;
    }

    // Try Lua handler
    auto lua_it = lua_handlers_.find(key);
    if (lua_it != lua_handlers_.end()) {
        // In a full sol2 build, call the Lua function here
        // For now, return 0 in EAX and do a stdcall return with 0 cleanup
        stdcall_return(0, 0);
        return true;
    }

    // Unknown API: return 0 and log
    stdcall_return(0, 0);
    return true;
}

// ============================================================
// TLS support
// ============================================================

uint32_t APIDispatcher::tls_alloc() {
    uint32_t idx = next_tls_index_++;
    tls_values_[idx] = 0;
    return idx;
}

void APIDispatcher::tls_free(uint32_t index) {
    tls_values_.erase(index);
}

void APIDispatcher::tls_set(uint32_t index, uint32_t value) {
    tls_values_[index] = value;
}

uint32_t APIDispatcher::tls_get(uint32_t index) const {
    auto it = tls_values_.find(index);
    return (it != tls_values_.end()) ? it->second : 0;
}

// ============================================================
// Handle tracking
// ============================================================

uint32_t APIDispatcher::alloc_handle() {
    return next_handle_++;
}

void APIDispatcher::close_handle(uint32_t /*h*/) {
    // No-op in emulation
}

// ============================================================
// Register all 50+ built-in APIs
// ============================================================

void APIDispatcher::register_builtins() {
    register_memory_apis();
    register_crt_apis();
    register_module_apis();
    register_thread_apis();
    register_sync_apis();
    register_error_apis();
    register_misc_apis();
}

// ============================================================
// Memory APIs
// ============================================================

void APIDispatcher::register_memory_apis() {
    // ---- VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect) ----
    register_native("VirtualAlloc", [this](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap& heap) -> uint32_t {
        uint32_t addr    = stack_arg(0);
        uint32_t size    = stack_arg(1);
        uint32_t type    = stack_arg(2);
        uint32_t protect = stack_arg(3);

        // Convert Windows protection to vx::Perm
        uint8_t perms = PERM_RW; // Default
        if (protect & PAGE_EXECUTE_READWRITE) perms = PERM_RWX;
        else if (protect & PAGE_EXECUTE_READ) perms = PERM_RX;
        else if (protect & PAGE_READWRITE) perms = PERM_RW;
        else if (protect & PAGE_READONLY) perms = PERM_READ;
        else if (protect & PAGE_EXECUTE) perms = PERM_EXEC;

        // Page-align size
        uint64_t aligned_size = (size + PAGE_SIZE - 1) & PAGE_MASK;
        if (aligned_size == 0) aligned_size = PAGE_SIZE;

        // If no address specified, allocate from high area
        if (addr == 0) {
            // Simple: use heap to track, but map pages directly
            static uint32_t va_alloc_ptr = 0x30000000;
            addr = va_alloc_ptr;
            va_alloc_ptr += static_cast<uint32_t>(aligned_size);
        } else {
            addr = addr & static_cast<uint32_t>(PAGE_MASK);
        }

        vmem.map(addr, aligned_size, perms);
        vmem.memset(addr, 0, static_cast<size_t>(aligned_size));

        virtual_allocs_[addr] = {addr, static_cast<uint32_t>(aligned_size), protect};

        stdcall_return(addr, 16);
        return 16;
    });

    // ---- VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect) ----
    register_native("VirtualProtect", [this](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t addr       = stack_arg(0);
        uint32_t size       = stack_arg(1);
        uint32_t new_prot   = stack_arg(2);
        uint32_t old_prot_p = stack_arg(3);

        // Write old protection
        if (old_prot_p != 0) {
            vmem.write32(old_prot_p, PAGE_READWRITE); // Simplified
        }

        uint8_t perms = PERM_RW;
        if (new_prot & PAGE_EXECUTE_READWRITE) perms = PERM_RWX;
        else if (new_prot & PAGE_EXECUTE_READ) perms = PERM_RX;
        else if (new_prot & PAGE_READWRITE) perms = PERM_RW;
        else if (new_prot & PAGE_READONLY) perms = PERM_READ;

        uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
        vmem.protect(addr, aligned, perms);

        stdcall_return(1, 16); // TRUE
        return 16;
    });

    // ---- VirtualQuery(lpAddress, lpBuffer, dwLength) ----
    register_native("VirtualQuery", [this](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t addr   = stack_arg(0);
        uint32_t buf    = stack_arg(1);
        uint32_t length = stack_arg(2);

        MEMORY_BASIC_INFORMATION32 mbi = {};
        uint32_t page_addr = addr & static_cast<uint32_t>(PAGE_MASK);

        // Check for fake attrs first
        uint32_t fake_prot = 0, fake_type = 0;
        if (vmem.get_fake_attrs(addr, fake_prot, fake_type)) {
            mbi.BaseAddress = page_addr;
            mbi.AllocationBase = page_addr;
            mbi.AllocationProtect = fake_prot;
            mbi.RegionSize = PAGE_SIZE;
            mbi.State = MEM_COMMIT;
            mbi.Protect = fake_prot;
            mbi.Type = fake_type;
        } else if (vmem.is_mapped(addr)) {
            mbi.BaseAddress = page_addr;
            mbi.AllocationBase = page_addr;
            mbi.AllocationProtect = PAGE_READWRITE;
            mbi.RegionSize = PAGE_SIZE;
            mbi.State = MEM_COMMIT;
            mbi.Protect = PAGE_READWRITE;
            mbi.Type = 0x20000; // MEM_PRIVATE
        } else {
            mbi.BaseAddress = page_addr;
            mbi.RegionSize = PAGE_SIZE;
            mbi.State = MEM_FREE;
            mbi.Protect = PAGE_NOACCESS;
        }

        uint32_t write_size = std::min(length,
            static_cast<uint32_t>(sizeof(MEMORY_BASIC_INFORMATION32)));
        vmem.write(buf, &mbi, write_size);

        stdcall_return(write_size, 12);
        return 12;
    });

    // ---- VirtualFree(lpAddress, dwSize, dwFreeType) ----
    register_native("VirtualFree", [this](X86Backend& cpu, VirtualMemory& vmem,
                                          EmulatedHeap&) -> uint32_t {
        uint32_t addr = stack_arg(0);
        uint32_t size = stack_arg(1);
        uint32_t type = stack_arg(2);

        if (type & MEM_RELEASE) {
            auto it = virtual_allocs_.find(addr);
            if (it != virtual_allocs_.end()) {
                vmem.unmap(it->second.base, it->second.size);
                virtual_allocs_.erase(it);
            }
        }

        stdcall_return(1, 12); // TRUE
        return 12;
    });

    // ---- HeapAlloc(hHeap, dwFlags, dwBytes) ----
    register_native("HeapAlloc", [this](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap& heap) -> uint32_t {
        uint32_t hHeap = stack_arg(0);
        uint32_t flags = stack_arg(1);
        uint32_t size  = stack_arg(2);

        uint32_t addr = heap.alloc(size);
        if (addr != 0 && (flags & HEAP_ZERO_MEMORY)) {
            vmem.memset(addr, 0, size);
        }

        stdcall_return(addr, 12);
        return 12;
    });

    // ---- HeapFree(hHeap, dwFlags, lpMem) ----
    register_native("HeapFree", [this](X86Backend&, VirtualMemory&,
                                       EmulatedHeap& heap) -> uint32_t {
        uint32_t hHeap = stack_arg(0);
        uint32_t flags = stack_arg(1);
        uint32_t ptr   = stack_arg(2);

        if (ptr != 0) heap.free(ptr);

        stdcall_return(1, 12); // TRUE
        return 12;
    });

    // ---- HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes) ----
    register_native("HeapReAlloc", [this](X86Backend&, VirtualMemory&,
                                          EmulatedHeap& heap) -> uint32_t {
        uint32_t hHeap   = stack_arg(0);
        uint32_t flags   = stack_arg(1);
        uint32_t ptr     = stack_arg(2);
        uint32_t newsize = stack_arg(3);

        uint32_t result = heap.realloc(ptr, newsize);

        stdcall_return(result, 16);
        return 16;
    });
}

// ============================================================
// CRT APIs (cdecl calling convention)
// ============================================================

void APIDispatcher::register_crt_apis() {
    // ---- malloc(size) ----
    register_native("malloc", [this](X86Backend&, VirtualMemory&,
                                     EmulatedHeap& heap) -> uint32_t {
        uint32_t size = stack_arg(0);
        uint32_t addr = heap.alloc(size);
        cdecl_return(addr);
        return 0;
    });

    // ---- calloc(count, size) ----
    register_native("calloc", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap& heap) -> uint32_t {
        uint32_t count = stack_arg(0);
        uint32_t size  = stack_arg(1);
        uint32_t total = count * size;
        uint32_t addr = heap.alloc(total);
        if (addr) vmem.memset(addr, 0, total);
        cdecl_return(addr);
        return 0;
    });

    // ---- realloc(ptr, size) ----
    register_native("realloc", [this](X86Backend&, VirtualMemory&,
                                      EmulatedHeap& heap) -> uint32_t {
        uint32_t ptr  = stack_arg(0);
        uint32_t size = stack_arg(1);
        uint32_t addr = heap.realloc(ptr, size);
        cdecl_return(addr);
        return 0;
    });

    // ---- free(ptr) ----
    register_native("free", [this](X86Backend&, VirtualMemory&,
                                   EmulatedHeap& heap) -> uint32_t {
        uint32_t ptr = stack_arg(0);
        if (ptr) heap.free(ptr);
        cdecl_return(0);
        return 0;
    });

    // ---- memcpy(dst, src, count) ----
    register_native("memcpy", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t dst   = stack_arg(0);
        uint32_t src   = stack_arg(1);
        uint32_t count = stack_arg(2);
        if (count > 0 && dst != 0 && src != 0) {
            vmem.memcpy(dst, src, count);
        }
        cdecl_return(dst);
        return 0;
    });

    // ---- memset(dst, val, count) ----
    register_native("memset", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t dst   = stack_arg(0);
        uint32_t val   = stack_arg(1);
        uint32_t count = stack_arg(2);
        if (count > 0 && dst != 0) {
            vmem.memset(dst, static_cast<uint8_t>(val), count);
        }
        cdecl_return(dst);
        return 0;
    });

    // ---- memcmp(s1, s2, count) ----
    register_native("memcmp", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t s1    = stack_arg(0);
        uint32_t s2    = stack_arg(1);
        uint32_t count = stack_arg(2);

        int result = 0;
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t a = 0, b = 0;
            vmem.read(s1 + i, &a, 1);
            vmem.read(s2 + i, &b, 1);
            if (a != b) {
                result = (a < b) ? -1 : 1;
                break;
            }
        }
        cdecl_return(static_cast<uint32_t>(result));
        return 0;
    });

    // ---- strlen(str) ----
    register_native("strlen", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t str = stack_arg(0);
        std::string s = vmem.read_string(str, 0x10000);
        cdecl_return(static_cast<uint32_t>(s.size()));
        return 0;
    });

    // ---- strcmp(s1, s2) ----
    register_native("strcmp", [this](X86Backend&, VirtualMemory& vmem,
                                    EmulatedHeap&) -> uint32_t {
        uint32_t s1 = stack_arg(0);
        uint32_t s2 = stack_arg(1);
        std::string a = vmem.read_string(s1, 0x10000);
        std::string b = vmem.read_string(s2, 0x10000);
        int result = a.compare(b);
        if (result < 0) result = -1;
        if (result > 0) result = 1;
        cdecl_return(static_cast<uint32_t>(result));
        return 0;
    });

    // ---- strncmp(s1, s2, n) ----
    register_native("strncmp", [this](X86Backend&, VirtualMemory& vmem,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t s1 = stack_arg(0);
        uint32_t s2 = stack_arg(1);
        uint32_t n  = stack_arg(2);
        std::string a = vmem.read_string(s1, n);
        std::string b = vmem.read_string(s2, n);
        a = a.substr(0, n);
        b = b.substr(0, n);
        int result = a.compare(b);
        if (result < 0) result = -1;
        if (result > 0) result = 1;
        cdecl_return(static_cast<uint32_t>(result));
        return 0;
    });

    // ---- strcpy(dst, src) ----
    register_native("strcpy", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t dst = stack_arg(0);
        uint32_t src = stack_arg(1);
        std::string s = vmem.read_string(src, 0x10000);
        vmem.write_string(dst, s);
        cdecl_return(dst);
        return 0;
    });

    // ---- strncpy(dst, src, count) ----
    register_native("strncpy", [this](X86Backend&, VirtualMemory& vmem,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t dst   = stack_arg(0);
        uint32_t src   = stack_arg(1);
        uint32_t count = stack_arg(2);
        std::string s = vmem.read_string(src, count);
        // strncpy pads with zeros if shorter
        for (uint32_t i = 0; i < count; ++i) {
            uint8_t c = (i < s.size()) ? static_cast<uint8_t>(s[i]) : 0;
            vmem.write(dst + i, &c, 1);
        }
        cdecl_return(dst);
        return 0;
    });

    // ---- strchr(str, c) ----
    register_native("strchr", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t str = stack_arg(0);
        uint32_t c   = stack_arg(1) & 0xFF;
        std::string s = vmem.read_string(str, 0x10000);
        auto pos = s.find(static_cast<char>(c));
        uint32_t result = (pos != std::string::npos) ? (str + static_cast<uint32_t>(pos)) : 0;
        cdecl_return(result);
        return 0;
    });

    // ---- strstr(haystack, needle) ----
    register_native("strstr", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap&) -> uint32_t {
        uint32_t hay = stack_arg(0);
        uint32_t ndl = stack_arg(1);
        std::string h = vmem.read_string(hay, 0x10000);
        std::string n = vmem.read_string(ndl, 0x10000);
        auto pos = h.find(n);
        uint32_t result = (pos != std::string::npos) ? (hay + static_cast<uint32_t>(pos)) : 0;
        cdecl_return(result);
        return 0;
    });

    // ---- sprintf(buf, fmt, ...) ---- simplified: just copies fmt
    register_native("sprintf", [this](X86Backend&, VirtualMemory& vmem,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t buf = stack_arg(0);
        uint32_t fmt = stack_arg(1);
        // Simplified: copy format string as-is (no varargs processing)
        std::string fmtstr = vmem.read_string(fmt, 0x1000);
        vmem.write_string(buf, fmtstr);
        cdecl_return(static_cast<uint32_t>(fmtstr.size()));
        return 0;
    });

    // ---- atoi(str) ----
    register_native("atoi", [this](X86Backend&, VirtualMemory& vmem,
                                   EmulatedHeap&) -> uint32_t {
        uint32_t str = stack_arg(0);
        std::string s = vmem.read_string(str, 64);
        int val = 0;
        try { val = std::stoi(s); } catch (...) {}
        cdecl_return(static_cast<uint32_t>(val));
        return 0;
    });

    // ---- atol(str) ----
    register_native("atol", [this](X86Backend&, VirtualMemory& vmem,
                                   EmulatedHeap&) -> uint32_t {
        uint32_t str = stack_arg(0);
        std::string s = vmem.read_string(str, 64);
        long val = 0;
        try { val = std::stol(s); } catch (...) {}
        cdecl_return(static_cast<uint32_t>(val));
        return 0;
    });

    // ---- tolower(c) ----
    register_native("tolower", [this](X86Backend&, VirtualMemory&,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t c = stack_arg(0);
        uint32_t result = static_cast<uint32_t>(std::tolower(static_cast<int>(c & 0xFF)));
        cdecl_return(result);
        return 0;
    });

    // ---- toupper(c) ----
    register_native("toupper", [this](X86Backend&, VirtualMemory&,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t c = stack_arg(0);
        uint32_t result = static_cast<uint32_t>(std::toupper(static_cast<int>(c & 0xFF)));
        cdecl_return(result);
        return 0;
    });
}

// ============================================================
// Module APIs
// ============================================================

void APIDispatcher::register_module_apis() {
    // ---- GetModuleHandleA(lpModuleName) ----
    register_native("GetModuleHandleA", [this](X86Backend&, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t name_ptr = stack_arg(0);

        if (name_ptr == 0) {
            // NULL = get own module base (from PEB)
            uint32_t peb_addr = PEB_ADDRESS;
            uint32_t image_base = vmem.read32(peb_addr + 0x08); // PEB.ImageBaseAddress
            stdcall_return(image_base, 4);
        } else {
            std::string name = vmem.read_string(name_ptr, 256);
            // Normalize to lowercase for comparison
            for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            // Walk PEB_LDR_DATA InLoadOrderModuleList
            uint32_t ldr_addr = vmem.read32(PEB_ADDRESS + 0x0C);
            uint32_t list_head = ldr_addr + 0x0C; // InLoadOrderModuleList
            uint32_t entry = vmem.read32(list_head); // Flink

            uint32_t result = 0;
            while (entry != list_head && entry != 0) {
                // BaseDllName at offset +0x2C in LDR_DATA_TABLE_ENTRY
                uint32_t name_buf = vmem.read32(entry + 0x30); // BaseDllName.Buffer
                uint16_t name_len = 0;
                vmem.read(entry + 0x2C, &name_len, 2); // BaseDllName.Length

                // Read UTF-16LE name
                std::string mod_name;
                for (uint16_t i = 0; i < name_len / 2; ++i) {
                    uint16_t wc = 0;
                    vmem.read(name_buf + i * 2, &wc, 2);
                    mod_name += static_cast<char>(wc & 0xFF);
                }
                for (auto& c : mod_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (mod_name == name || mod_name.find(name) != std::string::npos) {
                    result = vmem.read32(entry + 0x18); // DllBase
                    break;
                }

                entry = vmem.read32(entry); // Flink
            }

            stdcall_return(result, 4);
        }
        return 4;
    });

    // ---- GetProcAddress(hModule, lpProcName) ----
    register_native("GetProcAddress", [this](X86Backend&, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t hModule  = stack_arg(0);
        uint32_t proc_ptr = stack_arg(1);

        // In emulation, we return 0 (not found) since we don't have real DLLs loaded
        // A more complete implementation would walk the export table of the module
        stdcall_return(0, 8);
        return 8;
    });

    // ---- LoadLibraryA(lpLibFileName) ----
    register_native("LoadLibraryA", [this](X86Backend&, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t name_ptr = stack_arg(0);
        std::string name = vmem.read_string(name_ptr, 256);

        // Return a fake module handle (non-zero to indicate "success")
        // The sentinel system handles the actual API routing
        static uint32_t fake_base = 0x74000000;
        uint32_t handle = fake_base;
        fake_base += 0x00100000;

        stdcall_return(handle, 4);
        return 4;
    });

    // ---- FreeLibrary(hLibModule) ----
    register_native("FreeLibrary", [this](X86Backend&, VirtualMemory&,
                                          EmulatedHeap&) -> uint32_t {
        stdcall_return(1, 4); // TRUE
        return 4;
    });

    // ---- GetModuleFileNameA(hModule, lpFilename, nSize) ----
    register_native("GetModuleFileNameA", [this](X86Backend&, VirtualMemory& vmem,
                                                 EmulatedHeap&) -> uint32_t {
        uint32_t hModule  = stack_arg(0);
        uint32_t buf      = stack_arg(1);
        uint32_t buf_size = stack_arg(2);

        std::string path = "C:\\target.exe";
        uint32_t copy_len = std::min(static_cast<uint32_t>(path.size()),
                                     buf_size - 1);
        vmem.write(buf, path.c_str(), copy_len);
        uint8_t null = 0;
        vmem.write(buf + copy_len, &null, 1);

        stdcall_return(copy_len, 12);
        return 12;
    });
}

// ============================================================
// Thread APIs
// ============================================================

void APIDispatcher::register_thread_apis() {
    // ---- TlsAlloc() ----
    register_native("TlsAlloc", [this](X86Backend&, VirtualMemory&,
                                       EmulatedHeap&) -> uint32_t {
        uint32_t idx;
        if (thread_manager_ && thread_manager_->initialized()) {
            idx = thread_manager_->tls_alloc();
        } else {
            idx = tls_alloc();
        }
        stdcall_return(idx, 0);
        return 0;
    });

    // ---- TlsGetValue(dwTlsIndex) ----
    register_native("TlsGetValue", [this](X86Backend&, VirtualMemory&,
                                          EmulatedHeap&) -> uint32_t {
        uint32_t idx = stack_arg(0);
        uint32_t val;
        if (thread_manager_ && thread_manager_->initialized()) {
            val = static_cast<uint32_t>(thread_manager_->tls_get(idx));
        } else {
            val = tls_get(idx);
        }
        last_error_ = 0; // TlsGetValue clears last error on success
        stdcall_return(val, 4);
        return 4;
    });

    // ---- TlsSetValue(dwTlsIndex, lpTlsValue) ----
    register_native("TlsSetValue", [this](X86Backend&, VirtualMemory&,
                                          EmulatedHeap&) -> uint32_t {
        uint32_t idx = stack_arg(0);
        uint32_t val = stack_arg(1);
        if (thread_manager_ && thread_manager_->initialized()) {
            thread_manager_->tls_set(idx, val);
        } else {
            tls_set(idx, val);
        }
        stdcall_return(1, 8); // TRUE
        return 8;
    });

    // ---- TlsFree(dwTlsIndex) ----
    register_native("TlsFree", [this](X86Backend&, VirtualMemory&,
                                      EmulatedHeap&) -> uint32_t {
        uint32_t idx = stack_arg(0);
        if (thread_manager_ && thread_manager_->initialized()) {
            thread_manager_->tls_free(idx);
        } else {
            tls_free(idx);
        }
        stdcall_return(1, 4); // TRUE
        return 4;
    });

    // ---- GetCurrentThreadId() ----
    register_native("GetCurrentThreadId", [this](X86Backend&, VirtualMemory&,
                                                 EmulatedHeap&) -> uint32_t {
        uint32_t tid = 0x1004; // Fake TID matching TEB
        if (thread_manager_ && thread_manager_->initialized()) {
            tid = thread_manager_->current_id();
        }
        stdcall_return(tid, 0);
        return 0;
    });

    // ---- CreateThread(lpThreadAttributes, dwStackSize, lpStartAddress,
    //                   lpParameter, dwCreationFlags, lpThreadId) ----
    register_native("CreateThread", [this](X86Backend&, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t attrs      = stack_arg(0);  // lpThreadAttributes (ignored)
        uint32_t stack_size = stack_arg(1);  // dwStackSize
        uint32_t start_addr = stack_arg(2);  // lpStartAddress
        uint32_t param      = stack_arg(3);  // lpParameter
        uint32_t flags      = stack_arg(4);  // dwCreationFlags
        uint32_t tid_ptr    = stack_arg(5);  // lpThreadId

        if (!thread_manager_ || !thread_manager_->initialized()) {
            // No thread manager: return a fake handle, thread won't actually run
            uint32_t handle = alloc_handle();
            if (tid_ptr != 0) vmem.write32(tid_ptr, 0x2000);
            stdcall_return(handle, 24);
            return 24;
        }

        bool suspended = (flags & 0x4) != 0;  // CREATE_SUSPENDED
        if (stack_size == 0) stack_size = 0x100000;  // Default 1MB

        uint32_t handle = thread_manager_->create_thread(
            start_addr, param, stack_size, suspended);

        // Write thread ID to output pointer if provided
        if (tid_ptr != 0) {
            EmulatedThread* t = thread_manager_->thread_by_handle(handle);
            if (t) vmem.write32(tid_ptr, t->id);
        }

        stdcall_return(handle, 24);
        return 24;
    });

    // ---- ExitThread(dwExitCode) ----
    register_native("ExitThread", [this](X86Backend&, VirtualMemory&,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t exit_code = stack_arg(0);

        if (thread_manager_ && thread_manager_->initialized()) {
            uint32_t handle = thread_manager_->current_handle();
            thread_manager_->terminate_thread(handle, exit_code);
        }
        // ExitThread doesn't return; the thread is dead.
        // Don't do stdcall_return — the switch_to_next in terminate_thread
        // already loaded new thread state.
        return 4;
    });

    // ---- GetExitCodeThread(hThread, lpExitCode) ----
    register_native("GetExitCodeThread", [this](X86Backend&, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t handle = stack_arg(0);
        uint32_t exit_code_ptr = stack_arg(1);

        uint32_t exit_code = 259;  // STILL_ACTIVE
        if (thread_manager_ && thread_manager_->initialized()) {
            exit_code = thread_manager_->get_exit_code(handle);
        }

        if (exit_code_ptr != 0) {
            vmem.write32(exit_code_ptr, exit_code);
        }

        stdcall_return(1, 8);  // TRUE
        return 8;
    });

    // ---- SuspendThread(hThread) ----
    register_native("SuspendThread", [this](X86Backend&, VirtualMemory&,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t handle = stack_arg(0);
        uint32_t prev_count = 0;

        if (thread_manager_ && thread_manager_->initialized()) {
            EmulatedThread* t = thread_manager_->thread_by_handle(handle);
            if (t) prev_count = t->suspend_count;
            thread_manager_->suspend_thread(handle);
        }

        stdcall_return(prev_count, 4);
        return 4;
    });

    // ---- ResumeThread(hThread) ----
    register_native("ResumeThread", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t handle = stack_arg(0);
        uint32_t prev_count = 0;

        if (thread_manager_ && thread_manager_->initialized()) {
            EmulatedThread* t = thread_manager_->thread_by_handle(handle);
            if (t) prev_count = t->suspend_count;
            thread_manager_->resume_thread(handle);
        }

        stdcall_return(prev_count, 4);
        return 4;
    });

    // ---- WaitForSingleObject(hHandle, dwMilliseconds) ----
    register_native("WaitForSingleObject", [this](X86Backend&, VirtualMemory&,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t handle  = stack_arg(0);
        uint32_t timeout = stack_arg(1);

        uint32_t result = 0;  // WAIT_OBJECT_0
        if (thread_manager_ && thread_manager_->initialized()) {
            result = thread_manager_->wait_for_object(handle, timeout);
        }

        stdcall_return(result, 8);
        return 8;
    });
}

// ============================================================
// Synchronization APIs
// ============================================================

void APIDispatcher::register_sync_apis() {
    // ---- InitializeCriticalSection(lpCriticalSection) ----
    register_native("InitializeCriticalSection", [this](X86Backend&, VirtualMemory& vmem,
                                                        EmulatedHeap&) -> uint32_t {
        uint32_t cs_ptr = stack_arg(0);
        CRITICAL_SECTION32 cs = {};
        cs.LockCount = -1;
        cs.RecursionCount = 0;
        cs.OwningThread = 0;
        vmem.write(cs_ptr, &cs, sizeof(cs));
        stdcall_return(0, 4); // void return, but we set EAX=0
        return 4;
    });

    // ---- EnterCriticalSection(lpCriticalSection) ----
    register_native("EnterCriticalSection", [this](X86Backend&, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t cs_ptr = stack_arg(0);
        // Single-threaded emulation: just increment recursion count
        uint32_t rc = vmem.read32(cs_ptr + 8); // RecursionCount
        vmem.write32(cs_ptr + 8, rc + 1);
        vmem.write32(cs_ptr + 12, 0x1004); // OwningThread = our TID
        stdcall_return(0, 4);
        return 4;
    });

    // ---- LeaveCriticalSection(lpCriticalSection) ----
    register_native("LeaveCriticalSection", [this](X86Backend&, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t cs_ptr = stack_arg(0);
        uint32_t rc = vmem.read32(cs_ptr + 8);
        if (rc > 0) {
            vmem.write32(cs_ptr + 8, rc - 1);
            if (rc == 1) vmem.write32(cs_ptr + 12, 0); // Clear owner
        }
        stdcall_return(0, 4);
        return 4;
    });

    // ---- DeleteCriticalSection(lpCriticalSection) ----
    register_native("DeleteCriticalSection", [this](X86Backend&, VirtualMemory& vmem,
                                                     EmulatedHeap&) -> uint32_t {
        uint32_t cs_ptr = stack_arg(0);
        vmem.memset(cs_ptr, 0, sizeof(CRITICAL_SECTION32));
        stdcall_return(0, 4);
        return 4;
    });

    // ---- CreateMutexA(lpMutexAttributes, bInitialOwner, lpName) ----
    register_native("CreateMutexA", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t handle = alloc_handle();
        stdcall_return(handle, 12);
        return 12;
    });

    // ---- ReleaseMutex(hMutex) ----
    register_native("ReleaseMutex", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        stdcall_return(1, 4); // TRUE
        return 4;
    });

    // ---- InterlockedIncrement(lpAddend) ----
    register_native("InterlockedIncrement", [this](X86Backend&, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t ptr = stack_arg(0);
        uint32_t val = vmem.read32(ptr);
        val++;
        vmem.write32(ptr, val);
        stdcall_return(val, 4);
        return 4;
    });

    // ---- InterlockedDecrement(lpAddend) ----
    register_native("InterlockedDecrement", [this](X86Backend&, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t ptr = stack_arg(0);
        uint32_t val = vmem.read32(ptr);
        val--;
        vmem.write32(ptr, val);
        stdcall_return(val, 4);
        return 4;
    });
}

// ============================================================
// Error APIs
// ============================================================

void APIDispatcher::register_error_apis() {
    // ---- GetLastError() ----
    register_native("GetLastError", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        stdcall_return(last_error_, 0);
        return 0;
    });

    // ---- SetLastError(dwErrCode) ----
    register_native("SetLastError", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        last_error_ = stack_arg(0);
        // Also update TEB.LastErrorValue
        vmem_.write32(TEB_ADDRESS + 0x34, last_error_);
        stdcall_return(0, 4); // void return
        return 4;
    });
}

// ============================================================
// Misc APIs
// ============================================================

void APIDispatcher::register_misc_apis() {
    // ---- GetTickCount() ----
    register_native("GetTickCount", [this](X86Backend&, VirtualMemory&,
                                           EmulatedHeap&) -> uint32_t {
        tick_count_ += 16; // Advance fake time by ~16ms per call
        stdcall_return(tick_count_, 0);
        return 0;
    });

    // ---- GetVersionExA(lpVersionInformation) ----
    register_native("GetVersionExA", [this](X86Backend&, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t info_ptr = stack_arg(0);

        OSVERSIONINFOA info = {};
        info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
        info.dwMajorVersion = 6;    // Windows 7+
        info.dwMinorVersion = 1;
        info.dwBuildNumber = 7601;
        info.dwPlatformId = 2;      // VER_PLATFORM_WIN32_NT
        std::strncpy(info.szCSDVersion, "Service Pack 1",
                     sizeof(info.szCSDVersion) - 1);

        vmem.write(info_ptr, &info, sizeof(info));
        stdcall_return(1, 4); // TRUE
        return 4;
    });

    // ---- Sleep(dwMilliseconds) ----
    register_native("Sleep", [this](X86Backend&, VirtualMemory&,
                                    EmulatedHeap&) -> uint32_t {
        uint32_t ms = stack_arg(0);
        // In emulation, just advance tick count
        tick_count_ += ms;
        stdcall_return(0, 4); // void
        return 4;
    });

    // ---- CloseHandle(hObject) ----
    register_native("CloseHandle", [this](X86Backend&, VirtualMemory&,
                                          EmulatedHeap&) -> uint32_t {
        uint32_t handle = stack_arg(0);
        close_handle(handle);
        stdcall_return(1, 4); // TRUE
        return 4;
    });

    // ---- abort() ----
    register_native("abort", [this](X86Backend& cpu, VirtualMemory&,
                                    EmulatedHeap&) -> uint32_t {
        // Set PC to a halt sentinel
        cpu.set_pc(0xDEADDEAD);
        cdecl_return(0);
        return 0;
    });

    // ---- time(timer) ----
    register_native("time", [this](X86Backend&, VirtualMemory& vmem,
                                   EmulatedHeap&) -> uint32_t {
        uint32_t timer_ptr = stack_arg(0);
        uint32_t t = static_cast<uint32_t>(std::time(nullptr));
        if (timer_ptr != 0) {
            vmem.write32(timer_ptr, t);
        }
        cdecl_return(t);
        return 0;
    });

    // ---- _errno() ---- returns pointer to thread-local errno
    register_native("_errno", [this](X86Backend&, VirtualMemory& vmem,
                                     EmulatedHeap& heap) -> uint32_t {
        // Allocate a persistent errno location if not yet done
        if (errno_addr_ == 0) {
            errno_addr_ = heap.alloc(4);
            vmem.write32(errno_addr_, 0);
        }
        cdecl_return(errno_addr_);
        return 0;
    });
}

} // namespace vx
