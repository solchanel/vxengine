#pragma once
/**
 * VXEngine Windows API Dispatcher
 *
 * Sentinel-driven API interception:
 *   1. PE loader writes sentinel 0xFEED0000+N to each IAT entry
 *   2. When CPU jumps to a sentinel, SENTINEL_HIT is raised
 *   3. Dispatcher looks up sentinel -> (dll, func_name)
 *   4. Calls registered C++ handler or Lua callback
 *   5. Reads args from stack, sets EAX, simulates stdcall RET
 *
 * Includes 50+ native C++ implementations of critical Windows APIs.
 * Supports Lua-defined API handlers via sol2.
 */

#include "vxengine.h"
#include "memory.h"
#include "pe_loader.h"
#include "win_env.h"
#include "cpu/x86/x86_cpu.h"
#include "thread_manager.h"

// Forward declare — sol2 types are only used in .cpp files via #include <sol/sol.hpp>
// Headers use std::string for Lua API registration instead of sol::function

namespace vx {

// ============================================================
// API handler function signature
// ============================================================

/// Native API handler:
///   Takes (cpu, vmem, heap) context
///   Returns number of stack bytes to clean (for stdcall pop)
///   Handler reads args from [ESP+4], [ESP+8], etc.
///   Handler writes return value to EAX
using NativeAPIHandler = std::function<uint32_t(X86Backend& cpu,
                                                VirtualMemory& vmem,
                                                EmulatedHeap& heap)>;

// ============================================================
// Windows structure definitions for API implementations
// ============================================================

#pragma pack(push, 1)

struct MEMORY_BASIC_INFORMATION32 {
    uint32_t BaseAddress;
    uint32_t AllocationBase;
    uint32_t AllocationProtect;
    uint32_t RegionSize;
    uint32_t State;
    uint32_t Protect;
    uint32_t Type;
};

struct CRITICAL_SECTION32 {
    uint32_t DebugInfo;
    uint32_t LockCount;
    uint32_t RecursionCount;
    uint32_t OwningThread;
    uint32_t LockSemaphore;
    uint32_t SpinCount;
};

struct OSVERSIONINFOA {
    uint32_t dwOSVersionInfoSize;
    uint32_t dwMajorVersion;
    uint32_t dwMinorVersion;
    uint32_t dwBuildNumber;
    uint32_t dwPlatformId;
    char     szCSDVersion[128];
};

#pragma pack(pop)

// Windows constants
constexpr uint32_t MEM_COMMIT      = 0x1000;
constexpr uint32_t MEM_RESERVE     = 0x2000;
constexpr uint32_t MEM_RELEASE     = 0x8000;
constexpr uint32_t MEM_FREE        = 0x10000;
constexpr uint32_t PAGE_NOACCESS       = 0x01;
constexpr uint32_t PAGE_READONLY       = 0x02;
constexpr uint32_t PAGE_READWRITE      = 0x04;
constexpr uint32_t PAGE_EXECUTE        = 0x10;
constexpr uint32_t PAGE_EXECUTE_READ   = 0x20;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40;
constexpr uint32_t HEAP_ZERO_MEMORY    = 0x08;

// ============================================================
// API Dispatcher
// ============================================================

class APIDispatcher {
public:
    APIDispatcher(X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap);
    ~APIDispatcher() = default;

    APIDispatcher(const APIDispatcher&) = delete;
    APIDispatcher& operator=(const APIDispatcher&) = delete;

    /// Load sentinel map from PE loader (call after PELoader::load)
    void load_sentinels(const PELoader::SentinelMap& map);

    /// Register a native C++ API handler by name (e.g., "VirtualAlloc")
    void register_native(const std::string& name, NativeAPIHandler handler);

    /// Register a Lua-defined API handler (called from lua_bindings.cpp with sol2)
    /// The handler_key is stored and looked up in the Lua state at call time
    void register_lua_api(const std::string& name, const std::string& handler_key);

    /// Handle a sentinel hit. Called when CPU stops at a sentinel address.
    /// Returns true if handled, false if unknown sentinel.
    /// Modifies CPU state: reads args from stack, sets EAX, adjusts ESP (stdcall ret).
    bool handle_sentinel(uint64_t sentinel_addr);

    /// Register all 50+ built-in Windows API implementations
    void register_builtins();

    /// Look up which API a sentinel maps to
    std::pair<std::string, std::string> lookup_sentinel(uint64_t addr) const;

    /// Check if an address is a sentinel
    bool is_sentinel(uint64_t addr) const;

    /// Get/Set last error (shared with GetLastError/SetLastError)
    uint32_t last_error() const { return last_error_; }
    void set_last_error(uint32_t err) { last_error_ = err; }

    /// TLS allocation tracking
    uint32_t tls_alloc();
    void tls_free(uint32_t index);
    void tls_set(uint32_t index, uint32_t value);
    uint32_t tls_get(uint32_t index) const;

    /// Handle tracking for CloseHandle
    uint32_t alloc_handle();
    void close_handle(uint32_t h);

    /// Set thread manager for thread-aware API stubs
    void set_thread_manager(ThreadManager* tm) { thread_manager_ = tm; }
    ThreadManager* thread_manager() const { return thread_manager_; }

    // ===== Helpers (public for use by external API registration functions) =====

    /// Read a stack argument (stdcall, 0-indexed: arg0 at [ESP+4])
    uint32_t stack_arg(int index) const;

    /// Perform stdcall return (set EAX, pop return addr + num_bytes of args)
    void stdcall_return(uint32_t retval, uint32_t num_bytes);

    /// cdecl return (set EAX, pop return addr only, caller cleans args)
    void cdecl_return(uint32_t retval);

private:
    X86Backend& cpu_;
    VirtualMemory& vmem_;
    EmulatedHeap& heap_;

    // Sentinel address -> (dll_name, func_name)
    PELoader::SentinelMap sentinel_map_;

    // Func name (lowercase) -> handler
    std::map<std::string, NativeAPIHandler> native_handlers_;

    // Lua handlers (stored as opaque pointers to avoid sol2 dependency in header)
    struct LuaHandler;
    std::map<std::string, std::shared_ptr<LuaHandler>> lua_handlers_;

    // State
    uint32_t last_error_ = 0;
    uint32_t next_tls_index_ = 0;
    std::map<uint32_t, uint32_t> tls_values_;
    uint32_t next_handle_ = 0x100;
    uint32_t tick_count_ = 100000;  // Fake tick count

    // VirtualAlloc tracking for VirtualQuery
    struct AllocInfo {
        uint32_t base;
        uint32_t size;
        uint32_t protect;
    };
    std::map<uint32_t, AllocInfo> virtual_allocs_;

    // errno storage for _errno
    uint32_t errno_addr_ = 0;

    // Thread manager (optional, set via set_thread_manager)
    ThreadManager* thread_manager_ = nullptr;

    // Helper: normalize function name for lookup
    static std::string normalize(const std::string& name);

    // Builtin registration helpers
    void register_memory_apis();
    void register_crt_apis();
    void register_module_apis();
    void register_thread_apis();
    void register_sync_apis();
    void register_error_apis();
    void register_misc_apis();
};

/// Register ntoskrnl.exe API stubs for kernel driver emulation
void register_ntoskrnl_apis(APIDispatcher& disp);

/// Register extended kernel32 APIs (W/Ex variants, file, process, sync, etc.)
void register_extended_apis(APIDispatcher& disp);

/// Register ntdll APIs, syscall interceptor, and device I/O handlers
void register_ntdll_apis(APIDispatcher& disp);

/// Register ws2_32.dll Winsock API stubs for network behavior analysis
void register_ws2_32_apis(APIDispatcher& api);

} // namespace vx
