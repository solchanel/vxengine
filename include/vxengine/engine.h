#pragma once
/**
 * VXEngine Main Orchestrator
 *
 * Ties together all subsystems:
 *   - CPU backend (x86/x64/ARM)
 *   - Virtual memory with shadow PTE
 *   - PE/ELF loader
 *   - Windows environment (TEB/PEB/heap)
 *   - API dispatcher (import stub routing)
 *   - Instruction tracer
 *   - sol2 Lua scripting
 *   - Z3 solver (optional)
 */

#include "vxengine.h"
#include "memory.h"
#include "cpu/icpu.h"
#include "pe_loader.h"
#include "tracer.h"

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

// Forward declare sol::state
namespace sol { class state; }

namespace vx {

#ifdef VX_ENABLE_Z3
class Solver;
#endif

/// Windows environment stub (TEB/PEB/GDT/heap setup)
class WindowsEnvironment {
public:
    explicit WindowsEnvironment(VirtualMemory& vmem, ICpuBackend& cpu);
    ~WindowsEnvironment() = default;

    /// Initialize TEB, PEB, GDT, stack, heap
    void setup(Arch arch);

    uint64_t teb_addr() const { return teb_addr_; }
    uint64_t peb_addr() const { return peb_addr_; }
    uint64_t stack_base() const { return stack_base_; }
    uint64_t stack_top() const { return stack_top_; }
    uint64_t heap_base() const { return heap_base_; }

private:
    VirtualMemory& vmem_;
    ICpuBackend& cpu_;
    uint64_t teb_addr_ = 0;
    uint64_t peb_addr_ = 0;
    uint64_t stack_base_ = 0;
    uint64_t stack_top_ = 0;
    uint64_t heap_base_ = 0;
};

/// API dispatcher: routes sentinel hits to registered stubs
class APIDispatcher {
public:
    using APIHandler = std::function<uint64_t(ICpuBackend& cpu, VirtualMemory& vmem)>;
    using LuaAPIHandler = std::function<uint64_t()>;

    explicit APIDispatcher(ICpuBackend& cpu, VirtualMemory& vmem);
    ~APIDispatcher() = default;

    /// Register a native API handler
    void register_api(const std::string& name, APIHandler handler);

    /// Register a Lua API handler
    void register_lua_api(const std::string& name, LuaAPIHandler handler);

    /// Dispatch: look up sentinel address -> call handler
    /// Returns true if handled (sentinel was recognized)
    bool dispatch(uint64_t sentinel_addr);

    /// Bind sentinel map from PE loader
    void bind_sentinels(const PELoader::SentinelMap& sentinels);

    /// Get list of registered API names
    std::vector<std::string> registered_apis() const;

private:
    ICpuBackend& cpu_;
    VirtualMemory& vmem_;

    /// sentinel_addr -> (dll, func)
    std::unordered_map<uint64_t, std::pair<std::string, std::string>> sentinels_;

    /// func_name -> handler
    std::unordered_map<std::string, APIHandler> native_handlers_;
    std::unordered_map<std::string, LuaAPIHandler> lua_handlers_;

    /// Default handler for unregistered APIs
    uint64_t default_handler(const std::string& dll, const std::string& func);
};

/// Main VXEngine class
class VXEngine {
public:
    explicit VXEngine(Arch arch = Arch::X86_32);
    ~VXEngine();

    VXEngine(const VXEngine&) = delete;
    VXEngine& operator=(const VXEngine&) = delete;

    // ===== Loading =====

    /// Load a PE/ELF file into the engine
    LoadedModule load(const std::string& path);

    /// Run DllMain / entry point initialization
    void run_dll_init(LoadedModule& mod);

    // ===== Execution =====

    /// Call a function at addr with the given arguments (pushed to stack)
    void call(uint64_t addr, std::vector<uint64_t> args = {});

    /// Single step
    StepResult step();

    /// Run until address
    RunResult run_until(uint64_t addr, uint64_t max_insns = 0);

    // ===== Watchpoints / table monitoring =====

    /// Watch a handler table: set watchpoints on each entry
    void watch_table(uint64_t addr, size_t count, size_t entry_size = 4);

    // ===== Scripting =====

    /// Run a Lua script file
    void run_script(const std::string& lua_path);

    /// Start an interactive Lua REPL
    void lua_repl();

    // ===== Accessors =====

    ICpuBackend& cpu() { return *cpu_; }
    const ICpuBackend& cpu() const { return *cpu_; }
    VirtualMemory& memory() { return vmem_; }
    const VirtualMemory& memory() const { return vmem_; }
    PELoader& loader() { return loader_; }
    Tracer& tracer() { return tracer_; }
    APIDispatcher& api() { return api_; }
    sol::state& lua();
    Arch arch() const { return arch_; }

    /// Register an API stub from Lua
    void register_api(const std::string& name,
                      APIDispatcher::LuaAPIHandler handler);

#ifdef VX_ENABLE_Z3
    Solver& solver() { return *solver_; }
#endif

private:
    Arch arch_;
    VirtualMemory vmem_;
    std::unique_ptr<ICpuBackend> cpu_;
    PELoader loader_;
    std::unique_ptr<WindowsEnvironment> winenv_;
    APIDispatcher api_;
    Tracer tracer_;
    std::unique_ptr<sol::state> lua_;
    bool lua_initialized_ = false;

#ifdef VX_ENABLE_Z3
    std::unique_ptr<Solver> solver_;
#endif

    /// Initialize Lua state and register all bindings
    void init_lua();

    /// Handle sentinel hit during execution
    void handle_sentinel(uint64_t addr);

    /// Load the init.lua startup script
    void load_init_script();
};

} // namespace vx
