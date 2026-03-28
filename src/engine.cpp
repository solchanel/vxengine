/**
 * VXEngine Main Orchestrator
 *
 * Ties together CPU backend, virtual memory, PE loader, Windows environment,
 * API dispatcher, tracer, Lua scripting, and Z3 solver into a single
 * cohesive engine for obfuscated binary analysis.
 */

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#include "vxengine/engine.h"
#include "vxengine/lua_bindings.h"
#include "vxengine/cpu/x86/x86_cpu.h"
#include "../src/behavior_report.h"
#include "../src/registry.h"
#include "../src/vfs.h"
#include "../src/unpacker.h"
#include "../src/pe_writer.h"
#ifdef VX_ENABLE_Z3
#include "vxengine/solver.h"
#endif

#include <fstream>
#include <iostream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cassert>

namespace fs = std::filesystem;

namespace vx {

// Forward declarations for API registration functions
void register_advapi32_apis(APIDispatcher& api, Registry& reg);
void register_advapi32_security_apis(APIDispatcher& api);
void register_ws2_32_apis(APIDispatcher& api);
void register_wininet_apis(APIDispatcher& api);
void register_winhttp_apis(APIDispatcher& api);
void register_user32_apis(APIDispatcher& api);
void register_crypt32_apis(APIDispatcher& api);
void register_ole32_apis(APIDispatcher& api);
void register_vfs_apis(APIDispatcher& api, VirtualFileSystem& vfs);
void register_hal_apis(APIDispatcher& api);
void register_fltmgr_apis(APIDispatcher& api);
void register_cng_apis(APIDispatcher& api);

// ============================================================
// WindowsEnvironment
// ============================================================

WindowsEnvironment::WindowsEnvironment(VirtualMemory& vmem, ICpuBackend& cpu)
    : vmem_(vmem), cpu_(cpu)
{
}

void WindowsEnvironment::setup(Arch arch) {
    // Stack: 1MB at 0x00100000 - 0x00200000
    stack_base_ = 0x00100000;
    stack_top_  = 0x00200000;
    vmem_.map(stack_base_, stack_top_ - stack_base_, PERM_RW);
    cpu_.set_sp(stack_top_ - 0x100); // Leave some headroom

    // TEB at 0x7FFD0000
    teb_addr_ = 0x7FFD0000;
    vmem_.map(teb_addr_, PAGE_SIZE, PERM_RW);

    // PEB at 0x7FFD1000
    peb_addr_ = 0x7FFD1000;
    vmem_.map(peb_addr_, PAGE_SIZE, PERM_RW);

    // TEB->ProcessEnvironmentBlock = PEB address
    if (arch == Arch::X86_32) {
        vmem_.write32(teb_addr_ + 0x30, static_cast<uint32_t>(peb_addr_));
        // TEB->Self = TEB address
        vmem_.write32(teb_addr_ + 0x18, static_cast<uint32_t>(teb_addr_));
        // TEB->StackBase
        vmem_.write32(teb_addr_ + 0x04, static_cast<uint32_t>(stack_top_));
        // TEB->StackLimit
        vmem_.write32(teb_addr_ + 0x08, static_cast<uint32_t>(stack_base_));
    }

    // PEB fields
    if (arch == Arch::X86_32) {
        // PEB->BeingDebugged = 0 (not being debugged)
        vmem_.write(peb_addr_ + 0x02, "\x00", 1);
        // PEB->ImageBaseAddress (will be set when module is loaded)
        // PEB->NtGlobalFlag = 0 (no debug flags)
        vmem_.write32(peb_addr_ + 0x68, 0);
    }

    // Heap: simple bump allocator region at 0x00500000
    heap_base_ = 0x00500000;
    vmem_.map(heap_base_, 0x00100000, PERM_RW); // 1MB heap

    // GDT for segment registers (x86-32)
    if (arch == Arch::X86_32) {
        auto* x86 = dynamic_cast<X86Backend*>(&cpu_);
        if (x86) {
            GDTEntry gdt[8] = {};

            // Null descriptor
            gdt[0] = {0, 0, 0, 0};

            // Code segment (CS = 0x08, selector index 1)
            gdt[1] = {0, 0xFFFFF, 0x9A, 0xCF}; // 32-bit code, ring 0

            // Data segment (DS/ES/SS = 0x10, selector index 2)
            gdt[2] = {0, 0xFFFFF, 0x92, 0xCF}; // 32-bit data, ring 0

            // FS segment (FS = 0x18, selector index 3) -> TEB
            gdt[3] = {static_cast<uint32_t>(teb_addr_), 0xFFF, 0x92, 0x40};

            // GS segment (GS = 0x20, selector index 4)
            gdt[4] = {0, 0xFFFFF, 0x92, 0xCF};

            x86->setup_gdt(gdt, 5);

            // Set segment registers
            x86->set_reg(X86_CS, 0x08);
            x86->set_reg(X86_DS, 0x10);
            x86->set_reg(X86_ES, 0x10);
            x86->set_reg(X86_SS, 0x10);
            x86->set_reg(X86_FS, 0x18);
            x86->set_reg(X86_GS, 0x20);
        }
    }
}

// ============================================================
// APIDispatcher
// ============================================================

APIDispatcher::APIDispatcher(ICpuBackend& cpu, VirtualMemory& vmem)
    : cpu_(cpu), vmem_(vmem)
{
}

void APIDispatcher::register_api(const std::string& name, APIHandler handler) {
    native_handlers_[name] = std::move(handler);
}

void APIDispatcher::register_lua_api(const std::string& name, LuaAPIHandler handler) {
    lua_handlers_[name] = std::move(handler);
}

bool APIDispatcher::dispatch(uint64_t sentinel_addr) {
    auto it = sentinels_.find(sentinel_addr);
    if (it == sentinels_.end()) {
        return false;
    }

    const std::string& dll = it->second.first;
    const std::string& func = it->second.second;

    uint64_t retval = 0;

    // Check Lua handlers first (user overrides)
    auto lua_it = lua_handlers_.find(func);
    if (lua_it != lua_handlers_.end()) {
        retval = lua_it->second();
    }
    // Then native handlers
    else {
        auto native_it = native_handlers_.find(func);
        if (native_it != native_handlers_.end()) {
            retval = native_it->second(cpu_, vmem_);
        } else {
            retval = default_handler(dll, func);
        }
    }

    // Record API call in behavior report
    if (report_) {
        report_->record_api(dll, func, retval);
    }

    // Set return value (EAX for x86-32)
    cpu_.set_reg(X86_EAX, retval);

    // Simulate RET: pop return address and jump to it
    uint64_t ret_addr = 0;
    if (cpu_.pointer_size() == 4) {
        ret_addr = vmem_.read32(cpu_.sp());
        cpu_.set_sp(cpu_.sp() + 4);
    } else {
        ret_addr = vmem_.read64(cpu_.sp());
        cpu_.set_sp(cpu_.sp() + 8);
    }
    cpu_.set_pc(ret_addr);

    return true;
}

void APIDispatcher::bind_sentinels(const PELoader::SentinelMap& sentinels) {
    for (const auto& [addr, info] : sentinels) {
        sentinels_[addr] = info;
    }
}

std::vector<std::string> APIDispatcher::registered_apis() const {
    std::vector<std::string> result;
    for (const auto& [name, _] : native_handlers_) {
        result.push_back(name);
    }
    for (const auto& [name, _] : lua_handlers_) {
        result.push_back(name);
    }
    return result;
}

uint64_t APIDispatcher::default_handler(const std::string& dll,
                                         const std::string& func) {
    std::cerr << "[vx] WARNING: Unhandled API call: " << dll << "!" << func << "\n";
    return 0;
}

// ============================================================
// VXEngine
// ============================================================

VXEngine::VXEngine(Arch arch)
    : arch_(arch)
    , vmem_()
    , cpu_(ICpuBackend::create(arch, vmem_))
    , loader_(vmem_)
    , winenv_(std::make_unique<WindowsEnvironment>(vmem_, *cpu_))
    , api_(*cpu_, vmem_)
    , tracer_(*cpu_)
{
    // Set up Windows environment (TEB, PEB, GDT, stack, heap)
    winenv_->setup(arch);

    // Initialize behavior report and attach to API dispatcher
    report_ = std::make_unique<BehaviorReport>();
    api_.set_report(report_.get());

    // Initialize in-memory registry hive
    registry_ = std::make_unique<Registry>();

    // Initialize virtual filesystem
    vfs_ = std::make_unique<VirtualFileSystem>();

#ifdef VX_ENABLE_Z3
    solver_ = std::make_unique<Solver>();
    tracer_.attach_solver(solver_.get());
#endif
}

VXEngine::~VXEngine() = default;

BehaviorReport& VXEngine::report() { return *report_; }
Registry& VXEngine::registry() { return *registry_; }
VirtualFileSystem& VXEngine::vfs() { return *vfs_; }

// ============================================================
// Loading
// ============================================================

LoadedModule VXEngine::load(const std::string& path) {
    auto result = loader_.load_file(path);
    if (!result.has_value()) {
        throw std::runtime_error("Failed to load: " + path);
    }

    LoadedModule& mod = result.value();

    // Bind sentinel map for API dispatch
    api_.bind_sentinels(loader_.sentinel_map());

    // Register advapi32 registry API handlers
    register_advapi32_apis(api_, *registry_);

    // Register ws2_32 network API stubs
    register_ws2_32_apis(api_);

    // Register VFS-backed file API handlers
    register_vfs_apis(api_, *vfs_);

    // Register additional usermode DLL stubs
    register_advapi32_security_apis(api_);
    register_wininet_apis(api_);
    register_winhttp_apis(api_);
    register_user32_apis(api_);
    register_crypt32_apis(api_);
    register_ole32_apis(api_);

    // Register kernel module stubs
    register_hal_apis(api_);
    register_fltmgr_apis(api_);
    register_cng_apis(api_);

    // Set sample name for behavior report
    report_->set_sample_name(path);

    // Set up a sentinel hit handler: when CPU executes a sentinel address,
    // we intercept and route to the API dispatcher.
    // This is done by adding a code hook on the sentinel range.
    uint64_t sentinel_end = loader_.next_sentinel();
    if (sentinel_end > SENTINEL_BASE) {
        // Map sentinel pages (small stubs: each just contains RET)
        uint64_t sentinel_size = ((sentinel_end - SENTINEL_BASE) + PAGE_SIZE - 1)
                                 & PAGE_MASK;
        if (sentinel_size == 0) sentinel_size = PAGE_SIZE;
        vmem_.map(SENTINEL_BASE, sentinel_size, PERM_RX);

        // Write a RET instruction at each sentinel
        for (uint64_t addr = SENTINEL_BASE; addr < sentinel_end; ++addr) {
            uint8_t ret_opcode = 0xC3;
            vmem_.write(addr, &ret_opcode, 1);
        }
    }

    // Update PEB->ImageBaseAddress
    if (arch_ == Arch::X86_32 && winenv_) {
        vmem_.write32(winenv_->peb_addr() + 0x08,
                      static_cast<uint32_t>(mod.base));
    }

    // Store the loaded module for later use (unpack, export, etc.)
    loaded_mod_ = mod;

    return mod;
}

void VXEngine::run_dll_init(LoadedModule& mod) {
    if (mod.entry_point == 0) {
        return;
    }

    // For a DLL: call DllMain(hModule, DLL_PROCESS_ATTACH, 0)
    std::vector<uint64_t> args = {mod.base, 1 /* DLL_PROCESS_ATTACH */, 0};
    call(mod.entry_point, args);
}

// ============================================================
// Execution
// ============================================================

void VXEngine::call(uint64_t addr, std::vector<uint64_t> args) {
    // Set up a return sentinel: push a special address that will stop execution
    uint64_t return_sentinel = 0xDEADC0DE;
    vmem_.map(return_sentinel & PAGE_MASK, PAGE_SIZE, PERM_RX);
    uint8_t hlt_opcode = 0xF4; // HLT
    vmem_.write(return_sentinel, &hlt_opcode, 1);

    // Push arguments in reverse order (cdecl calling convention)
    for (auto it = args.rbegin(); it != args.rend(); ++it) {
        uint64_t sp = cpu_->sp();
        if (cpu_->pointer_size() == 4) {
            sp -= 4;
            vmem_.write32(sp, static_cast<uint32_t>(*it));
        } else {
            sp -= 8;
            vmem_.write64(sp, *it);
        }
        cpu_->set_sp(sp);
    }

    // Push return address
    uint64_t sp = cpu_->sp();
    if (cpu_->pointer_size() == 4) {
        sp -= 4;
        vmem_.write32(sp, static_cast<uint32_t>(return_sentinel));
    } else {
        sp -= 8;
        vmem_.write64(sp, return_sentinel);
    }
    cpu_->set_sp(sp);

    // Set PC to function address
    cpu_->set_pc(addr);

    // Run until we hit the return sentinel or an error
    constexpr uint64_t MAX_INSNS = 10000000; // 10M instruction safety limit
    uint64_t count = 0;

    while (count < MAX_INSNS) {
        uint64_t pc = cpu_->pc();

        // Check if we hit the return sentinel
        if (pc == return_sentinel) {
            break;
        }

        // Check if we hit an API sentinel
        if (pc >= SENTINEL_BASE && pc < loader_.next_sentinel()) {
            if (!api_.dispatch(pc)) {
                std::cerr << "[vx] Unknown sentinel at 0x" << std::hex << pc << "\n";
                break;
            }
            count++;
            continue;
        }

        StepResult result = cpu_->step();
        count++;

        if (result.reason == StopReason::EXCEPTION ||
            result.reason == StopReason::ERROR ||
            result.reason == StopReason::HALT) {
            if (cpu_->pc() != return_sentinel) {
                std::cerr << "[vx] Execution stopped: reason="
                          << static_cast<int>(result.reason)
                          << " at 0x" << std::hex << result.addr << "\n";
            }
            break;
        }
    }

    if (count >= MAX_INSNS) {
        std::cerr << "[vx] WARNING: Instruction limit reached (" << MAX_INSNS << ")\n";
    }
}

StepResult VXEngine::step() {
    uint64_t pc = cpu_->pc();

    // Check API sentinel
    if (pc >= SENTINEL_BASE && pc < loader_.next_sentinel()) {
        api_.dispatch(pc);
        StepResult r{};
        r.addr = pc;
        r.reason = StopReason::SENTINEL_HIT;
        r.disasm = "<api_call>";
        return r;
    }

    return tracer_.step();
}

RunResult VXEngine::run_until(uint64_t addr, uint64_t max_insns) {
    RunResult result{};
    uint64_t count = 0;
    uint64_t limit = max_insns > 0 ? max_insns : 10000000;

    while (count < limit) {
        uint64_t pc = cpu_->pc();

        if (pc == addr) {
            result.reason = StopReason::ADDRESS_HIT;
            result.stop_addr = addr;
            result.insn_count = count;
            return result;
        }

        // API sentinel check
        if (pc >= SENTINEL_BASE && pc < loader_.next_sentinel()) {
            api_.dispatch(pc);
            count++;
            continue;
        }

        StepResult sr = cpu_->step();
        count++;

        if (sr.reason == StopReason::BREAKPOINT ||
            sr.reason == StopReason::EXCEPTION ||
            sr.reason == StopReason::ERROR ||
            sr.reason == StopReason::HALT) {
            result.reason = sr.reason;
            result.stop_addr = sr.addr;
            result.insn_count = count;
            return result;
        }
    }

    result.reason = StopReason::MAX_INSNS;
    result.stop_addr = cpu_->pc();
    result.insn_count = count;
    return result;
}

// ============================================================
// Watchpoints / table monitoring
// ============================================================

void VXEngine::watch_table(uint64_t addr, size_t count, size_t entry_size) {
    for (size_t i = 0; i < count; ++i) {
        uint64_t entry_addr = addr + i * entry_size;
        size_t idx = i; // capture by value

        vmem_.add_watchpoint(entry_addr, entry_size,
            [idx, entry_addr, entry_size, this](uint64_t a, uint32_t s,
                                                 uint64_t val,
                                                 AccessType type) -> bool {
                if (type == AccessType::WRITE) {
                    std::cout << "[vx] Handler table[" << idx
                              << "] @ 0x" << std::hex << entry_addr
                              << " = 0x" << val << "\n";
                }
                return true; // Continue execution
            }, AccessType::WRITE);
    }
}

// ============================================================
// Scripting
// ============================================================

void VXEngine::init_lua() {
    if (lua_initialized_) return;

    lua_ = std::make_unique<sol::state>();
    register_lua_bindings(*lua_, this);
    lua_initialized_ = true;
}

sol::state& VXEngine::lua() {
    init_lua();
    return *lua_;
}

void VXEngine::run_script(const std::string& lua_path) {
    init_lua();

    auto result = lua_->safe_script_file(lua_path, sol::script_pass_on_error);
    if (!result.valid()) {
        sol::error err = result;
        std::cerr << "[vx] Lua error in " << lua_path << ": " << err.what() << "\n";
        throw std::runtime_error(std::string("Lua error: ") + err.what());
    }
}

void VXEngine::lua_repl() {
    init_lua();
    load_init_script();

    std::cout << "VXEngine Lua REPL (type 'quit' to exit)\n";
    std::cout << ">>> ";

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "quit" || line == "exit" || line == "q") {
            break;
        }

        if (line.empty()) {
            std::cout << ">>> ";
            continue;
        }

        auto result = lua_->safe_script(line, sol::script_pass_on_error);
        if (!result.valid()) {
            sol::error err = result;
            std::cerr << "Error: " << err.what() << "\n";
        } else if (result.return_count() > 0) {
            // Print return values
            for (int i = 0; i < result.return_count(); ++i) {
                sol::object obj = result.get<sol::object>(i);
                if (obj.is<std::string>()) {
                    std::cout << obj.as<std::string>() << "\n";
                } else if (obj.is<uint64_t>()) {
                    uint64_t val = obj.as<uint64_t>();
                    std::cout << val << " (0x" << std::hex << val << std::dec << ")\n";
                } else if (obj.is<double>()) {
                    std::cout << obj.as<double>() << "\n";
                } else if (obj.is<bool>()) {
                    std::cout << (obj.as<bool>() ? "true" : "false") << "\n";
                } else if (obj.get_type() == sol::type::nil) {
                    // Don't print nil
                } else {
                    std::cout << "<" << sol::type_name(lua_->lua_state(),
                                                        obj.get_type()) << ">\n";
                }
            }
        }

        std::cout << ">>> ";
    }

    std::cout << "\nGoodbye.\n";
}

void VXEngine::register_api(const std::string& name,
                              APIDispatcher::LuaAPIHandler handler) {
    api_.register_lua_api(name, std::move(handler));
}

void VXEngine::load_init_script() {
    // Try to find init.lua relative to the executable or in known paths
    std::vector<std::string> search_paths = {
        "lua/init.lua",
        "../lua/init.lua",
        "../share/vxengine/lua/init.lua",
    };

    for (const auto& path : search_paths) {
        if (fs::exists(path)) {
            auto result = lua_->safe_script_file(path, sol::script_pass_on_error);
            if (!result.valid()) {
                sol::error err = result;
                std::cerr << "[vx] Warning: init.lua error: " << err.what() << "\n";
            }
            return;
        }
    }

    // init.lua not found -- that's fine, continue without it
}

void VXEngine::handle_sentinel(uint64_t addr) {
    api_.dispatch(addr);
}

// ============================================================
// Shellcode Loader
// ============================================================

LoadedModule VXEngine::load_shellcode_bytes(const uint8_t* data, size_t size, uint64_t base) {
    if (base == 0) base = 0x00400000;

    // Align size to page boundary
    uint64_t aligned_size = (size + PAGE_SIZE - 1) & PAGE_MASK;
    vmem_.map(base, aligned_size, PERM_RWX);
    vmem_.write(base, data, size);

    // Set PC to base
    cpu_->set_pc(base);

    // Create synthetic LoadedModule
    LoadedModule mod;
    mod.name = "shellcode";
    mod.path = "<shellcode>";
    mod.base = base;
    mod.size = size;
    mod.entry_point = base;
    mod.image_base = base;

    LoadedModule::Section sec;
    sec.name = ".text";
    sec.va = base;
    sec.size = size;
    sec.raw_size = size;
    sec.perms = PERM_RWX;
    mod.sections.push_back(sec);

    // Update PEB
    if (arch_ == Arch::X86_32 && winenv_) {
        vmem_.write32(winenv_->peb_addr() + 0x08, static_cast<uint32_t>(base));
    }

    std::cerr << "[vx] Loaded " << size << " bytes of shellcode at 0x"
              << std::hex << base << std::dec << "\n";
    return mod;
}

LoadedModule VXEngine::load_shellcode(const std::string& path, uint64_t base) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        throw std::runtime_error("Failed to open shellcode file: " + path);
    }

    size_t size = static_cast<size_t>(ifs.tellg());
    ifs.seekg(0);
    std::vector<uint8_t> data(size);
    ifs.read(reinterpret_cast<char*>(data.data()), size);

    auto mod = load_shellcode_bytes(data.data(), data.size(), base);
    mod.path = path;
    return mod;
}

// ============================================================
// Auto-Unpack
// ============================================================

bool VXEngine::auto_unpack(const std::string& dump_path) {
    // Get the currently loaded module info
    if (!loaded_mod_.has_value()) {
        std::cerr << "[vx] No modules loaded for unpacking\n";
        return false;
    }

    const auto& mod = loaded_mod_.value();
    Unpacker unpacker(*cpu_, vmem_, loader_);
    unpacker.arm(mod);

    // Run until OEP detected or instruction limit
    constexpr uint64_t MAX_INSNS = 50000000; // 50M
    uint64_t count = 0;

    while (count < MAX_INSNS) {
        uint64_t pc = cpu_->pc();

        if (unpacker.check(pc)) {
            auto result = unpacker.dump(dump_path, mod);
            return result.success;
        }

        // API sentinel check
        if (pc >= SENTINEL_BASE && pc < loader_.next_sentinel()) {
            api_.dispatch(pc);
            count++;
            continue;
        }

        StepResult sr = cpu_->step();
        count++;

        if (sr.reason == StopReason::EXCEPTION ||
            sr.reason == StopReason::ERROR ||
            sr.reason == StopReason::HALT) {
            std::cerr << "[vx] Unpacker: Execution stopped at 0x"
                      << std::hex << sr.addr << std::dec << "\n";
            break;
        }
    }

    if (count >= MAX_INSNS) {
        std::cerr << "[vx] Unpacker: Instruction limit reached without OEP detection\n";
    }
    return false;
}

// ============================================================
// Export Exerciser
// ============================================================

std::vector<ExportResult> VXEngine::exercise_exports() {
    std::vector<ExportResult> results;

    if (!loaded_mod_.has_value()) return results;

    const auto& mod = loaded_mod_.value();
    if (mod.exports.empty()) return results;

    // Save CPU state
    uint64_t saved_pc = cpu_->pc();
    uint64_t saved_sp = cpu_->sp();
    uint64_t saved_eax = cpu_->reg(X86_EAX);

    for (const auto& exp : mod.exports) {
        ExportResult er;
        er.name = exp.name;
        er.address = exp.addr;

        // Restore stack pointer
        cpu_->set_sp(saved_sp);

        try {
            // Call with 4 zero args, 100k instruction limit
            call(exp.addr, {0, 0, 0, 0});
            er.completed = true;
            er.stop_reason = StopReason::HALT;
        } catch (...) {
            er.completed = false;
            er.stop_reason = StopReason::ERROR;
        }

        results.push_back(er);
        std::cerr << "[vx] Export '" << exp.name << "' @ 0x" << std::hex
                  << exp.addr << ": " << (er.completed ? "OK" : "FAIL")
                  << std::dec << "\n";
    }

    // Restore CPU state
    cpu_->set_pc(saved_pc);
    cpu_->set_sp(saved_sp);
    cpu_->set_reg(X86_EAX, saved_eax);

    return results;
}

// ============================================================
// PE Writer (Export for Debugger)
// ============================================================

bool VXEngine::export_for_debugger(const std::string& path, uint64_t oep) {
    if (!loaded_mod_.has_value()) {
        std::cerr << "[vx] No modules loaded for export\n";
        return false;
    }

    return PEWriter::write(path, vmem_, loaded_mod_.value(), oep, loader_.sentinel_map());
}

} // namespace vx
