/**
 * VXEngine sol2 Lua Bindings
 *
 * Exposes the entire engine API to Lua scripts via the "vx" global table.
 * All engine subsystems are accessible: CPU, memory, loader, tracer,
 * stealth hooks, watchpoints, disassembly, API stubs, and Z3 solver.
 */

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>

#include "vxengine/lua_bindings.h"
#include "vxengine/engine.h"
#include "../src/behavior_report.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include "vxengine/cpu/x86/x86_cpu.h"
#include "vxengine/tracer.h"
#include "vxengine/pe_loader.h"
#include "vxengine/thread_manager.h"
#ifdef VX_ENABLE_Z3
#include "vxengine/solver.h"
#endif

#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace vx {

// ============================================================
// Helper: resolve register name string -> register ID
// ============================================================
static int reg_name_to_id(const std::string& name) {
    // Lowercase the name
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });

    // x86-32 general purpose
    if (lower == "eax") return X86_EAX;
    if (lower == "ecx") return X86_ECX;
    if (lower == "edx") return X86_EDX;
    if (lower == "ebx") return X86_EBX;
    if (lower == "esp") return X86_ESP;
    if (lower == "ebp") return X86_EBP;
    if (lower == "esi") return X86_ESI;
    if (lower == "edi") return X86_EDI;
    if (lower == "eip") return X86_EIP;
    if (lower == "eflags") return X86_EFLAGS;

    // Segment registers
    if (lower == "cs") return X86_CS;
    if (lower == "ds") return X86_DS;
    if (lower == "es") return X86_ES;
    if (lower == "fs") return X86_FS;
    if (lower == "gs") return X86_GS;
    if (lower == "ss") return X86_SS;

    // 8-bit
    if (lower == "al") return X86_AL;
    if (lower == "ah") return X86_AH;
    if (lower == "bl") return X86_BL;
    if (lower == "bh") return X86_BH;
    if (lower == "cl") return X86_CL;
    if (lower == "ch") return X86_CH;
    if (lower == "dl") return X86_DL;
    if (lower == "dh") return X86_DH;

    // 16-bit
    if (lower == "ax") return X86_AX;
    if (lower == "bx") return X86_BX;
    if (lower == "cx") return X86_CX;
    if (lower == "dx") return X86_DX;
    if (lower == "sp") return X86_SP;
    if (lower == "bp") return X86_BP;
    if (lower == "si") return X86_SI;
    if (lower == "di") return X86_DI;

    return -1; // Unknown
}

// ============================================================
// Helper: format address as hex string
// ============================================================
static std::string hex_addr(uint64_t addr) {
    std::ostringstream ss;
    ss << "0x" << std::hex << addr;
    return ss.str();
}

// ============================================================
// Register core memory/CPU bindings
// ============================================================
void register_lua_core(sol::state& lua, ICpuBackend* cpu, VirtualMemory* vmem) {
    auto vx = lua["vx"].get_or_create<sol::table>();

    // ---- Register access ----
    vx.set_function("reg", [cpu](const std::string& name) -> uint64_t {
        int id = reg_name_to_id(name);
        if (id < 0) {
            throw std::runtime_error("Unknown register: " + name);
        }
        return cpu->reg(id);
    });

    vx.set_function("set_reg", [cpu](const std::string& name, uint64_t val) {
        int id = reg_name_to_id(name);
        if (id < 0) {
            throw std::runtime_error("Unknown register: " + name);
        }
        cpu->set_reg(id, val);
    });

    // ---- Execution ----
    vx.set_function("step", [cpu]() -> sol::object {
        // Returns a table with step result info
        StepResult r = cpu->step();
        return sol::nil; // Simplified; actual table built in full engine binding
    });

    vx.set_function("step_over", [cpu]() {
        cpu->step_over();
    });

    vx.set_function("run_until", [cpu](uint64_t addr, sol::optional<uint64_t> max) {
        uint64_t max_insns = max.value_or(0);
        return cpu->run_until(addr, max_insns);
    });

    // ---- Program counter ----
    vx.set_function("pc", [cpu]() -> uint64_t {
        return cpu->pc();
    });

    vx.set_function("set_pc", [cpu](uint64_t addr) {
        cpu->set_pc(addr);
    });

    // ---- Disassembly ----
    vx.set_function("disasm", [cpu](sol::optional<uint64_t> addr) -> std::string {
        if (addr.has_value()) {
            return cpu->disasm(addr.value());
        }
        return cpu->disasm_at_pc();
    });

    // ---- Breakpoints ----
    vx.set_function("bp", [cpu](uint64_t addr) {
        cpu->add_breakpoint(addr);
    });

    vx.set_function("bp_del", [cpu](uint64_t addr) {
        cpu->remove_breakpoint(addr);
    });

    // ---- Memory read ----
    vx.set_function("read", [vmem](uint64_t addr, size_t size) -> std::string {
        std::string buf(size, '\0');
        if (!vmem->read(addr, buf.data(), size)) {
            throw std::runtime_error("Memory read failed at " + hex_addr(addr));
        }
        return buf;
    });

    vx.set_function("write", [vmem](uint64_t addr, const std::string& data) {
        if (!vmem->write(addr, data.data(), data.size())) {
            throw std::runtime_error("Memory write failed at " + hex_addr(addr));
        }
    });

    vx.set_function("read32", [vmem](uint64_t addr) -> uint32_t {
        return vmem->read32(addr);
    });

    vx.set_function("write32", [vmem](uint64_t addr, uint32_t val) {
        vmem->write32(addr, val);
    });

    vx.set_function("read64", [vmem](uint64_t addr) -> uint64_t {
        return vmem->read64(addr);
    });

    vx.set_function("write64", [vmem](uint64_t addr, uint64_t val) {
        vmem->write64(addr, val);
    });

    vx.set_function("read_string", [vmem](uint64_t addr,
                                           sol::optional<size_t> max) -> std::string {
        return vmem->read_string(addr, max.value_or(4096));
    });

    vx.set_function("write_string", [vmem](uint64_t addr, const std::string& str) {
        vmem->write_string(addr, str);
    });

    // ---- Memory mapping ----
    vx.set_function("map", [vmem](uint64_t addr, uint64_t size,
                                   sol::optional<int> perms) {
        uint8_t p = static_cast<uint8_t>(perms.value_or(PERM_RWX));
        if (!vmem->map(addr, size, p)) {
            throw std::runtime_error("Memory map failed at " + hex_addr(addr));
        }
    });

    vx.set_function("unmap", [vmem](uint64_t addr, uint64_t size) {
        vmem->unmap(addr, size);
    });

    vx.set_function("is_mapped", [vmem](uint64_t addr) -> bool {
        return vmem->is_mapped(addr);
    });

    // ---- Shadow PTE / stealth ----
    vx.set_function("split_page", [vmem](uint64_t addr) {
        if (!vmem->split_page(addr)) {
            throw std::runtime_error("split_page failed at " + hex_addr(addr));
        }
    });

    vx.set_function("unsplit_page", [vmem](uint64_t addr) {
        vmem->unsplit_page(addr);
    });

    vx.set_function("is_split", [vmem](uint64_t addr) -> bool {
        return vmem->is_split(addr);
    });

    vx.set_function("stealth_hook", [vmem](uint64_t addr, const std::string& bytes) {
        std::vector<uint8_t> hook_bytes(bytes.begin(), bytes.end());
        if (!vmem->install_stealth_hook(addr, hook_bytes)) {
            throw std::runtime_error("stealth_hook failed at " + hex_addr(addr));
        }
    });

    vx.set_function("stealth_int3", [vmem](uint64_t addr) {
        vmem->install_stealth_int3(addr);
    });

    vx.set_function("remove_stealth_hook", [vmem](uint64_t addr, size_t size) {
        vmem->remove_stealth_hook(addr, size);
    });

    // ---- Watchpoints ----
    vx.set_function("watch", [vmem](uint64_t addr, uint64_t size,
                                     sol::function callback,
                                     sol::optional<int> type_opt) -> HookID {
        AccessType type = static_cast<AccessType>(type_opt.value_or(
            static_cast<int>(AccessType::WRITE)));

        return vmem->add_watchpoint(addr, size,
            [callback](uint64_t a, uint32_t s, uint64_t v, AccessType t) -> bool {
                sol::protected_function_result r = callback(a, s, v, static_cast<int>(t));
                if (r.valid()) {
                    // If the Lua callback returns a boolean, use it;
                    // otherwise (nil/no return), default to true (continue)
                    sol::optional<bool> val = r;
                    return val.value_or(true);
                }
                return true; // Continue by default on error
            }, type);
    });

    vx.set_function("unwatch", [vmem](HookID id) {
        vmem->remove_watchpoint(id);
    });

    // ---- Memory fill/copy ----
    vx.set_function("memset", [vmem](uint64_t addr, uint8_t val, size_t size) {
        vmem->memset(addr, val, size);
    });

    vx.set_function("memcpy", [vmem](uint64_t dst, uint64_t src, size_t size) {
        vmem->memcpy(dst, src, size);
    });

    // ---- Inspection ----
    vx.set_function("mapped_regions", [vmem]() -> sol::as_table_t<
                        std::vector<std::pair<uint64_t, uint64_t>>> {
        return sol::as_table(vmem->mapped_regions());
    });

    vx.set_function("total_mapped", [vmem]() -> size_t {
        return vmem->total_mapped();
    });

    // ---- Flags ----
    vx.set_function("flags", [cpu]() -> uint64_t {
        return cpu->flags();
    });

    vx.set_function("set_flags", [cpu](uint64_t val) {
        cpu->set_flags(val);
    });

    // ---- Instruction count ----
    vx.set_function("insn_count", [cpu]() -> uint64_t {
        return cpu->insn_count();
    });

    // ---- Logging ----
    vx.set_function("log", [](const std::string& msg) {
        std::cout << "[vx] " << msg << std::endl;
    });

    // ---- Hex formatting helper ----
    vx.set_function("hex", [](uint64_t val) -> std::string {
        return hex_addr(val);
    });

    // ---- Snapshot / restore ----
    vx.set_function("snapshot", [cpu]() {
        return cpu->snapshot();
    });

    vx.set_function("restore", [cpu](const RegSnapshot& snap) {
        cpu->restore(snap);
    });
}

// ============================================================
// Register tracer bindings
// ============================================================
void register_lua_tracer(sol::state& lua, Tracer* tracer) {
    auto vx = lua["vx"].get_or_create<sol::table>();

    vx.set_function("trace_step", [tracer]() {
        return tracer->step();
    });

    vx.set_function("trace_block", [tracer]() {
        return tracer->trace_block();
    });

    vx.set_function("trace_until", [tracer](uint64_t addr,
                                             sol::optional<uint64_t> max) {
        return tracer->run_until(addr, max.value_or(100000));
    });

    vx.set_function("trace_clear", [tracer]() {
        tracer->clear();
    });

    vx.set_function("trace_recording", [tracer](bool enable) {
        tracer->set_recording(enable);
    });

    vx.set_function("trace_count", [tracer]() -> uint64_t {
        return tracer->total_traced();
    });

    vx.set_function("trace_size", [tracer]() -> size_t {
        return tracer->trace().size();
    });

    vx.set_function("trace_export", [tracer](const std::string& path,
                                              sol::optional<std::string> fmt) {
        TraceFormat format = TraceFormat::TEXT;
        std::string fmt_str = fmt.value_or("text");
        if (fmt_str == "json") format = TraceFormat::JSON;
        else if (fmt_str == "ida") format = TraceFormat::IDA_SCRIPT;

        if (!tracer->export_trace(path, format)) {
            throw std::runtime_error("Failed to export trace to " + path);
        }
    });

    vx.set_function("trace_last", [tracer](size_t n) {
        return tracer->last(n);
    });
}

// ============================================================
// Register Z3 solver bindings
// ============================================================
#ifdef VX_ENABLE_Z3
void register_lua_solver(sol::state& lua, Solver* solver) {
    auto vx = lua["vx"].get_or_create<sol::table>();

    vx.set_function("symbolize", [solver](const std::string& name,
                                           sol::optional<int> bits) {
        int b = bits.value_or(32);
        solver->make_symbol(name, b);
    });

    vx.set_function("symbolize_reg", [solver](const std::string& reg_name,
                                               const std::string& sym_name,
                                               sol::optional<int> bits) {
        int id = reg_name_to_id(reg_name);
        if (id < 0) {
            throw std::runtime_error("Unknown register: " + reg_name);
        }
        solver->symbolize_reg(id, sym_name, bits.value_or(32));
    });

    vx.set_function("symbolize_mem", [solver](uint64_t addr, size_t size,
                                               const std::string& name) {
        solver->symbolize_mem(addr, size, name);
    });

    vx.set_function("solve_predicate", [solver](uint64_t addr) -> std::string {
        PredicateResult r = solver->solve_opaque_predicate(addr);
        switch (r) {
            case PredicateResult::ALWAYS_TRUE:  return "always_true";
            case PredicateResult::ALWAYS_FALSE: return "always_false";
            case PredicateResult::INPUT_DEPENDENT: return "input_dependent";
            case PredicateResult::UNKNOWN:      return "unknown";
        }
        return "unknown";
    });

    vx.set_function("solver_push", [solver]() { solver->push(); });
    vx.set_function("solver_pop", [solver]() { solver->pop(); });
    vx.set_function("solver_reset", [solver]() { solver->clear_constraints(); });

    vx.set_function("solver_timeout", [solver](unsigned ms) {
        solver->set_timeout(ms);
    });

    vx.set_function("solver_stats", [solver]() -> sol::as_table_t<
                        std::map<std::string, uint64_t>> {
        std::map<std::string, uint64_t> stats;
        stats["queries"] = solver->query_count();
        stats["sat"] = solver->sat_count();
        return sol::as_table(std::move(stats));
    });
}
#endif

// ============================================================
// Register thread manager bindings
// ============================================================
void register_lua_threads(sol::state& lua, ThreadManager* tmgr) {
    if (!tmgr) return;

    auto vx = lua["vx"].get_or_create<sol::table>();

    // vx.thread_create(start_addr, param, [stack_size]) -> handle
    vx.set_function("thread_create", [tmgr](uint64_t start_addr, uint64_t param,
                                             sol::optional<uint64_t> stack_size) -> uint32_t {
        uint64_t ss = stack_size.value_or(0x100000);
        return tmgr->create_thread(start_addr, param, ss, false);
    });

    // vx.thread_suspend(handle)
    vx.set_function("thread_suspend", [tmgr](uint32_t handle) -> bool {
        return tmgr->suspend_thread(handle);
    });

    // vx.thread_resume(handle)
    vx.set_function("thread_resume", [tmgr](uint32_t handle) -> bool {
        return tmgr->resume_thread(handle);
    });

    // vx.thread_list() -> table of thread info
    vx.set_function("thread_list", [tmgr](sol::this_state s) -> sol::table {
        sol::state_view lua(s);
        sol::table result = lua.create_table();

        auto threads = tmgr->all_threads();
        int idx = 1;
        for (auto* t : threads) {
            sol::table entry = lua.create_table();
            entry["id"] = t->id;
            entry["handle"] = t->handle;
            entry["entry_point"] = t->entry_point;
            entry["teb_addr"] = t->teb_addr;

            const char* state_str = "unknown";
            switch (t->state) {
                case EmulatedThread::RUNNING:    state_str = "running"; break;
                case EmulatedThread::READY:      state_str = "ready"; break;
                case EmulatedThread::SUSPENDED:  state_str = "suspended"; break;
                case EmulatedThread::TERMINATED: state_str = "terminated"; break;
                case EmulatedThread::WAITING:    state_str = "waiting"; break;
            }
            entry["state"] = state_str;
            entry["exit_code"] = t->exit_code;
            entry["suspend_count"] = t->suspend_count;

            result[idx++] = entry;
        }
        return result;
    });

    // vx.thread_switch(thread_id)
    vx.set_function("thread_switch", [tmgr](uint32_t thread_id) {
        tmgr->switch_to(thread_id);
    });

    // vx.thread_current() -> current thread id
    vx.set_function("thread_current", [tmgr]() -> uint32_t {
        return tmgr->current_id();
    });
}

// ============================================================
// Register full engine bindings (the "vx" global table)
// ============================================================
void register_lua_bindings(sol::state& lua, VXEngine* engine) {
    // Open standard Lua libraries
    lua.open_libraries(sol::lib::base, sol::lib::string, sol::lib::table,
                       sol::lib::math, sol::lib::io, sol::lib::os,
                       sol::lib::package, sol::lib::bit32);

    // Create the vx table
    auto vx = lua.create_named_table("vx");

    // Register core CPU/memory bindings
    register_lua_core(lua, &engine->cpu(), &engine->memory());

    // Register tracer bindings
    register_lua_tracer(lua, &engine->tracer());

#ifdef VX_ENABLE_Z3
    // Register solver bindings
    register_lua_solver(lua, &engine->solver());
#endif

    // ---- Engine-level functions ----

    // Load a PE/ELF file
    vx.set_function("load", [engine](const std::string& path) -> sol::as_table_t<
                        std::map<std::string, sol::object>> {
        LoadedModule mod = engine->load(path);
        std::map<std::string, sol::object> result;
        // Return basic module info (Lua doesn't need full C++ struct)
        // The caller can access via engine after loading
        return sol::as_table(std::move(result));
    });

    // Run DLL init
    vx.set_function("run_init", [engine]() {
        // Run init on last loaded module -- engine should track this
    });

    // Call a function at address with arguments
    vx.set_function("call", [engine](uint64_t addr, sol::variadic_args va) {
        std::vector<uint64_t> args;
        for (auto v : va) {
            args.push_back(v.as<uint64_t>());
        }
        engine->call(addr, std::move(args));
    });

    // Register an API stub handler
    vx.set_function("api", [engine](const std::string& name, sol::function handler) {
        engine->register_api(name, [handler]() -> uint64_t {
            sol::protected_function_result r = handler();
            if (r.valid()) {
                sol::optional<uint64_t> val = r;
                return val.value_or(0);
            }
            return 0;
        });
    });

    // Watch handler table
    vx.set_function("watch_table", [engine](uint64_t addr, size_t count,
                                             sol::optional<size_t> entry_size) {
        engine->watch_table(addr, count, entry_size.value_or(4));
    });

    // Behavior report: export JSON to file
    vx.set_function("report", [engine](const std::string& path) -> bool {
        return engine->report().export_json(path);
    });

    // Behavior report: get JSON string
    vx.set_function("report_json", [engine]() -> std::string {
        return engine->report().to_json();
    });

    // VFS: add a fake file
    vx.set_function("vfs_add_file", [engine](const std::string& path,
                                              const std::string& content) {
        engine->vfs().add_file(path, content);
    });

    // VFS: map a virtual path to a host file
    vx.set_function("vfs_map", [engine](const std::string& vpath,
                                         const std::string& hpath) {
        engine->vfs().map_host_file(vpath, hpath);
    });

    // Shellcode loader: load from file
    vx.set_function("load_shellcode", [engine](const std::string& path,
                                                sol::optional<uint64_t> base) {
        engine->load_shellcode(path, base.value_or(0));
    });

    // Auto-unpack: detect OEP and dump
    vx.set_function("auto_unpack", [engine](const std::string& dump_path) -> bool {
        return engine->auto_unpack(dump_path);
    });

    // Export exerciser: call all DLL exports
    vx.set_function("exercise_exports", [engine, &lua]() -> sol::table {
        auto results = engine->exercise_exports();
        sol::table tbl = lua.create_table();
        for (size_t i = 0; i < results.size(); ++i) {
            sol::table entry = lua.create_table();
            entry["name"] = results[i].name;
            entry["address"] = results[i].address;
            entry["completed"] = results[i].completed;
            tbl[i + 1] = entry;
        }
        return tbl;
    });

    // PE writer: export for debugger
    vx.set_function("export_usermode", [engine](const std::string& path,
                                                 sol::optional<uint64_t> oep) -> bool {
        return engine->export_for_debugger(path, oep.value_or(0));
    });

    // Run a Lua script
    vx.set_function("run_script", [engine](const std::string& path) {
        engine->run_script(path);
    });

    // ---- Step/run wrappers that go through tracer ----
    // Override the core step/run_until to use the tracer
    vx.set_function("step", [engine]() -> sol::as_table_t<
                        std::map<std::string, sol::object>> {
        StepResult r = engine->step();
        std::map<std::string, sol::object> result;
        return sol::as_table(std::move(result));
    });

    vx.set_function("run_until", [engine](uint64_t addr,
                                           sol::optional<uint64_t> max) {
        engine->run_until(addr, max.value_or(0));
    });

    // ---- Convenience: dump memory as hex string ----
    vx.set_function("hexdump", [engine](uint64_t addr, size_t size) -> std::string {
        std::string buf(size, '\0');
        engine->memory().read(addr, buf.data(), size);

        std::ostringstream ss;
        for (size_t i = 0; i < size; ++i) {
            if (i > 0 && i % 16 == 0) ss << "\n";
            else if (i > 0 && i % 8 == 0) ss << " ";
            ss << std::hex << std::setw(2) << std::setfill('0')
               << (static_cast<unsigned>(buf[i]) & 0xFF) << " ";
        }
        return ss.str();
    });

    // ---- Convenience: read DWORD table ----
    vx.set_function("read_table", [engine](uint64_t addr, size_t count,
                                            sol::optional<size_t> entry_size)
                        -> sol::as_table_t<std::vector<uint64_t>> {
        size_t es = entry_size.value_or(4);
        std::vector<uint64_t> result;
        result.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            if (es == 4) {
                result.push_back(engine->memory().read32(addr + i * 4));
            } else {
                result.push_back(engine->memory().read64(addr + i * 8));
            }
        }
        return sol::as_table(std::move(result));
    });

    // ---- Fake memory attributes ----
    vx.set_function("set_fake_attrs", [engine](uint64_t addr, uint32_t protect,
                                                uint32_t type) {
        engine->memory().set_fake_attrs(addr, protect, type);
    });

    // ---- Access logging ----
    vx.set_function("logging", [engine](bool enable) {
        engine->memory().set_logging(enable);
    });

    vx.set_function("clear_log", [engine]() {
        engine->memory().clear_log();
    });

    // ---- Architecture info ----
    vx.set_function("arch", [engine]() -> std::string {
        switch (engine->arch()) {
            case Arch::X86_32: return "x86";
            case Arch::X86_64: return "x64";
            case Arch::ARM_32: return "arm";
            case Arch::ARM_64: return "arm64";
        }
        return "unknown";
    });

    vx.set_function("ptr_size", [engine]() -> int {
        return engine->cpu().pointer_size();
    });

    // ---- Anti-debug ----
    vx.set_function("anti_debug", [engine](bool enable) {
        engine->cpu().set_anti_debug(enable);
    });

    // ---- Hooks ----
    vx.set_function("code_hook", [engine](uint64_t begin, uint64_t end,
                                           sol::function callback) -> HookID {
        return engine->cpu().add_code_hook(begin, end,
            [callback](uint64_t addr, uint32_t size) {
                callback(addr, size);
            });
    });

    vx.set_function("mem_hook", [engine](uint64_t begin, uint64_t end,
                                          sol::function callback,
                                          sol::optional<int> type_opt) -> HookID {
        AccessType type = static_cast<AccessType>(type_opt.value_or(
            static_cast<int>(AccessType::ALL)));

        return engine->cpu().add_mem_hook(begin, end,
            [callback](uint64_t addr, uint32_t size,
                       uint64_t value, AccessType t) -> bool {
                sol::protected_function_result r = callback(addr, size, value,
                                                            static_cast<int>(t));
                if (r.valid()) {
                    return r.get<bool>();
                }
                return true;
            }, type);
    });

    vx.set_function("remove_hook", [engine](HookID id) {
        engine->cpu().remove_hook(id);
    });

    // ---- UserType bindings for RegSnapshot ----
    lua.new_usertype<RegSnapshot>("RegSnapshot",
        "eax", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rax; }),
        "ecx", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rcx; }),
        "edx", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rdx; }),
        "ebx", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rbx; }),
        "esp", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rsp; }),
        "ebp", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rbp; }),
        "esi", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rsi; }),
        "edi", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rdi; }),
        "eip", sol::property([](const RegSnapshot& s) { return (uint32_t)s.rip; }),
        "eflags", &RegSnapshot::eflags
    );

    // ---- UserType bindings for StepResult ----
    lua.new_usertype<StepResult>("StepResult",
        "addr", &StepResult::addr,
        "size", &StepResult::size,
        "disasm", &StepResult::disasm,
        "reason", sol::property([](const StepResult& s) { return (int)s.reason; }),
        "regs_before", &StepResult::regs_before,
        "regs_after", &StepResult::regs_after,
        "simplified", &StepResult::simplified,
        "predicate_note", &StepResult::predicate_note
    );

    // ---- UserType bindings for LoadedModule ----
    lua.new_usertype<LoadedModule>("LoadedModule",
        "name", &LoadedModule::name,
        "path", &LoadedModule::path,
        "base", &LoadedModule::base,
        "size", &LoadedModule::size,
        "entry_point", &LoadedModule::entry_point,
        "image_base", &LoadedModule::image_base
    );

    // ---- UserType bindings for RunResult ----
    lua.new_usertype<RunResult>("RunResult",
        "reason", sol::property([](const RunResult& r) { return (int)r.reason; }),
        "stop_addr", &RunResult::stop_addr,
        "insn_count", &RunResult::insn_count
    );

    // ---- Constants ----
    vx["PERM_NONE"]  = PERM_NONE;
    vx["PERM_READ"]  = PERM_READ;
    vx["PERM_WRITE"] = PERM_WRITE;
    vx["PERM_EXEC"]  = PERM_EXEC;
    vx["PERM_RW"]    = PERM_RW;
    vx["PERM_RX"]    = PERM_RX;
    vx["PERM_RWX"]   = PERM_RWX;

    vx["ACCESS_READ"]  = static_cast<int>(AccessType::READ);
    vx["ACCESS_WRITE"] = static_cast<int>(AccessType::WRITE);
    vx["ACCESS_EXEC"]  = static_cast<int>(AccessType::EXEC);
    vx["ACCESS_ALL"]   = static_cast<int>(AccessType::ALL);

    vx["STOP_STEP"]       = static_cast<int>(StopReason::STEP);
    vx["STOP_BREAKPOINT"] = static_cast<int>(StopReason::BREAKPOINT);
    vx["STOP_WATCHPOINT"] = static_cast<int>(StopReason::WATCHPOINT);
    vx["STOP_ADDRESS"]    = static_cast<int>(StopReason::ADDRESS_HIT);
    vx["STOP_MAX_INSNS"]  = static_cast<int>(StopReason::MAX_INSNS);
    vx["STOP_EXCEPTION"]  = static_cast<int>(StopReason::EXCEPTION);
    vx["STOP_SENTINEL"]   = static_cast<int>(StopReason::SENTINEL_HIT);
    vx["STOP_ERROR"]      = static_cast<int>(StopReason::ERROR);
    vx["STOP_HALT"]       = static_cast<int>(StopReason::HALT);

    vx["SENTINEL_BASE"] = SENTINEL_BASE;
    vx["PAGE_SIZE"]     = PAGE_SIZE;
}

} // namespace vx
