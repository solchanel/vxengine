#pragma once
/**
 * VXEngine CPU Backend Interface
 *
 * Abstract interface for multi-architecture CPU emulation.
 * Implementations: X86Backend, X64Backend, ARMBackend
 */

#include "../vxengine.h"

namespace vx {

class ICpuBackend {
public:
    virtual ~ICpuBackend() = default;

    // ===== Architecture info =====
    virtual Arch arch() const = 0;
    virtual int pointer_size() const = 0;  // 4 for x86/ARM32, 8 for x64/ARM64

    // ===== Execution =====
    virtual StepResult step() = 0;
    virtual StepResult step_over() = 0;
    virtual RunResult run_until(uint64_t addr, uint64_t max_insns = 0) = 0;
    virtual RunResult run_block() = 0;  // Execute one basic block

    // ===== Register access =====
    virtual uint64_t reg(int id) const = 0;
    virtual void set_reg(int id, uint64_t val) = 0;
    virtual RegSnapshot snapshot() const = 0;
    virtual void restore(const RegSnapshot& snap) = 0;

    // Program counter
    virtual uint64_t pc() const = 0;
    virtual void set_pc(uint64_t addr) = 0;

    // Stack pointer
    virtual uint64_t sp() const = 0;
    virtual void set_sp(uint64_t addr) = 0;

    // Flags
    virtual uint64_t flags() const = 0;
    virtual void set_flags(uint64_t val) = 0;

    // ===== Disassembly =====
    virtual std::string disasm(uint64_t addr) const = 0;
    virtual std::string disasm_at_pc() const = 0;

    // ===== Hooks =====
    virtual HookID add_code_hook(uint64_t begin, uint64_t end, CodeCallback cb) = 0;
    virtual HookID add_mem_hook(uint64_t begin, uint64_t end,
                                 MemCallback cb, AccessType type) = 0;
    virtual void remove_hook(HookID id) = 0;

    // ===== Breakpoints =====
    virtual void add_breakpoint(uint64_t addr) = 0;
    virtual void remove_breakpoint(uint64_t addr) = 0;
    virtual bool has_breakpoint(uint64_t addr) const = 0;

    // ===== Anti-debug =====
    virtual void set_anti_debug(bool enable) = 0;

    // ===== Instruction count =====
    virtual uint64_t insn_count() const = 0;

    // ===== Memory reference =====
    virtual VirtualMemory& memory() = 0;
    virtual const VirtualMemory& memory() const = 0;

    // ===== Factory =====
    static std::unique_ptr<ICpuBackend> create(Arch arch, VirtualMemory& vmem);
};

} // namespace vx
