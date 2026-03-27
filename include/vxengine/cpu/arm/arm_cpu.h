#pragma once
/**
 * VXEngine ARM32 CPU Backend
 *
 * Capstone-based decoder + custom interpreter for ARM instruction semantics.
 * Handles:
 *   - ARM mode (32-bit instructions) and Thumb mode (16/32-bit instructions)
 *   - Condition code evaluation on every instruction
 *   - Barrel shifter (LSL, LSR, ASR, ROR, RRX)
 *   - VFP/NEON single/double precision floating-point
 *   - ARM<->Thumb interworking via BX/BLX
 *   - Full data processing, multiply, load/store, block transfer, branch
 */

// Must define compat BEFORE any capstone include
#ifndef CAPSTONE_ARM_COMPAT_HEADER
#define CAPSTONE_ARM_COMPAT_HEADER
#endif

#include "../icpu.h"
#include <capstone/capstone.h>
#include <unordered_set>
#include <unordered_map>

namespace vx {

// ARM register IDs (for reg()/set_reg() interface)
enum ARMReg : int {
    // General purpose
    ARM_R0 = 0, ARM_R1, ARM_R2, ARM_R3,
    ARM_R4, ARM_R5, ARM_R6, ARM_R7,
    ARM_R8, ARM_R9, ARM_R10, ARM_R11,  // R11 = FP (frame pointer)
    ARM_R12,                             // IP (intra-procedure scratch)
    ARM_SP,   // R13
    ARM_LR,   // R14
    ARM_PC,   // R15
    ARM_CPSR, // Current Program Status Register
    ARM_SPSR, // Saved Program Status Register

    // VFP single-precision (S0-S31)
    ARM_S0 = 32, ARM_S1, ARM_S2, ARM_S3,
    ARM_S4, ARM_S5, ARM_S6, ARM_S7,
    ARM_S8, ARM_S9, ARM_S10, ARM_S11,
    ARM_S12, ARM_S13, ARM_S14, ARM_S15,
    ARM_S16, ARM_S17, ARM_S18, ARM_S19,
    ARM_S20, ARM_S21, ARM_S22, ARM_S23,
    ARM_S24, ARM_S25, ARM_S26, ARM_S27,
    ARM_S28, ARM_S29, ARM_S30, ARM_S31,

    // VFP double-precision (D0-D31)
    ARM_D0 = 100, ARM_D1, ARM_D2, ARM_D3,
    ARM_D4, ARM_D5, ARM_D6, ARM_D7,
    ARM_D8, ARM_D9, ARM_D10, ARM_D11,
    ARM_D12, ARM_D13, ARM_D14, ARM_D15,
    ARM_D16, ARM_D17, ARM_D18, ARM_D19,
    ARM_D20, ARM_D21, ARM_D22, ARM_D23,
    ARM_D24, ARM_D25, ARM_D26, ARM_D27,
    ARM_D28, ARM_D29, ARM_D30, ARM_D31,
};

// ARM CPSR flag bit positions
enum ARMFlags : uint32_t {
    ARM_FLAG_N = (1u << 31), // Negative
    ARM_FLAG_Z = (1u << 30), // Zero
    ARM_FLAG_C = (1u << 29), // Carry
    ARM_FLAG_V = (1u << 28), // Overflow
    ARM_FLAG_Q = (1u << 27), // Saturation (sticky)
    ARM_FLAG_T = (1u << 5),  // Thumb mode
    ARM_FLAG_I = (1u << 7),  // IRQ disable
    ARM_FLAG_F = (1u << 6),  // FIQ disable
};

// ARM CPU state
struct ARMState {
    uint32_t r[16];      // R0-R15 (R13=SP, R14=LR, R15=PC)
    uint32_t cpsr;       // Current Program Status Register (flags + mode)
    uint32_t spsr;       // Saved Program Status Register

    // VFP state
    float  s[32];        // Single-precision (S0-S31)
    double d[32];        // Double-precision (D0-D31, overlaps S regs)
    uint32_t fpscr;      // Floating-point status/control register

    // Convenience accessors
    uint32_t& sp() { return r[13]; }
    uint32_t& lr() { return r[14]; }
    uint32_t& pc() { return r[15]; }
    const uint32_t& sp() const { return r[13]; }
    const uint32_t& lr() const { return r[14]; }
    const uint32_t& pc() const { return r[15]; }
    bool thumb() const { return (cpsr & ARM_FLAG_T) != 0; }

    // CPSR flag accessors
    bool flag_n() const { return (cpsr & ARM_FLAG_N) != 0; }
    bool flag_z() const { return (cpsr & ARM_FLAG_Z) != 0; }
    bool flag_c() const { return (cpsr & ARM_FLAG_C) != 0; }
    bool flag_v() const { return (cpsr & ARM_FLAG_V) != 0; }
};

class ARMBackend : public ICpuBackend {
public:
    explicit ARMBackend(VirtualMemory& vmem);
    ~ARMBackend() override;

    // ICpuBackend interface
    Arch arch() const override { return Arch::ARM_32; }
    int pointer_size() const override { return 4; }

    StepResult step() override;
    StepResult step_over() override;
    RunResult run_until(uint64_t addr, uint64_t max_insns) override;
    RunResult run_block() override;

    uint64_t reg(int id) const override;
    void set_reg(int id, uint64_t val) override;
    RegSnapshot snapshot() const override;
    void restore(const RegSnapshot& snap) override;

    uint64_t pc() const override { return state_.pc(); }
    void set_pc(uint64_t addr) override { state_.pc() = static_cast<uint32_t>(addr); }
    uint64_t sp() const override { return state_.sp(); }
    void set_sp(uint64_t addr) override { state_.sp() = static_cast<uint32_t>(addr); }
    uint64_t flags() const override { return state_.cpsr; }
    void set_flags(uint64_t val) override { state_.cpsr = static_cast<uint32_t>(val); }

    std::string disasm(uint64_t addr) const override;
    std::string disasm_at_pc() const override;

    HookID add_code_hook(uint64_t begin, uint64_t end, CodeCallback cb) override;
    HookID add_mem_hook(uint64_t begin, uint64_t end,
                         MemCallback cb, AccessType type) override;
    void remove_hook(HookID id) override;

    void add_breakpoint(uint64_t addr) override;
    void remove_breakpoint(uint64_t addr) override;
    bool has_breakpoint(uint64_t addr) const override;

    void set_anti_debug(bool enable) override { anti_debug_ = enable; }
    uint64_t insn_count() const override { return insn_count_; }

    VirtualMemory& memory() override { return vmem_; }
    const VirtualMemory& memory() const override { return vmem_; }

    // ===== ARM-specific =====

    /// Direct state access
    ARMState& state() { return state_; }
    const ARMState& state() const { return state_; }

    /// Check if currently in Thumb mode
    bool is_thumb() const { return state_.thumb(); }

    /// Get the active Capstone handle (ARM or Thumb based on CPSR.T)
    csh active_cs_handle() const { return state_.thumb() ? cs_thumb_handle_ : cs_arm_handle_; }

    /// Evaluate ARM condition code against current CPSR flags
    bool evaluate_condition(arm_cc cc) const;

private:
    VirtualMemory& vmem_;
    ARMState state_{};
    uint64_t insn_count_ = 0;
    bool anti_debug_ = false;

    // Capstone decoders: one for ARM mode, one for Thumb mode
    csh cs_arm_handle_ = 0;
    csh cs_thumb_handle_ = 0;

    // Breakpoints
    std::unordered_set<uint64_t> breakpoints_;

    // Hooks
    struct HookEntry {
        uint64_t begin, end;
        CodeCallback code_cb;
        MemCallback mem_cb;
        AccessType type;
        bool is_code;
    };
    std::unordered_map<HookID, HookEntry> hooks_;
    HookID next_hook_id_ = 1;

    // ===== Instruction execution =====
public:
    struct ExecResult {
        bool ok = true;
        StopReason stop = StopReason::STEP;
        uint64_t next_pc = 0;
    };

    /// Barrel shifter: apply shift operation, return result and carry out
    uint32_t barrel_shift(uint32_t value, arm_shifter type, uint32_t amount, bool& carry_out) const;

    /// Map Capstone ARM register to our register index
    int cs_arm_reg_to_index(arm_reg reg) const;

    /// Read a Capstone ARM register value
    uint32_t cs_arm_reg_value(arm_reg reg) const;

    /// Write a Capstone ARM register value
    void cs_arm_reg_write(arm_reg reg, uint32_t val);

    /// Resolve ARM operand value
    uint32_t read_operand(const cs_arm_op& op) const;
    void write_operand(const cs_arm_op& op, uint32_t val);

    /// Compute effective address for LDR/STR memory operands
    uint32_t effective_address(const cs_arm_op& op) const;

    /// Update CPSR N,Z flags from result
    void update_flags_nz(uint32_t result);

    /// Update CPSR N,Z,C,V flags after addition
    void update_flags_add(uint32_t a, uint32_t b, uint32_t result);

    /// Update CPSR N,Z,C,V flags after subtraction
    void update_flags_sub(uint32_t a, uint32_t b, uint32_t result);

    /// Stack operations
    void push32(uint32_t val);
    uint32_t pop32();

private:
    /// Execute one instruction at current PC
    ExecResult execute_one();

    /// Fire code hooks for current address
    void fire_code_hooks(uint64_t addr, uint32_t size);

    // Allow instruction dispatch functions to access private members
    friend ExecResult arm_dispatch_insn(ARMBackend& cpu, const cs_insn* insn, VirtualMemory& vmem);
    friend ExecResult arm_dispatch_vfp(ARMBackend& cpu, const cs_insn* insn, VirtualMemory& vmem);
};

} // namespace vx
