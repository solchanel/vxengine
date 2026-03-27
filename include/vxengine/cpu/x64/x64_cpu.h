#pragma once
/**
 * VXEngine x86-64 CPU Backend
 *
 * Extends the x86-32 backend with 64-bit long mode support:
 *   - 16 general purpose registers (RAX-R15), all 64-bit
 *   - RIP-relative addressing (ModRM with no base + disp32 = RIP+disp)
 *   - REX prefix handling (extends register encoding to 16 regs)
 *   - 32-bit writes to GPRs zero-extend to 64 bits
 *   - 16 XMM registers (instead of 8)
 *   - No GDT-based segmentation in long mode (FS/GS use MSR bases)
 *   - Default operand size is 32-bit (need REX.W for 64-bit)
 *   - SYSCALL/SYSRET instead of INT 0x80
 */

#include "../icpu.h"
#include "../x86/x86_cpu.h"
#include <capstone/capstone.h>
#include <unordered_set>
#include <unordered_map>

namespace vx {

// x64 register IDs (extends X86Reg — values start at 100 to avoid collision)
enum X64Reg : int {
    // 64-bit general purpose
    X64_RAX = 100, X64_RCX, X64_RDX, X64_RBX,
    X64_RSP, X64_RBP, X64_RSI, X64_RDI,
    X64_R8, X64_R9, X64_R10, X64_R11,
    X64_R12, X64_R13, X64_R14, X64_R15,
    X64_RIP, X64_RFLAGS,

    // 8-bit low registers (new in x64: SIL, DIL, SPL, BPL)
    X64_SIL, X64_DIL, X64_SPL, X64_BPL,

    // R8-R15 byte (low 8 bits)
    X64_R8B, X64_R9B, X64_R10B, X64_R11B,
    X64_R12B, X64_R13B, X64_R14B, X64_R15B,

    // R8-R15 word (low 16 bits)
    X64_R8W, X64_R9W, X64_R10W, X64_R11W,
    X64_R12W, X64_R13W, X64_R14W, X64_R15W,

    // R8-R15 dword (low 32 bits — writes zero-extend to full 64-bit register)
    X64_R8D, X64_R9D, X64_R10D, X64_R11D,
    X64_R12D, X64_R13D, X64_R14D, X64_R15D,
};

// Full x64 CPU state
struct X64State {
    // General purpose registers (64-bit)
    uint64_t rax, rcx, rdx, rbx;
    uint64_t rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    // Instruction pointer and flags
    uint64_t rip;
    uint64_t rflags;

    // Segment registers (mostly vestigial in long mode)
    uint16_t cs, ds, es, fs, gs, ss;

    // FS/GS base addresses (direct base — no GDT in long mode)
    uint64_t fs_base, gs_base;

    // FPU state (same as x86)
    X86FPUState fpu;

    // SSE state (16 XMM registers in 64-bit mode)
    struct SSE64State {
        struct XMMReg { uint64_t lo, hi; } xmm[16];
        uint32_t mxcsr = 0x1F80;
    } sse;
};

class X64Backend : public ICpuBackend {
public:
    explicit X64Backend(VirtualMemory& vmem);
    ~X64Backend() override;

    // ICpuBackend interface
    Arch arch() const override { return Arch::X86_64; }
    int pointer_size() const override { return 8; }

    StepResult step() override;
    StepResult step_over() override;
    RunResult run_until(uint64_t addr, uint64_t max_insns) override;
    RunResult run_block() override;

    uint64_t reg(int id) const override;
    void set_reg(int id, uint64_t val) override;
    RegSnapshot snapshot() const override;
    void restore(const RegSnapshot& snap) override;

    uint64_t pc() const override { return state_.rip; }
    void set_pc(uint64_t addr) override { state_.rip = addr; }
    uint64_t sp() const override { return state_.rsp; }
    void set_sp(uint64_t addr) override { state_.rsp = addr; }
    uint64_t flags() const override { return state_.rflags; }
    void set_flags(uint64_t val) override { state_.rflags = val; }

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

    // ===== x64-specific =====

    /// Set FS base address (IA32_FS_BASE MSR equivalent)
    void set_fs_base(uint64_t base) { state_.fs_base = base; }

    /// Set GS base address (IA32_GS_BASE MSR equivalent)
    void set_gs_base(uint64_t base) { state_.gs_base = base; }

    /// Get FS/GS base
    uint64_t fs_base() const { return state_.fs_base; }
    uint64_t gs_base() const { return state_.gs_base; }

    /// Direct state access
    X64State& state() { return state_; }
    const X64State& state() const { return state_; }

private:
    VirtualMemory& vmem_;
    X64State state_{};
    uint64_t insn_count_ = 0;
    bool anti_debug_ = true;

    // Capstone decoder (CS_MODE_64)
    csh cs_handle_ = 0;

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
private:

    /// Execute one instruction at current RIP
    ExecResult execute_one();

    /// Resolve operand value (handles registers, memory, immediates)
    uint64_t read_operand(const cs_x86_op& op, int size) const;
    void write_operand(const cs_x86_op& op, uint64_t val, int size);

    /// Compute effective address (handles RIP-relative, SIB, segments)
    uint64_t effective_address(const cs_x86_op& op, uint64_t insn_addr, uint8_t insn_size) const;

    /// Update flags after arithmetic (64-bit aware)
    void update_flags_add(uint64_t a, uint64_t b, uint64_t result, int size);
    void update_flags_sub(uint64_t a, uint64_t b, uint64_t result, int size);
    void update_flags_logic(uint64_t result, int size);

    /// Stack operations (always 64-bit in long mode)
    void push64(uint64_t val);
    uint64_t pop64();

    /// Fire code hooks for current address
    void fire_code_hooks(uint64_t addr, uint32_t size);

    /// Check anti-debug: clear TF before pushfq
    void check_anti_debug(const cs_insn* insn);

    /// Map Capstone register ID to the value in our state
    uint64_t cs_reg_to_vx_val(x86_reg reg) const;

    /// Write a value to a Capstone register in our state
    void cs_reg_write(x86_reg reg, uint64_t val);

    // Allow instruction dispatch functions to access private members
    friend ExecResult x64_dispatch_insn(X64Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);
};

} // namespace vx
