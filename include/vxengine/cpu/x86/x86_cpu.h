#pragma once
/**
 * VXEngine x86-32 CPU Backend
 *
 * Capstone-based decoder + custom interpreter for instruction semantics.
 * Handles ALL x86-32 instructions including:
 *   - Full segment register support (push ss, pop ss, mov fs:[X])
 *   - FPU (x87) with full stack model
 *   - SSE/SSE2 (XMM registers)
 *   - Overlapping instruction support (decode at exact PC byte)
 *   - Anti-anti-debug (TF clearing before pushfd)
 */

#include "../icpu.h"
#include <capstone/capstone.h>
#include <unordered_set>
#include <unordered_map>

// Capstone v6 compatibility — some instruction IDs were renamed
#ifndef X86_INS_PUSHAD
#define X86_INS_PUSHAD X86_INS_PUSHAL
#endif
#ifndef X86_INS_POPAD
#define X86_INS_POPAD X86_INS_POPAL
#endif
#ifndef X86_INS_FSTENV
#define X86_INS_FSTENV X86_INS_FNSTENV
#endif

namespace vx {

// x86 register IDs (for reg()/set_reg() interface)
enum X86Reg : int {
    // General purpose
    X86_EAX = 0, X86_ECX, X86_EDX, X86_EBX,
    X86_ESP, X86_EBP, X86_ESI, X86_EDI,
    X86_EIP,
    X86_EFLAGS,
    // Segment
    X86_CS, X86_DS, X86_ES, X86_FS, X86_GS, X86_SS,
    // 8-bit
    X86_AL, X86_AH, X86_BL, X86_BH,
    X86_CL, X86_CH, X86_DL, X86_DH,
    // 16-bit
    X86_AX, X86_BX, X86_CX, X86_DX, X86_SP, X86_BP, X86_SI, X86_DI,
};

// EFLAGS bits
enum EFlags : uint32_t {
    EFLAG_CF = (1 << 0),   // Carry
    EFLAG_PF = (1 << 2),   // Parity
    EFLAG_AF = (1 << 4),   // Auxiliary carry
    EFLAG_ZF = (1 << 6),   // Zero
    EFLAG_SF = (1 << 7),   // Sign
    EFLAG_TF = (1 << 8),   // Trap (single-step)
    EFLAG_IF = (1 << 9),   // Interrupt
    EFLAG_DF = (1 << 10),  // Direction
    EFLAG_OF = (1 << 11),  // Overflow
};

// x87 FPU state
struct X86FPUState {
    double st[8];          // FPU register stack
    int top = 7;           // Stack top pointer (0-7)
    uint16_t cw = 0x037F;  // Control word (default: round-to-nearest, all masks)
    uint16_t sw = 0;       // Status word
    uint16_t tw = 0xFFFF;  // Tag word (all empty)
};

// SSE state
struct SSEState {
    struct XMMReg { uint64_t lo, hi; } xmm[8];
    uint32_t mxcsr = 0x1F80;  // Default MXCSR
};

// Full x86 CPU state
struct X86State {
    uint32_t eax, ecx, edx, ebx;
    uint32_t esp, ebp, esi, edi;
    uint32_t eip;
    uint32_t eflags;
    uint16_t cs, ds, es, fs, gs, ss;

    X86FPUState fpu;
    SSEState sse;
};

class X86Backend : public ICpuBackend {
public:
    explicit X86Backend(VirtualMemory& vmem);
    ~X86Backend() override;

    // ICpuBackend interface
    Arch arch() const override { return Arch::X86_32; }
    int pointer_size() const override { return 4; }

    StepResult step() override;
    StepResult step_over() override;
    RunResult run_until(uint64_t addr, uint64_t max_insns) override;
    RunResult run_block() override;

    uint64_t reg(int id) const override;
    void set_reg(int id, uint64_t val) override;
    RegSnapshot snapshot() const override;
    void restore(const RegSnapshot& snap) override;

    uint64_t pc() const override { return state_.eip; }
    void set_pc(uint64_t addr) override { state_.eip = static_cast<uint32_t>(addr); }
    uint64_t sp() const override { return state_.esp; }
    void set_sp(uint64_t addr) override { state_.esp = static_cast<uint32_t>(addr); }
    uint64_t flags() const override { return state_.eflags; }
    void set_flags(uint64_t val) override { state_.eflags = static_cast<uint32_t>(val); }

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

    // ===== x86-specific =====

    /// Set up GDT for segment register support
    void setup_gdt(const GDTEntry* entries, int count);

    /// Resolve segment base address
    uint32_t segment_base(uint16_t seg_reg) const;

    /// Direct state access
    X86State& state() { return state_; }
    const X86State& state() const { return state_; }

private:
    VirtualMemory& vmem_;
    X86State state_{};
    GDTEntry gdt_[16]{};
    uint64_t insn_count_ = 0;
    bool anti_debug_ = true;

    // Capstone decoder
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

    /// Compute effective address (handles segment overrides, SIB, disp)
    uint32_t effective_address(const cs_x86_op& op) const;

private:

    /// Execute one instruction at current PC
    ExecResult execute_one();

    /// Resolve operand value (handles registers, memory, immediates, segments)
    uint32_t read_operand(const cs_x86_op& op, int size) const;
    void write_operand(const cs_x86_op& op, uint32_t val, int size);

    /// Update flags after arithmetic
    void update_flags_add(uint32_t a, uint32_t b, uint32_t result, int size);
    void update_flags_sub(uint32_t a, uint32_t b, uint32_t result, int size);
    void update_flags_logic(uint32_t result, int size);

    /// Stack operations
    void push32(uint32_t val);
    uint32_t pop32();

    /// Fire code hooks for current address
    void fire_code_hooks(uint64_t addr, uint32_t size);

    /// Check anti-debug: clear TF before pushfd
    void check_anti_debug(const cs_insn* insn);

    /// Map Capstone register ID to the value in our state
    uint32_t cs_reg_to_vx_val(x86_reg reg) const;

    /// Map Capstone segment register to our segment selector value
    uint16_t cs_seg_to_vx(x86_reg seg) const;

    // Allow instruction dispatch functions to access private members
    friend ExecResult x86_dispatch_insn(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);
    friend ExecResult x86_dispatch_fpu(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);
};

} // namespace vx
