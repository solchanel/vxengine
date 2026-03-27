/**
 * VXEngine x86-32 CPU Backend — Core Implementation
 *
 * Capstone-based decoder with custom instruction interpreter.
 * This file contains:
 *   - Constructor/Destructor (Capstone init/teardown)
 *   - Execution loop (step, step_over, run_until, run_block)
 *   - Register read/write
 *   - State snapshot/restore
 *   - Disassembly
 *   - Hook management
 *   - Stack operations (push32/pop32)
 *   - Effective address computation
 *   - Segment/GDT support
 *   - Anti-debug handling
 *   - ICpuBackend factory
 */

#include "vxengine/cpu/x86/x86_cpu.h"
#include "vxengine/cpu/x64/x64_cpu.h"
#include "vxengine/cpu/arm/arm_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>
#include <stdexcept>

namespace vx {

// Forward declarations for instruction dispatch (implemented in x86_insns.cpp / x86_fpu.cpp)
extern X86Backend::ExecResult x86_dispatch_insn(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);
extern X86Backend::ExecResult x86_dispatch_fpu(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);

// ============================================================
// Constructor / Destructor
// ============================================================

X86Backend::X86Backend(VirtualMemory& vmem)
    : vmem_(vmem)
{
    // Initialize Capstone for x86-32 mode
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_);
    if (err != CS_ERR_OK) {
        throw std::runtime_error(std::string("Capstone init failed: ") + cs_strerror(err));
    }

    // Enable detailed operand info — required for our interpreter
    cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize CPU state to sane defaults
    std::memset(&state_, 0, sizeof(state_));
    state_.eflags = 0x202;  // IF set, reserved bit 1 always set
    state_.cs = 0x23;       // Ring 3 code segment (typical Windows usermode)
    state_.ds = 0x2B;
    state_.es = 0x2B;
    state_.fs = 0x53;       // TEB segment
    state_.gs = 0x2B;
    state_.ss = 0x2B;

    // FPU defaults
    state_.fpu.cw = 0x037F;   // Round-to-nearest, all exceptions masked
    state_.fpu.sw = 0;
    state_.fpu.tw = 0xFFFF;   // All registers empty
    state_.fpu.top = 7;

    // SSE defaults
    state_.sse.mxcsr = 0x1F80;

    // Zero GDT
    std::memset(gdt_, 0, sizeof(gdt_));
}

X86Backend::~X86Backend() {
    if (cs_handle_) {
        cs_close(&cs_handle_);
        cs_handle_ = 0;
    }
}

// ============================================================
// Execution: execute_one
// ============================================================

X86Backend::ExecResult X86Backend::execute_one() {
    // Fetch up to 15 bytes at current EIP (max x86 instruction length)
    uint8_t code[16];
    if (!vmem_.fetch(state_.eip, code, sizeof(code))) {
        return { false, StopReason::ERROR, state_.eip };
    }

    // Decode one instruction
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.eip, 1, &insn);
    if (count == 0) {
        return { false, StopReason::ERROR, state_.eip };
    }

    // Anti-debug: clear TF before pushfd so the pushed flags don't reveal single-stepping
    check_anti_debug(insn);

    // Fire code hooks
    fire_code_hooks(state_.eip, static_cast<uint32_t>(insn->size));

    // Default: advance PC past the current instruction
    uint32_t next_pc = static_cast<uint32_t>(insn->address) + insn->size;

    // Check if this is an FPU/SSE instruction
    ExecResult result;
    const cs_x86& x86 = insn->detail->x86;

    // Determine if FPU/SSE instruction by prefix or opcode group
    bool is_fpu_insn = false;
    switch (insn->id) {
        // x87 instructions
        case X86_INS_FLD: case X86_INS_FST: case X86_INS_FSTP:
        case X86_INS_FILD: case X86_INS_FIST: case X86_INS_FISTP:
        case X86_INS_FADD: case X86_INS_FSUB: case X86_INS_FMUL: case X86_INS_FDIV:
        case X86_INS_FSUBP: case X86_INS_FMULP: case X86_INS_FDIVP:
        case X86_INS_FSUBR: case X86_INS_FSUBRP: case X86_INS_FDIVR: case X86_INS_FDIVRP:
        case X86_INS_FCHS: case X86_INS_FABS: case X86_INS_FSQRT:
        case X86_INS_FSIN: case X86_INS_FCOS: case X86_INS_FPTAN: case X86_INS_FPATAN:
        case X86_INS_FYL2X: case X86_INS_FXCH:
        case X86_INS_FCOM: case X86_INS_FCOMP: case X86_INS_FCOMPP:
        case X86_INS_FUCOM: case X86_INS_FUCOMP: case X86_INS_FUCOMPP:
        case X86_INS_FLDZ: case X86_INS_FLD1: case X86_INS_FLDPI:
        case X86_INS_FLDL2E: case X86_INS_FLDLN2: case X86_INS_FLDL2T: case X86_INS_FLDLG2:
        case X86_INS_FNSTCW: case X86_INS_FLDCW: case X86_INS_FNSTSW:
        case X86_INS_FSTENV: case X86_INS_FLDENV:
        case X86_INS_WAIT: case X86_INS_FNINIT: case X86_INS_FNCLEX:
        case X86_INS_FRNDINT: case X86_INS_F2XM1:
        // SSE/SSE2 instructions
        case X86_INS_MOVSS: case X86_INS_MOVSD: case X86_INS_MOVAPS: case X86_INS_MOVUPS:
        case X86_INS_MOVDQA: case X86_INS_MOVDQU:
        case X86_INS_ADDSS: case X86_INS_ADDSD: case X86_INS_SUBSS: case X86_INS_SUBSD:
        case X86_INS_MULSS: case X86_INS_MULSD: case X86_INS_DIVSS: case X86_INS_DIVSD:
        case X86_INS_COMISS: case X86_INS_COMISD: case X86_INS_UCOMISS: case X86_INS_UCOMISD:
        case X86_INS_CVTSI2SS: case X86_INS_CVTSI2SD:
        case X86_INS_CVTSS2SI: case X86_INS_CVTSD2SI:
        case X86_INS_CVTTSS2SI: case X86_INS_CVTTSD2SI:
        case X86_INS_PAND: case X86_INS_POR: case X86_INS_PXOR:
        case X86_INS_MOVD: case X86_INS_MOVQ:
            is_fpu_insn = true;
            break;
        default:
            break;
    }

    if (is_fpu_insn) {
        result = x86_dispatch_fpu(*this, insn, vmem_);
    } else {
        result = x86_dispatch_insn(*this, insn, vmem_);
    }

    // If the instruction handler didn't set next_pc, advance past instruction
    if (result.ok && result.next_pc == 0) {
        state_.eip = next_pc;
    } else if (result.ok) {
        state_.eip = static_cast<uint32_t>(result.next_pc);
    }

    insn_count_++;
    cs_free(insn, count);
    return result;
}

// ============================================================
// Execution: step
// ============================================================

StepResult X86Backend::step() {
    StepResult sr;
    sr.addr = state_.eip;
    sr.regs_before = snapshot();

    // Disassemble for the step result
    sr.disasm = disasm(state_.eip);

    // Fetch instruction size
    uint8_t code[16];
    if (vmem_.fetch(state_.eip, code, sizeof(code))) {
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.eip, 1, &insn);
        if (count > 0) {
            sr.size = static_cast<uint8_t>(insn->size);
            cs_free(insn, count);
        }
    }

    auto result = execute_one();
    sr.regs_after = snapshot();
    sr.reason = result.stop;

    return sr;
}

// ============================================================
// Execution: step_over
// ============================================================

StepResult X86Backend::step_over() {
    // Check if current instruction is a CALL
    uint8_t code[16];
    if (!vmem_.fetch(state_.eip, code, sizeof(code))) {
        return step();
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.eip, 1, &insn);
    if (count == 0) {
        return step();
    }

    bool is_call = (insn->id == X86_INS_CALL);
    uint32_t next_addr = static_cast<uint32_t>(insn->address) + insn->size;
    cs_free(insn, count);

    if (is_call) {
        // Run until return address (the instruction after the CALL)
        StepResult sr;
        sr.addr = state_.eip;
        sr.regs_before = snapshot();
        sr.disasm = disasm(state_.eip);

        RunResult rr = run_until(next_addr, 1000000);

        sr.regs_after = snapshot();
        sr.reason = rr.reason;
        return sr;
    }

    return step();
}

// ============================================================
// Execution: run_until
// ============================================================

RunResult X86Backend::run_until(uint64_t addr, uint64_t max_insns) {
    RunResult rr;
    rr.insn_count = 0;

    uint64_t limit = (max_insns > 0) ? max_insns : 0xFFFFFFFFULL;

    while (rr.insn_count < limit) {
        // Check if we've reached the target address
        if (state_.eip == static_cast<uint32_t>(addr)) {
            rr.reason = StopReason::ADDRESS_HIT;
            rr.stop_addr = state_.eip;
            return rr;
        }

        // Check breakpoints before executing each instruction
        if (breakpoints_.count(state_.eip)) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.eip;
            return rr;
        }

        auto result = execute_one();
        rr.insn_count++;

        if (!result.ok) {
            rr.reason = result.stop;
            rr.stop_addr = state_.eip;
            return rr;
        }

        if (result.stop == StopReason::HALT || result.stop == StopReason::EXCEPTION ||
            result.stop == StopReason::SENTINEL_HIT) {
            rr.reason = result.stop;
            rr.stop_addr = state_.eip;
            return rr;
        }
    }

    rr.reason = StopReason::MAX_INSNS;
    rr.stop_addr = state_.eip;
    return rr;
}

// ============================================================
// Execution: run_block (execute until branch/call/ret)
// ============================================================

RunResult X86Backend::run_block() {
    RunResult rr;
    rr.insn_count = 0;

    while (true) {
        // Check breakpoints before executing each instruction
        if (breakpoints_.count(state_.eip)) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.eip;
            return rr;
        }

        // Peek at current instruction to check if it terminates the block
        uint8_t code[16];
        if (!vmem_.fetch(state_.eip, code, sizeof(code))) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.eip;
            return rr;
        }

        cs_insn* insn = nullptr;
        size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.eip, 1, &insn);
        if (count == 0) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.eip;
            return rr;
        }

        bool is_block_end = false;
        switch (insn->id) {
            case X86_INS_JMP:
            case X86_INS_CALL:
            case X86_INS_RET:
            case X86_INS_RETF:
            case X86_INS_RETFQ:
            case X86_INS_INT:
            case X86_INS_INT3:
            case X86_INS_HLT:
            case X86_INS_LOOP:
            case X86_INS_LOOPE:
            case X86_INS_LOOPNE:
                is_block_end = true;
                break;
            default:
                // Check for conditional jumps (Jcc)
                if (insn->detail) {
                    for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
                        if (insn->detail->groups[g] == X86_GRP_JUMP ||
                            insn->detail->groups[g] == X86_GRP_RET) {
                            is_block_end = true;
                            break;
                        }
                    }
                }
                break;
        }

        cs_free(insn, count);

        // Execute the instruction
        auto result = execute_one();
        rr.insn_count++;

        if (!result.ok || result.stop == StopReason::HALT ||
            result.stop == StopReason::EXCEPTION ||
            result.stop == StopReason::SENTINEL_HIT) {
            rr.reason = result.ok ? result.stop : StopReason::ERROR;
            rr.stop_addr = state_.eip;
            return rr;
        }

        if (is_block_end) {
            rr.reason = StopReason::STEP;
            rr.stop_addr = state_.eip;
            return rr;
        }
    }
}

// ============================================================
// Register access
// ============================================================

uint64_t X86Backend::reg(int id) const {
    switch (id) {
        // 32-bit general purpose
        case X86_EAX: return state_.eax;
        case X86_ECX: return state_.ecx;
        case X86_EDX: return state_.edx;
        case X86_EBX: return state_.ebx;
        case X86_ESP: return state_.esp;
        case X86_EBP: return state_.ebp;
        case X86_ESI: return state_.esi;
        case X86_EDI: return state_.edi;
        case X86_EIP: return state_.eip;
        case X86_EFLAGS: return state_.eflags;

        // Segment registers
        case X86_CS: return state_.cs;
        case X86_DS: return state_.ds;
        case X86_ES: return state_.es;
        case X86_FS: return state_.fs;
        case X86_GS: return state_.gs;
        case X86_SS: return state_.ss;

        // 8-bit registers
        case X86_AL: return state_.eax & 0xFF;
        case X86_AH: return (state_.eax >> 8) & 0xFF;
        case X86_BL: return state_.ebx & 0xFF;
        case X86_BH: return (state_.ebx >> 8) & 0xFF;
        case X86_CL: return state_.ecx & 0xFF;
        case X86_CH: return (state_.ecx >> 8) & 0xFF;
        case X86_DL: return state_.edx & 0xFF;
        case X86_DH: return (state_.edx >> 8) & 0xFF;

        // 16-bit registers
        case X86_AX: return state_.eax & 0xFFFF;
        case X86_BX: return state_.ebx & 0xFFFF;
        case X86_CX: return state_.ecx & 0xFFFF;
        case X86_DX: return state_.edx & 0xFFFF;
        case X86_SP: return state_.esp & 0xFFFF;
        case X86_BP: return state_.ebp & 0xFFFF;
        case X86_SI: return state_.esi & 0xFFFF;
        case X86_DI: return state_.edi & 0xFFFF;

        default: return 0;
    }
}

void X86Backend::set_reg(int id, uint64_t val) {
    uint32_t v32 = static_cast<uint32_t>(val);

    switch (id) {
        // 32-bit general purpose
        case X86_EAX: state_.eax = v32; break;
        case X86_ECX: state_.ecx = v32; break;
        case X86_EDX: state_.edx = v32; break;
        case X86_EBX: state_.ebx = v32; break;
        case X86_ESP: state_.esp = v32; break;
        case X86_EBP: state_.ebp = v32; break;
        case X86_ESI: state_.esi = v32; break;
        case X86_EDI: state_.edi = v32; break;
        case X86_EIP: state_.eip = v32; break;
        case X86_EFLAGS: state_.eflags = v32; break;

        // Segment registers
        case X86_CS: state_.cs = static_cast<uint16_t>(val); break;
        case X86_DS: state_.ds = static_cast<uint16_t>(val); break;
        case X86_ES: state_.es = static_cast<uint16_t>(val); break;
        case X86_FS: state_.fs = static_cast<uint16_t>(val); break;
        case X86_GS: state_.gs = static_cast<uint16_t>(val); break;
        case X86_SS: state_.ss = static_cast<uint16_t>(val); break;

        // 8-bit: merge into 32-bit register
        case X86_AL: state_.eax = (state_.eax & 0xFFFFFF00) | (v32 & 0xFF); break;
        case X86_AH: state_.eax = (state_.eax & 0xFFFF00FF) | ((v32 & 0xFF) << 8); break;
        case X86_BL: state_.ebx = (state_.ebx & 0xFFFFFF00) | (v32 & 0xFF); break;
        case X86_BH: state_.ebx = (state_.ebx & 0xFFFF00FF) | ((v32 & 0xFF) << 8); break;
        case X86_CL: state_.ecx = (state_.ecx & 0xFFFFFF00) | (v32 & 0xFF); break;
        case X86_CH: state_.ecx = (state_.ecx & 0xFFFF00FF) | ((v32 & 0xFF) << 8); break;
        case X86_DL: state_.edx = (state_.edx & 0xFFFFFF00) | (v32 & 0xFF); break;
        case X86_DH: state_.edx = (state_.edx & 0xFFFF00FF) | ((v32 & 0xFF) << 8); break;

        // 16-bit: merge into 32-bit register
        case X86_AX: state_.eax = (state_.eax & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_BX: state_.ebx = (state_.ebx & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_CX: state_.ecx = (state_.ecx & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_DX: state_.edx = (state_.edx & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_SP: state_.esp = (state_.esp & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_BP: state_.ebp = (state_.ebp & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_SI: state_.esi = (state_.esi & 0xFFFF0000) | (v32 & 0xFFFF); break;
        case X86_DI: state_.edi = (state_.edi & 0xFFFF0000) | (v32 & 0xFFFF); break;

        default: break;
    }
}

// ============================================================
// Snapshot / Restore
// ============================================================

RegSnapshot X86Backend::snapshot() const {
    RegSnapshot snap{};

    snap.rax = state_.eax;
    snap.rbx = state_.ebx;
    snap.rcx = state_.ecx;
    snap.rdx = state_.edx;
    snap.rsi = state_.esi;
    snap.rdi = state_.edi;
    snap.rbp = state_.ebp;
    snap.rsp = state_.esp;
    snap.rip = state_.eip;
    snap.eflags = state_.eflags;

    snap.cs = state_.cs;
    snap.ds = state_.ds;
    snap.es = state_.es;
    snap.fs = state_.fs;
    snap.gs = state_.gs;
    snap.ss = state_.ss;

    // FPU
    for (int i = 0; i < 8; i++) snap.st[i] = state_.fpu.st[i];
    snap.fpu_cw = state_.fpu.cw;
    snap.fpu_sw = state_.fpu.sw;
    snap.fpu_tw = state_.fpu.tw;
    snap.fpu_top = state_.fpu.top;

    // SSE
    for (int i = 0; i < 8; i++) {
        snap.xmm[i].lo = state_.sse.xmm[i].lo;
        snap.xmm[i].hi = state_.sse.xmm[i].hi;
    }

    // Zero upper xmm[8..15] (not used in 32-bit mode)
    for (int i = 8; i < 16; i++) {
        snap.xmm[i].lo = 0;
        snap.xmm[i].hi = 0;
    }

    return snap;
}

void X86Backend::restore(const RegSnapshot& snap) {
    state_.eax = static_cast<uint32_t>(snap.rax);
    state_.ebx = static_cast<uint32_t>(snap.rbx);
    state_.ecx = static_cast<uint32_t>(snap.rcx);
    state_.edx = static_cast<uint32_t>(snap.rdx);
    state_.esi = static_cast<uint32_t>(snap.rsi);
    state_.edi = static_cast<uint32_t>(snap.rdi);
    state_.ebp = static_cast<uint32_t>(snap.rbp);
    state_.esp = static_cast<uint32_t>(snap.rsp);
    state_.eip = static_cast<uint32_t>(snap.rip);
    state_.eflags = snap.eflags;

    state_.cs = snap.cs;
    state_.ds = snap.ds;
    state_.es = snap.es;
    state_.fs = snap.fs;
    state_.gs = snap.gs;
    state_.ss = snap.ss;

    for (int i = 0; i < 8; i++) state_.fpu.st[i] = snap.st[i];
    state_.fpu.cw = snap.fpu_cw;
    state_.fpu.sw = snap.fpu_sw;
    state_.fpu.tw = snap.fpu_tw;
    state_.fpu.top = snap.fpu_top;

    for (int i = 0; i < 8; i++) {
        state_.sse.xmm[i].lo = snap.xmm[i].lo;
        state_.sse.xmm[i].hi = snap.xmm[i].hi;
    }
}

// ============================================================
// Disassembly
// ============================================================

std::string X86Backend::disasm(uint64_t addr) const {
    uint8_t code[16];
    if (!vmem_.fetch(addr, code, sizeof(code))) {
        return "<fetch error>";
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(cs_handle_, code, sizeof(code), addr, 1, &insn);
    if (count == 0) {
        return "<decode error>";
    }

    std::string result = std::string(insn->mnemonic) + " " + insn->op_str;
    cs_free(insn, count);
    return result;
}

std::string X86Backend::disasm_at_pc() const {
    return disasm(state_.eip);
}

// ============================================================
// Hooks
// ============================================================

HookID X86Backend::add_code_hook(uint64_t begin, uint64_t end, CodeCallback cb) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, std::move(cb), nullptr, AccessType::EXEC, true };
    return id;
}

HookID X86Backend::add_mem_hook(uint64_t begin, uint64_t end,
                                 MemCallback cb, AccessType type) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, nullptr, std::move(cb), type, false };
    return id;
}

void X86Backend::remove_hook(HookID id) {
    hooks_.erase(id);
}

void X86Backend::fire_code_hooks(uint64_t addr, uint32_t size) {
    for (auto& [id, hook] : hooks_) {
        if (!hook.is_code) continue;
        if (addr >= hook.begin && addr < hook.end && hook.code_cb) {
            hook.code_cb(addr, size);
        }
    }
}

// ============================================================
// Breakpoints
// ============================================================

void X86Backend::add_breakpoint(uint64_t addr) {
    breakpoints_.insert(addr);
}

void X86Backend::remove_breakpoint(uint64_t addr) {
    breakpoints_.erase(addr);
}

bool X86Backend::has_breakpoint(uint64_t addr) const {
    return breakpoints_.count(addr) > 0;
}

// ============================================================
// Stack operations
// ============================================================

void X86Backend::push32(uint32_t val) {
    state_.esp -= 4;
    vmem_.write32(state_.esp, val);
}

uint32_t X86Backend::pop32() {
    uint32_t val = vmem_.read32(state_.esp);
    state_.esp += 4;
    return val;
}

// ============================================================
// Effective address computation
// ============================================================

uint32_t X86Backend::effective_address(const cs_x86_op& op) const {
    assert(op.type == X86_OP_MEM);

    uint32_t addr = 0;

    // Base register
    if (op.mem.base != X86_REG_INVALID) {
        addr += static_cast<uint32_t>(cs_reg_to_vx_val(op.mem.base));
    }

    // Index register * scale
    if (op.mem.index != X86_REG_INVALID) {
        addr += static_cast<uint32_t>(cs_reg_to_vx_val(op.mem.index)) * op.mem.scale;
    }

    // Displacement
    addr += static_cast<uint32_t>(op.mem.disp);

    // Segment override
    if (op.mem.segment != X86_REG_INVALID) {
        addr += segment_base(cs_seg_to_vx(op.mem.segment));
    } else {
        // Default segment: SS for ESP/EBP-based, DS for everything else
        if (op.mem.base == X86_REG_ESP || op.mem.base == X86_REG_EBP) {
            addr += segment_base(state_.ss);
        } else {
            addr += segment_base(state_.ds);
        }
    }

    return addr;
}

// ============================================================
// Segment / GDT support
// ============================================================

void X86Backend::setup_gdt(const GDTEntry* entries, int count) {
    int n = (count > 16) ? 16 : count;
    for (int i = 0; i < n; i++) {
        gdt_[i] = entries[i];
    }
}

uint32_t X86Backend::segment_base(uint16_t seg_reg) const {
    // Extract GDT index from selector (bits 3..15)
    uint16_t idx = seg_reg >> 3;
    if (idx == 0 || idx >= 16) return 0;  // Null selector or out of range
    return gdt_[idx].base;
}

// ============================================================
// Anti-debug: clear TF before PUSHFD
// ============================================================

void X86Backend::check_anti_debug(const cs_insn* insn) {
    if (!anti_debug_) return;

    if (insn->id == X86_INS_PUSHFD || insn->id == X86_INS_PUSHFQ) {
        // Clear TF so the pushed EFLAGS value doesn't reveal single-stepping
        state_.eflags &= ~EFLAG_TF;
    }
}

// ============================================================
// Operand read/write and flag helpers
// (These are called from x86_insns.cpp — they need access to
//  the private state, but the header declares them as private
//  members so they can be called from the instruction file
//  via the ExecResult friend-style dispatch functions.)
// ============================================================

/// Map Capstone register ID to the value stored in our state.
/// This is a helper used by read_operand / effective_address.
static uint32_t cs_reg_val(const X86State& state, x86_reg reg) {
    switch (reg) {
        case X86_REG_EAX: return state.eax;
        case X86_REG_ECX: return state.ecx;
        case X86_REG_EDX: return state.edx;
        case X86_REG_EBX: return state.ebx;
        case X86_REG_ESP: return state.esp;
        case X86_REG_EBP: return state.ebp;
        case X86_REG_ESI: return state.esi;
        case X86_REG_EDI: return state.edi;
        case X86_REG_EIP: return state.eip;

        // 16-bit
        case X86_REG_AX: return state.eax & 0xFFFF;
        case X86_REG_CX: return state.ecx & 0xFFFF;
        case X86_REG_DX: return state.edx & 0xFFFF;
        case X86_REG_BX: return state.ebx & 0xFFFF;
        case X86_REG_SP: return state.esp & 0xFFFF;
        case X86_REG_BP: return state.ebp & 0xFFFF;
        case X86_REG_SI: return state.esi & 0xFFFF;
        case X86_REG_DI: return state.edi & 0xFFFF;

        // 8-bit low
        case X86_REG_AL: return state.eax & 0xFF;
        case X86_REG_CL: return state.ecx & 0xFF;
        case X86_REG_DL: return state.edx & 0xFF;
        case X86_REG_BL: return state.ebx & 0xFF;

        // 8-bit high
        case X86_REG_AH: return (state.eax >> 8) & 0xFF;
        case X86_REG_CH: return (state.ecx >> 8) & 0xFF;
        case X86_REG_DH: return (state.edx >> 8) & 0xFF;
        case X86_REG_BH: return (state.ebx >> 8) & 0xFF;

        // Segment registers
        case X86_REG_CS: return state.cs;
        case X86_REG_DS: return state.ds;
        case X86_REG_ES: return state.es;
        case X86_REG_FS: return state.fs;
        case X86_REG_GS: return state.gs;
        case X86_REG_SS: return state.ss;

        default: return 0;
    }
}

/// Write a value to a Capstone register in our state
static void cs_reg_write(X86State& state, x86_reg reg, uint32_t val) {
    switch (reg) {
        case X86_REG_EAX: state.eax = val; break;
        case X86_REG_ECX: state.ecx = val; break;
        case X86_REG_EDX: state.edx = val; break;
        case X86_REG_EBX: state.ebx = val; break;
        case X86_REG_ESP: state.esp = val; break;
        case X86_REG_EBP: state.ebp = val; break;
        case X86_REG_ESI: state.esi = val; break;
        case X86_REG_EDI: state.edi = val; break;
        case X86_REG_EIP: state.eip = val; break;

        case X86_REG_AX: state.eax = (state.eax & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_CX: state.ecx = (state.ecx & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_DX: state.edx = (state.edx & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_BX: state.ebx = (state.ebx & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_SP: state.esp = (state.esp & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_BP: state.ebp = (state.ebp & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_SI: state.esi = (state.esi & 0xFFFF0000) | (val & 0xFFFF); break;
        case X86_REG_DI: state.edi = (state.edi & 0xFFFF0000) | (val & 0xFFFF); break;

        case X86_REG_AL: state.eax = (state.eax & 0xFFFFFF00) | (val & 0xFF); break;
        case X86_REG_CL: state.ecx = (state.ecx & 0xFFFFFF00) | (val & 0xFF); break;
        case X86_REG_DL: state.edx = (state.edx & 0xFFFFFF00) | (val & 0xFF); break;
        case X86_REG_BL: state.ebx = (state.ebx & 0xFFFFFF00) | (val & 0xFF); break;

        case X86_REG_AH: state.eax = (state.eax & 0xFFFF00FF) | ((val & 0xFF) << 8); break;
        case X86_REG_CH: state.ecx = (state.ecx & 0xFFFF00FF) | ((val & 0xFF) << 8); break;
        case X86_REG_DH: state.edx = (state.edx & 0xFFFF00FF) | ((val & 0xFF) << 8); break;
        case X86_REG_BH: state.ebx = (state.ebx & 0xFFFF00FF) | ((val & 0xFF) << 8); break;

        case X86_REG_CS: state.cs = static_cast<uint16_t>(val); break;
        case X86_REG_DS: state.ds = static_cast<uint16_t>(val); break;
        case X86_REG_ES: state.es = static_cast<uint16_t>(val); break;
        case X86_REG_FS: state.fs = static_cast<uint16_t>(val); break;
        case X86_REG_GS: state.gs = static_cast<uint16_t>(val); break;
        case X86_REG_SS: state.ss = static_cast<uint16_t>(val); break;

        default: break;
    }
}

// Helper: Convert Capstone register to our value (non-member, callable from this TU)
uint32_t X86Backend::cs_reg_to_vx_val(x86_reg reg) const {
    return cs_reg_val(state_, reg);
}

// Helper: Convert Capstone segment register to VX segment selector value
uint16_t X86Backend::cs_seg_to_vx(x86_reg seg) const {
    switch (seg) {
        case X86_REG_CS: return state_.cs;
        case X86_REG_DS: return state_.ds;
        case X86_REG_ES: return state_.es;
        case X86_REG_FS: return state_.fs;
        case X86_REG_GS: return state_.gs;
        case X86_REG_SS: return state_.ss;
        default: return state_.ds;
    }
}

// ============================================================
// read_operand / write_operand
// ============================================================

uint32_t X86Backend::read_operand(const cs_x86_op& op, int size) const {
    switch (op.type) {
        case X86_OP_REG:
            return cs_reg_val(state_, op.reg);

        case X86_OP_IMM:
            return static_cast<uint32_t>(op.imm);

        case X86_OP_MEM: {
            uint32_t addr = effective_address(op);
            uint32_t val = 0;
            vmem_.read(addr, &val, size);
            return val;
        }

        default:
            return 0;
    }
}

void X86Backend::write_operand(const cs_x86_op& op, uint32_t val, int size) {
    switch (op.type) {
        case X86_OP_REG:
            cs_reg_write(state_, op.reg, val);
            break;

        case X86_OP_MEM: {
            uint32_t addr = effective_address(op);
            vmem_.write(addr, &val, size);
            break;
        }

        default:
            break;
    }
}

// ============================================================
// Flag update helpers
// ============================================================

/// Compute parity of low byte: PF=1 if even number of set bits
static bool parity(uint32_t val) {
    uint8_t b = val & 0xFF;
    b ^= (b >> 4);
    b ^= (b >> 2);
    b ^= (b >> 1);
    return (b & 1) == 0;  // PF=1 if even parity
}

/// Mask for the sign bit at given operand size
static uint32_t sign_bit(int size) {
    switch (size) {
        case 1: return 0x80;
        case 2: return 0x8000;
        case 4: return 0x80000000;
        default: return 0x80000000;
    }
}

/// Mask for the operand size
static uint32_t size_mask(int size) {
    switch (size) {
        case 1: return 0xFF;
        case 2: return 0xFFFF;
        case 4: return 0xFFFFFFFF;
        default: return 0xFFFFFFFF;
    }
}

void X86Backend::update_flags_add(uint32_t a, uint32_t b, uint32_t result, int size) {
    uint32_t mask = size_mask(size);
    uint32_t sb = sign_bit(size);
    uint32_t r = result & mask;
    uint32_t a_m = a & mask;
    uint32_t b_m = b & mask;

    // CF: unsigned overflow (carry out)
    uint64_t full = static_cast<uint64_t>(a_m) + static_cast<uint64_t>(b_m);
    bool cf = (full >> (size * 8)) != 0;

    // ZF: result is zero
    bool zf = (r == 0);

    // SF: sign bit of result
    bool sf = (r & sb) != 0;

    // OF: signed overflow (both operands same sign, result different)
    bool of = ((~(a_m ^ b_m)) & (a_m ^ r) & sb) != 0;

    // AF: auxiliary carry (carry from bit 3 to bit 4)
    bool af = ((a ^ b ^ result) & 0x10) != 0;

    // PF: parity of low byte
    bool pf = parity(r);

    state_.eflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    if (cf) state_.eflags |= EFLAG_CF;
    if (zf) state_.eflags |= EFLAG_ZF;
    if (sf) state_.eflags |= EFLAG_SF;
    if (of) state_.eflags |= EFLAG_OF;
    if (af) state_.eflags |= EFLAG_AF;
    if (pf) state_.eflags |= EFLAG_PF;
}

void X86Backend::update_flags_sub(uint32_t a, uint32_t b, uint32_t result, int size) {
    uint32_t mask = size_mask(size);
    uint32_t sb = sign_bit(size);
    uint32_t r = result & mask;
    uint32_t a_m = a & mask;
    uint32_t b_m = b & mask;

    // CF: unsigned borrow (a < b)
    bool cf = (a_m < b_m);

    // ZF
    bool zf = (r == 0);

    // SF
    bool sf = (r & sb) != 0;

    // OF: signed overflow ((a ^ b) & (a ^ result) & sign_bit)
    bool of = (((a_m ^ b_m) & (a_m ^ r)) & sb) != 0;

    // AF
    bool af = ((a ^ b ^ result) & 0x10) != 0;

    // PF
    bool pf = parity(r);

    state_.eflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    if (cf) state_.eflags |= EFLAG_CF;
    if (zf) state_.eflags |= EFLAG_ZF;
    if (sf) state_.eflags |= EFLAG_SF;
    if (of) state_.eflags |= EFLAG_OF;
    if (af) state_.eflags |= EFLAG_AF;
    if (pf) state_.eflags |= EFLAG_PF;
}

void X86Backend::update_flags_logic(uint32_t result, int size) {
    uint32_t mask = size_mask(size);
    uint32_t sb = sign_bit(size);
    uint32_t r = result & mask;

    // CF and OF are always cleared by logic ops
    bool cf = false;
    bool of = false;

    bool zf = (r == 0);
    bool sf = (r & sb) != 0;
    bool pf = parity(r);

    state_.eflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    if (cf) state_.eflags |= EFLAG_CF;
    if (zf) state_.eflags |= EFLAG_ZF;
    if (sf) state_.eflags |= EFLAG_SF;
    if (of) state_.eflags |= EFLAG_OF;
    // AF is undefined after logic ops, we clear it
    if (pf) state_.eflags |= EFLAG_PF;
}

// ============================================================
// Factory: ICpuBackend::create
// ============================================================

std::unique_ptr<ICpuBackend> ICpuBackend::create(Arch arch, VirtualMemory& vmem) {
    switch (arch) {
        case Arch::X86_32:
            return std::make_unique<X86Backend>(vmem);
        case Arch::X86_64:
            return std::make_unique<X64Backend>(vmem);
        case Arch::ARM_32:
            return std::make_unique<ARMBackend>(vmem);
        default:
            return nullptr;  // Other architectures not yet implemented
    }
}

} // namespace vx
