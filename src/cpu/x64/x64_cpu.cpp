/**
 * VXEngine x86-64 CPU Backend -- Core Implementation
 *
 * Capstone-based decoder with custom instruction interpreter for 64-bit long mode.
 * This file contains:
 *   - Constructor/Destructor (Capstone init/teardown with CS_MODE_64)
 *   - Execution loop (step, step_over, run_until, run_block)
 *   - Register read/write (64-bit registers + R8-R15 + zero-extension rule)
 *   - State snapshot/restore
 *   - Disassembly
 *   - Hook management
 *   - Stack operations (push64/pop64 -- always 64-bit in long mode)
 *   - Effective address computation with RIP-relative support
 *   - FS/GS base via direct fields (no GDT in long mode)
 *   - Anti-debug handling
 */

#include "vxengine/cpu/x64/x64_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>
#include <stdexcept>

namespace vx {

// Forward declaration for instruction dispatch (implemented in x64_insns.cpp)
extern X64Backend::ExecResult x64_dispatch_insn(X64Backend& cpu, const cs_insn* insn, VirtualMemory& vmem);

// ============================================================
// Constructor / Destructor
// ============================================================

X64Backend::X64Backend(VirtualMemory& vmem)
    : vmem_(vmem)
{
    // Initialize Capstone for x86-64 mode
    cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_);
    if (err != CS_ERR_OK) {
        throw std::runtime_error(std::string("Capstone x64 init failed: ") + cs_strerror(err));
    }

    // Enable detailed operand info -- required for our interpreter
    cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize CPU state to sane defaults for 64-bit long mode
    std::memset(&state_, 0, sizeof(state_));
    state_.rflags = 0x202;  // IF set, reserved bit 1 always set
    state_.cs = 0x33;       // Ring 3 64-bit code segment (typical Windows x64)
    state_.ds = 0x2B;
    state_.es = 0x2B;
    state_.fs = 0x53;       // TEB segment
    state_.gs = 0x2B;
    state_.ss = 0x2B;

    // FS/GS bases default to 0 (set by the environment/loader)
    state_.fs_base = 0;
    state_.gs_base = 0;

    // FPU defaults
    state_.fpu.cw = 0x037F;   // Round-to-nearest, all exceptions masked
    state_.fpu.sw = 0;
    state_.fpu.tw = 0xFFFF;   // All registers empty
    state_.fpu.top = 7;

    // SSE defaults
    state_.sse.mxcsr = 0x1F80;
}

X64Backend::~X64Backend() {
    if (cs_handle_) {
        cs_close(&cs_handle_);
        cs_handle_ = 0;
    }
}

// ============================================================
// Execution: execute_one
// ============================================================

X64Backend::ExecResult X64Backend::execute_one() {
    // Fetch up to 15 bytes at current RIP (max x86 instruction length)
    uint8_t code[16];
    if (!vmem_.fetch(state_.rip, code, sizeof(code))) {
        return { false, StopReason::ERROR, state_.rip };
    }

    // Decode one instruction
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.rip, 1, &insn);
    if (count == 0) {
        return { false, StopReason::ERROR, state_.rip };
    }

    // Anti-debug: clear TF before pushfq so the pushed flags don't reveal single-stepping
    check_anti_debug(insn);

    // Fire code hooks
    fire_code_hooks(state_.rip, static_cast<uint32_t>(insn->size));

    // Default: advance PC past the current instruction
    uint64_t next_pc = insn->address + insn->size;

    // Dispatch instruction
    ExecResult result = x64_dispatch_insn(*this, insn, vmem_);

    // If the instruction handler didn't set next_pc, advance past instruction
    if (result.ok && result.next_pc == 0) {
        state_.rip = next_pc;
    } else if (result.ok) {
        state_.rip = result.next_pc;
    }

    insn_count_++;
    cs_free(insn, count);
    return result;
}

// ============================================================
// Execution: step
// ============================================================

StepResult X64Backend::step() {
    StepResult sr;
    sr.addr = state_.rip;
    sr.regs_before = snapshot();

    // Disassemble for the step result
    sr.disasm = disasm(state_.rip);

    // Fetch instruction size
    uint8_t code[16];
    if (vmem_.fetch(state_.rip, code, sizeof(code))) {
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.rip, 1, &insn);
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

StepResult X64Backend::step_over() {
    // Check if current instruction is a CALL
    uint8_t code[16];
    if (!vmem_.fetch(state_.rip, code, sizeof(code))) {
        return step();
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.rip, 1, &insn);
    if (count == 0) {
        return step();
    }

    bool is_call = (insn->id == X86_INS_CALL);
    uint64_t next_addr = insn->address + insn->size;
    cs_free(insn, count);

    if (is_call) {
        // Run until return address (the instruction after the CALL)
        StepResult sr;
        sr.addr = state_.rip;
        sr.regs_before = snapshot();
        sr.disasm = disasm(state_.rip);

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

RunResult X64Backend::run_until(uint64_t addr, uint64_t max_insns) {
    RunResult rr;
    rr.insn_count = 0;

    uint64_t limit = (max_insns > 0) ? max_insns : 0xFFFFFFFFFFFFFFFFULL;

    while (rr.insn_count < limit) {
        // Check if we've reached the target address
        if (state_.rip == addr) {
            rr.reason = StopReason::ADDRESS_HIT;
            rr.stop_addr = state_.rip;
            return rr;
        }

        // Check breakpoints
        if (breakpoints_.count(state_.rip) && rr.insn_count > 0) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.rip;
            return rr;
        }

        auto result = execute_one();
        rr.insn_count++;

        if (!result.ok) {
            rr.reason = result.stop;
            rr.stop_addr = state_.rip;
            return rr;
        }

        if (result.stop == StopReason::HALT || result.stop == StopReason::EXCEPTION ||
            result.stop == StopReason::SENTINEL_HIT) {
            rr.reason = result.stop;
            rr.stop_addr = state_.rip;
            return rr;
        }
    }

    rr.reason = StopReason::MAX_INSNS;
    rr.stop_addr = state_.rip;
    return rr;
}

// ============================================================
// Execution: run_block (execute until branch/call/ret)
// ============================================================

RunResult X64Backend::run_block() {
    RunResult rr;
    rr.insn_count = 0;

    while (true) {
        // Check breakpoints (except on first instruction)
        if (breakpoints_.count(state_.rip) && rr.insn_count > 0) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.rip;
            return rr;
        }

        // Peek at current instruction to check if it terminates the block
        uint8_t code[16];
        if (!vmem_.fetch(state_.rip, code, sizeof(code))) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.rip;
            return rr;
        }

        cs_insn* insn = nullptr;
        size_t count = cs_disasm(cs_handle_, code, sizeof(code), state_.rip, 1, &insn);
        if (count == 0) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.rip;
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
            case X86_INS_SYSCALL:
            case X86_INS_SYSRET:
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
            rr.stop_addr = state_.rip;
            return rr;
        }

        if (is_block_end) {
            rr.reason = StopReason::STEP;
            rr.stop_addr = state_.rip;
            return rr;
        }
    }
}

// ============================================================
// Register access
// ============================================================

uint64_t X64Backend::reg(int id) const {
    switch (id) {
        // 64-bit general purpose
        case X64_RAX: return state_.rax;
        case X64_RCX: return state_.rcx;
        case X64_RDX: return state_.rdx;
        case X64_RBX: return state_.rbx;
        case X64_RSP: return state_.rsp;
        case X64_RBP: return state_.rbp;
        case X64_RSI: return state_.rsi;
        case X64_RDI: return state_.rdi;
        case X64_R8:  return state_.r8;
        case X64_R9:  return state_.r9;
        case X64_R10: return state_.r10;
        case X64_R11: return state_.r11;
        case X64_R12: return state_.r12;
        case X64_R13: return state_.r13;
        case X64_R14: return state_.r14;
        case X64_R15: return state_.r15;
        case X64_RIP: return state_.rip;
        case X64_RFLAGS: return state_.rflags;

        // 32-bit (x86 compat -- reads low 32 bits)
        case X86_EAX: return state_.rax & 0xFFFFFFFF;
        case X86_ECX: return state_.rcx & 0xFFFFFFFF;
        case X86_EDX: return state_.rdx & 0xFFFFFFFF;
        case X86_EBX: return state_.rbx & 0xFFFFFFFF;
        case X86_ESP: return state_.rsp & 0xFFFFFFFF;
        case X86_EBP: return state_.rbp & 0xFFFFFFFF;
        case X86_ESI: return state_.rsi & 0xFFFFFFFF;
        case X86_EDI: return state_.rdi & 0xFFFFFFFF;
        case X86_EIP: return state_.rip & 0xFFFFFFFF;
        case X86_EFLAGS: return state_.rflags & 0xFFFFFFFF;

        // Segment registers
        case X86_CS: return state_.cs;
        case X86_DS: return state_.ds;
        case X86_ES: return state_.es;
        case X86_FS: return state_.fs;
        case X86_GS: return state_.gs;
        case X86_SS: return state_.ss;

        // 8-bit legacy
        case X86_AL: return state_.rax & 0xFF;
        case X86_AH: return (state_.rax >> 8) & 0xFF;
        case X86_BL: return state_.rbx & 0xFF;
        case X86_BH: return (state_.rbx >> 8) & 0xFF;
        case X86_CL: return state_.rcx & 0xFF;
        case X86_CH: return (state_.rcx >> 8) & 0xFF;
        case X86_DL: return state_.rdx & 0xFF;
        case X86_DH: return (state_.rdx >> 8) & 0xFF;

        // 8-bit new (x64 only: SIL, DIL, SPL, BPL)
        case X64_SIL: return state_.rsi & 0xFF;
        case X64_DIL: return state_.rdi & 0xFF;
        case X64_SPL: return state_.rsp & 0xFF;
        case X64_BPL: return state_.rbp & 0xFF;

        // R8-R15 byte
        case X64_R8B:  return state_.r8  & 0xFF;
        case X64_R9B:  return state_.r9  & 0xFF;
        case X64_R10B: return state_.r10 & 0xFF;
        case X64_R11B: return state_.r11 & 0xFF;
        case X64_R12B: return state_.r12 & 0xFF;
        case X64_R13B: return state_.r13 & 0xFF;
        case X64_R14B: return state_.r14 & 0xFF;
        case X64_R15B: return state_.r15 & 0xFF;

        // 16-bit legacy
        case X86_AX: return state_.rax & 0xFFFF;
        case X86_BX: return state_.rbx & 0xFFFF;
        case X86_CX: return state_.rcx & 0xFFFF;
        case X86_DX: return state_.rdx & 0xFFFF;
        case X86_SP: return state_.rsp & 0xFFFF;
        case X86_BP: return state_.rbp & 0xFFFF;
        case X86_SI: return state_.rsi & 0xFFFF;
        case X86_DI: return state_.rdi & 0xFFFF;

        // R8-R15 word
        case X64_R8W:  return state_.r8  & 0xFFFF;
        case X64_R9W:  return state_.r9  & 0xFFFF;
        case X64_R10W: return state_.r10 & 0xFFFF;
        case X64_R11W: return state_.r11 & 0xFFFF;
        case X64_R12W: return state_.r12 & 0xFFFF;
        case X64_R13W: return state_.r13 & 0xFFFF;
        case X64_R14W: return state_.r14 & 0xFFFF;
        case X64_R15W: return state_.r15 & 0xFFFF;

        // R8-R15 dword
        case X64_R8D:  return state_.r8  & 0xFFFFFFFF;
        case X64_R9D:  return state_.r9  & 0xFFFFFFFF;
        case X64_R10D: return state_.r10 & 0xFFFFFFFF;
        case X64_R11D: return state_.r11 & 0xFFFFFFFF;
        case X64_R12D: return state_.r12 & 0xFFFFFFFF;
        case X64_R13D: return state_.r13 & 0xFFFFFFFF;
        case X64_R14D: return state_.r14 & 0xFFFFFFFF;
        case X64_R15D: return state_.r15 & 0xFFFFFFFF;

        default: return 0;
    }
}

void X64Backend::set_reg(int id, uint64_t val) {
    switch (id) {
        // 64-bit general purpose
        case X64_RAX: state_.rax = val; break;
        case X64_RCX: state_.rcx = val; break;
        case X64_RDX: state_.rdx = val; break;
        case X64_RBX: state_.rbx = val; break;
        case X64_RSP: state_.rsp = val; break;
        case X64_RBP: state_.rbp = val; break;
        case X64_RSI: state_.rsi = val; break;
        case X64_RDI: state_.rdi = val; break;
        case X64_R8:  state_.r8  = val; break;
        case X64_R9:  state_.r9  = val; break;
        case X64_R10: state_.r10 = val; break;
        case X64_R11: state_.r11 = val; break;
        case X64_R12: state_.r12 = val; break;
        case X64_R13: state_.r13 = val; break;
        case X64_R14: state_.r14 = val; break;
        case X64_R15: state_.r15 = val; break;
        case X64_RIP: state_.rip = val; break;
        case X64_RFLAGS: state_.rflags = val; break;

        // 32-bit writes zero-extend to 64 bits (critical x64 rule)
        case X86_EAX: state_.rax = val & 0xFFFFFFFF; break;
        case X86_ECX: state_.rcx = val & 0xFFFFFFFF; break;
        case X86_EDX: state_.rdx = val & 0xFFFFFFFF; break;
        case X86_EBX: state_.rbx = val & 0xFFFFFFFF; break;
        case X86_ESP: state_.rsp = val & 0xFFFFFFFF; break;
        case X86_EBP: state_.rbp = val & 0xFFFFFFFF; break;
        case X86_ESI: state_.rsi = val & 0xFFFFFFFF; break;
        case X86_EDI: state_.rdi = val & 0xFFFFFFFF; break;
        case X86_EIP: state_.rip = val & 0xFFFFFFFF; break;
        case X86_EFLAGS: state_.rflags = val & 0xFFFFFFFF; break;

        // Segment registers
        case X86_CS: state_.cs = static_cast<uint16_t>(val); break;
        case X86_DS: state_.ds = static_cast<uint16_t>(val); break;
        case X86_ES: state_.es = static_cast<uint16_t>(val); break;
        case X86_FS: state_.fs = static_cast<uint16_t>(val); break;
        case X86_GS: state_.gs = static_cast<uint16_t>(val); break;
        case X86_SS: state_.ss = static_cast<uint16_t>(val); break;

        // 8-bit legacy: merge into 64-bit register (no zero-extension)
        case X86_AL: state_.rax = (state_.rax & ~0xFFULL) | (val & 0xFF); break;
        case X86_AH: state_.rax = (state_.rax & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_BL: state_.rbx = (state_.rbx & ~0xFFULL) | (val & 0xFF); break;
        case X86_BH: state_.rbx = (state_.rbx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_CL: state_.rcx = (state_.rcx & ~0xFFULL) | (val & 0xFF); break;
        case X86_CH: state_.rcx = (state_.rcx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_DL: state_.rdx = (state_.rdx & ~0xFFULL) | (val & 0xFF); break;
        case X86_DH: state_.rdx = (state_.rdx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;

        // 8-bit new (x64: SIL, DIL, SPL, BPL)
        case X64_SIL: state_.rsi = (state_.rsi & ~0xFFULL) | (val & 0xFF); break;
        case X64_DIL: state_.rdi = (state_.rdi & ~0xFFULL) | (val & 0xFF); break;
        case X64_SPL: state_.rsp = (state_.rsp & ~0xFFULL) | (val & 0xFF); break;
        case X64_BPL: state_.rbp = (state_.rbp & ~0xFFULL) | (val & 0xFF); break;

        // R8-R15 byte
        case X64_R8B:  state_.r8  = (state_.r8  & ~0xFFULL) | (val & 0xFF); break;
        case X64_R9B:  state_.r9  = (state_.r9  & ~0xFFULL) | (val & 0xFF); break;
        case X64_R10B: state_.r10 = (state_.r10 & ~0xFFULL) | (val & 0xFF); break;
        case X64_R11B: state_.r11 = (state_.r11 & ~0xFFULL) | (val & 0xFF); break;
        case X64_R12B: state_.r12 = (state_.r12 & ~0xFFULL) | (val & 0xFF); break;
        case X64_R13B: state_.r13 = (state_.r13 & ~0xFFULL) | (val & 0xFF); break;
        case X64_R14B: state_.r14 = (state_.r14 & ~0xFFULL) | (val & 0xFF); break;
        case X64_R15B: state_.r15 = (state_.r15 & ~0xFFULL) | (val & 0xFF); break;

        // 16-bit: merge into 64-bit register (no zero-extension)
        case X86_AX: state_.rax = (state_.rax & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_BX: state_.rbx = (state_.rbx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_CX: state_.rcx = (state_.rcx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_DX: state_.rdx = (state_.rdx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_SP: state_.rsp = (state_.rsp & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_BP: state_.rbp = (state_.rbp & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_SI: state_.rsi = (state_.rsi & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_DI: state_.rdi = (state_.rdi & ~0xFFFFULL) | (val & 0xFFFF); break;

        // R8-R15 word
        case X64_R8W:  state_.r8  = (state_.r8  & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R9W:  state_.r9  = (state_.r9  & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R10W: state_.r10 = (state_.r10 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R11W: state_.r11 = (state_.r11 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R12W: state_.r12 = (state_.r12 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R13W: state_.r13 = (state_.r13 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R14W: state_.r14 = (state_.r14 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X64_R15W: state_.r15 = (state_.r15 & ~0xFFFFULL) | (val & 0xFFFF); break;

        // R8-R15 dword (writes zero-extend to 64 bits)
        case X64_R8D:  state_.r8  = val & 0xFFFFFFFF; break;
        case X64_R9D:  state_.r9  = val & 0xFFFFFFFF; break;
        case X64_R10D: state_.r10 = val & 0xFFFFFFFF; break;
        case X64_R11D: state_.r11 = val & 0xFFFFFFFF; break;
        case X64_R12D: state_.r12 = val & 0xFFFFFFFF; break;
        case X64_R13D: state_.r13 = val & 0xFFFFFFFF; break;
        case X64_R14D: state_.r14 = val & 0xFFFFFFFF; break;
        case X64_R15D: state_.r15 = val & 0xFFFFFFFF; break;

        default: break;
    }
}

// ============================================================
// Snapshot / Restore
// ============================================================

RegSnapshot X64Backend::snapshot() const {
    RegSnapshot snap{};

    snap.rax = state_.rax;
    snap.rbx = state_.rbx;
    snap.rcx = state_.rcx;
    snap.rdx = state_.rdx;
    snap.rsi = state_.rsi;
    snap.rdi = state_.rdi;
    snap.rbp = state_.rbp;
    snap.rsp = state_.rsp;
    snap.r8  = state_.r8;
    snap.r9  = state_.r9;
    snap.r10 = state_.r10;
    snap.r11 = state_.r11;
    snap.r12 = state_.r12;
    snap.r13 = state_.r13;
    snap.r14 = state_.r14;
    snap.r15 = state_.r15;
    snap.rip = state_.rip;
    snap.eflags = static_cast<uint32_t>(state_.rflags);

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

    // SSE (all 16 registers in 64-bit mode)
    for (int i = 0; i < 16; i++) {
        snap.xmm[i].lo = state_.sse.xmm[i].lo;
        snap.xmm[i].hi = state_.sse.xmm[i].hi;
    }

    return snap;
}

void X64Backend::restore(const RegSnapshot& snap) {
    state_.rax = snap.rax;
    state_.rbx = snap.rbx;
    state_.rcx = snap.rcx;
    state_.rdx = snap.rdx;
    state_.rsi = snap.rsi;
    state_.rdi = snap.rdi;
    state_.rbp = snap.rbp;
    state_.rsp = snap.rsp;
    state_.r8  = snap.r8;
    state_.r9  = snap.r9;
    state_.r10 = snap.r10;
    state_.r11 = snap.r11;
    state_.r12 = snap.r12;
    state_.r13 = snap.r13;
    state_.r14 = snap.r14;
    state_.r15 = snap.r15;
    state_.rip = snap.rip;
    state_.rflags = snap.eflags;

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

    for (int i = 0; i < 16; i++) {
        state_.sse.xmm[i].lo = snap.xmm[i].lo;
        state_.sse.xmm[i].hi = snap.xmm[i].hi;
    }
}

// ============================================================
// Disassembly
// ============================================================

std::string X64Backend::disasm(uint64_t addr) const {
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

std::string X64Backend::disasm_at_pc() const {
    return disasm(state_.rip);
}

// ============================================================
// Hooks
// ============================================================

HookID X64Backend::add_code_hook(uint64_t begin, uint64_t end, CodeCallback cb) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, std::move(cb), nullptr, AccessType::EXEC, true };
    return id;
}

HookID X64Backend::add_mem_hook(uint64_t begin, uint64_t end,
                                 MemCallback cb, AccessType type) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, nullptr, std::move(cb), type, false };
    return id;
}

void X64Backend::remove_hook(HookID id) {
    hooks_.erase(id);
}

void X64Backend::fire_code_hooks(uint64_t addr, uint32_t size) {
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

void X64Backend::add_breakpoint(uint64_t addr) {
    breakpoints_.insert(addr);
}

void X64Backend::remove_breakpoint(uint64_t addr) {
    breakpoints_.erase(addr);
}

bool X64Backend::has_breakpoint(uint64_t addr) const {
    return breakpoints_.count(addr) > 0;
}

// ============================================================
// Stack operations (always 64-bit in long mode)
// ============================================================

void X64Backend::push64(uint64_t val) {
    state_.rsp -= 8;
    vmem_.write64(state_.rsp, val);
}

uint64_t X64Backend::pop64() {
    uint64_t val = vmem_.read64(state_.rsp);
    state_.rsp += 8;
    return val;
}

// ============================================================
// Effective address computation (with RIP-relative support)
// ============================================================

uint64_t X64Backend::effective_address(const cs_x86_op& op,
                                        uint64_t insn_addr,
                                        uint8_t insn_size) const {
    assert(op.type == X86_OP_MEM);

    uint64_t addr = 0;

    // RIP-relative addressing: in 64-bit mode, ModRM with base=NONE and
    // no index means RIP + disp32 (Capstone reports base=X86_REG_RIP)
    if (op.mem.base == X86_REG_RIP) {
        addr = insn_addr + insn_size + op.mem.disp;
    } else {
        // Base register
        if (op.mem.base != X86_REG_INVALID) {
            addr += cs_reg_to_vx_val(op.mem.base);
        }

        // Index register * scale
        if (op.mem.index != X86_REG_INVALID) {
            addr += cs_reg_to_vx_val(op.mem.index) * op.mem.scale;
        }

        // Displacement
        addr += static_cast<uint64_t>(static_cast<int64_t>(op.mem.disp));
    }

    // Segment override: in 64-bit mode, only FS and GS have non-zero bases
    if (op.mem.segment == X86_REG_FS) {
        addr += state_.fs_base;
    } else if (op.mem.segment == X86_REG_GS) {
        addr += state_.gs_base;
    }
    // All other segments (CS, DS, ES, SS) have base = 0 in long mode

    return addr;
}

// ============================================================
// Anti-debug: clear TF before PUSHFQ
// ============================================================

void X64Backend::check_anti_debug(const cs_insn* insn) {
    if (!anti_debug_) return;

    if (insn->id == X86_INS_PUSHFQ || insn->id == X86_INS_PUSHFD) {
        // Clear TF so the pushed RFLAGS value doesn't reveal single-stepping
        state_.rflags &= ~EFLAG_TF;
    }
}

// ============================================================
// Capstone register mapping: read
// ============================================================

uint64_t X64Backend::cs_reg_to_vx_val(x86_reg reg) const {
    switch (reg) {
        // 64-bit
        case X86_REG_RAX: return state_.rax;
        case X86_REG_RCX: return state_.rcx;
        case X86_REG_RDX: return state_.rdx;
        case X86_REG_RBX: return state_.rbx;
        case X86_REG_RSP: return state_.rsp;
        case X86_REG_RBP: return state_.rbp;
        case X86_REG_RSI: return state_.rsi;
        case X86_REG_RDI: return state_.rdi;
        case X86_REG_R8:  return state_.r8;
        case X86_REG_R9:  return state_.r9;
        case X86_REG_R10: return state_.r10;
        case X86_REG_R11: return state_.r11;
        case X86_REG_R12: return state_.r12;
        case X86_REG_R13: return state_.r13;
        case X86_REG_R14: return state_.r14;
        case X86_REG_R15: return state_.r15;
        case X86_REG_RIP: return state_.rip;

        // 32-bit (reads low 32 bits, zero-extended)
        case X86_REG_EAX: return state_.rax & 0xFFFFFFFF;
        case X86_REG_ECX: return state_.rcx & 0xFFFFFFFF;
        case X86_REG_EDX: return state_.rdx & 0xFFFFFFFF;
        case X86_REG_EBX: return state_.rbx & 0xFFFFFFFF;
        case X86_REG_ESP: return state_.rsp & 0xFFFFFFFF;
        case X86_REG_EBP: return state_.rbp & 0xFFFFFFFF;
        case X86_REG_ESI: return state_.rsi & 0xFFFFFFFF;
        case X86_REG_EDI: return state_.rdi & 0xFFFFFFFF;
        case X86_REG_EIP: return state_.rip & 0xFFFFFFFF;
        case X86_REG_R8D:  return state_.r8  & 0xFFFFFFFF;
        case X86_REG_R9D:  return state_.r9  & 0xFFFFFFFF;
        case X86_REG_R10D: return state_.r10 & 0xFFFFFFFF;
        case X86_REG_R11D: return state_.r11 & 0xFFFFFFFF;
        case X86_REG_R12D: return state_.r12 & 0xFFFFFFFF;
        case X86_REG_R13D: return state_.r13 & 0xFFFFFFFF;
        case X86_REG_R14D: return state_.r14 & 0xFFFFFFFF;
        case X86_REG_R15D: return state_.r15 & 0xFFFFFFFF;

        // 16-bit
        case X86_REG_AX: return state_.rax & 0xFFFF;
        case X86_REG_CX: return state_.rcx & 0xFFFF;
        case X86_REG_DX: return state_.rdx & 0xFFFF;
        case X86_REG_BX: return state_.rbx & 0xFFFF;
        case X86_REG_SP: return state_.rsp & 0xFFFF;
        case X86_REG_BP: return state_.rbp & 0xFFFF;
        case X86_REG_SI: return state_.rsi & 0xFFFF;
        case X86_REG_DI: return state_.rdi & 0xFFFF;
        case X86_REG_R8W:  return state_.r8  & 0xFFFF;
        case X86_REG_R9W:  return state_.r9  & 0xFFFF;
        case X86_REG_R10W: return state_.r10 & 0xFFFF;
        case X86_REG_R11W: return state_.r11 & 0xFFFF;
        case X86_REG_R12W: return state_.r12 & 0xFFFF;
        case X86_REG_R13W: return state_.r13 & 0xFFFF;
        case X86_REG_R14W: return state_.r14 & 0xFFFF;
        case X86_REG_R15W: return state_.r15 & 0xFFFF;

        // 8-bit low
        case X86_REG_AL: return state_.rax & 0xFF;
        case X86_REG_CL: return state_.rcx & 0xFF;
        case X86_REG_DL: return state_.rdx & 0xFF;
        case X86_REG_BL: return state_.rbx & 0xFF;
        case X86_REG_SIL: return state_.rsi & 0xFF;
        case X86_REG_DIL: return state_.rdi & 0xFF;
        case X86_REG_SPL: return state_.rsp & 0xFF;
        case X86_REG_BPL: return state_.rbp & 0xFF;
        case X86_REG_R8B:  return state_.r8  & 0xFF;
        case X86_REG_R9B:  return state_.r9  & 0xFF;
        case X86_REG_R10B: return state_.r10 & 0xFF;
        case X86_REG_R11B: return state_.r11 & 0xFF;
        case X86_REG_R12B: return state_.r12 & 0xFF;
        case X86_REG_R13B: return state_.r13 & 0xFF;
        case X86_REG_R14B: return state_.r14 & 0xFF;
        case X86_REG_R15B: return state_.r15 & 0xFF;

        // 8-bit high
        case X86_REG_AH: return (state_.rax >> 8) & 0xFF;
        case X86_REG_CH: return (state_.rcx >> 8) & 0xFF;
        case X86_REG_DH: return (state_.rdx >> 8) & 0xFF;
        case X86_REG_BH: return (state_.rbx >> 8) & 0xFF;

        // Segment registers
        case X86_REG_CS: return state_.cs;
        case X86_REG_DS: return state_.ds;
        case X86_REG_ES: return state_.es;
        case X86_REG_FS: return state_.fs;
        case X86_REG_GS: return state_.gs;
        case X86_REG_SS: return state_.ss;

        default: return 0;
    }
}

// ============================================================
// Capstone register mapping: write
// Implements the x64 zero-extension rule:
//   - 32-bit writes zero-extend to full 64-bit register
//   - 8-bit and 16-bit writes merge into the existing value
// ============================================================

void X64Backend::cs_reg_write(x86_reg reg, uint64_t val) {
    switch (reg) {
        // 64-bit: full write
        case X86_REG_RAX: state_.rax = val; break;
        case X86_REG_RCX: state_.rcx = val; break;
        case X86_REG_RDX: state_.rdx = val; break;
        case X86_REG_RBX: state_.rbx = val; break;
        case X86_REG_RSP: state_.rsp = val; break;
        case X86_REG_RBP: state_.rbp = val; break;
        case X86_REG_RSI: state_.rsi = val; break;
        case X86_REG_RDI: state_.rdi = val; break;
        case X86_REG_R8:  state_.r8  = val; break;
        case X86_REG_R9:  state_.r9  = val; break;
        case X86_REG_R10: state_.r10 = val; break;
        case X86_REG_R11: state_.r11 = val; break;
        case X86_REG_R12: state_.r12 = val; break;
        case X86_REG_R13: state_.r13 = val; break;
        case X86_REG_R14: state_.r14 = val; break;
        case X86_REG_R15: state_.r15 = val; break;
        case X86_REG_RIP: state_.rip = val; break;

        // 32-bit: zero-extend to 64 bits
        case X86_REG_EAX: state_.rax = val & 0xFFFFFFFF; break;
        case X86_REG_ECX: state_.rcx = val & 0xFFFFFFFF; break;
        case X86_REG_EDX: state_.rdx = val & 0xFFFFFFFF; break;
        case X86_REG_EBX: state_.rbx = val & 0xFFFFFFFF; break;
        case X86_REG_ESP: state_.rsp = val & 0xFFFFFFFF; break;
        case X86_REG_EBP: state_.rbp = val & 0xFFFFFFFF; break;
        case X86_REG_ESI: state_.rsi = val & 0xFFFFFFFF; break;
        case X86_REG_EDI: state_.rdi = val & 0xFFFFFFFF; break;
        case X86_REG_EIP: state_.rip = val & 0xFFFFFFFF; break;
        case X86_REG_R8D:  state_.r8  = val & 0xFFFFFFFF; break;
        case X86_REG_R9D:  state_.r9  = val & 0xFFFFFFFF; break;
        case X86_REG_R10D: state_.r10 = val & 0xFFFFFFFF; break;
        case X86_REG_R11D: state_.r11 = val & 0xFFFFFFFF; break;
        case X86_REG_R12D: state_.r12 = val & 0xFFFFFFFF; break;
        case X86_REG_R13D: state_.r13 = val & 0xFFFFFFFF; break;
        case X86_REG_R14D: state_.r14 = val & 0xFFFFFFFF; break;
        case X86_REG_R15D: state_.r15 = val & 0xFFFFFFFF; break;

        // 16-bit: merge (no zero-extension)
        case X86_REG_AX: state_.rax = (state_.rax & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_CX: state_.rcx = (state_.rcx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_DX: state_.rdx = (state_.rdx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_BX: state_.rbx = (state_.rbx & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_SP: state_.rsp = (state_.rsp & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_BP: state_.rbp = (state_.rbp & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_SI: state_.rsi = (state_.rsi & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_DI: state_.rdi = (state_.rdi & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R8W:  state_.r8  = (state_.r8  & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R9W:  state_.r9  = (state_.r9  & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R10W: state_.r10 = (state_.r10 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R11W: state_.r11 = (state_.r11 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R12W: state_.r12 = (state_.r12 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R13W: state_.r13 = (state_.r13 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R14W: state_.r14 = (state_.r14 & ~0xFFFFULL) | (val & 0xFFFF); break;
        case X86_REG_R15W: state_.r15 = (state_.r15 & ~0xFFFFULL) | (val & 0xFFFF); break;

        // 8-bit low: merge (no zero-extension)
        case X86_REG_AL:  state_.rax = (state_.rax & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_CL:  state_.rcx = (state_.rcx & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_DL:  state_.rdx = (state_.rdx & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_BL:  state_.rbx = (state_.rbx & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_SIL: state_.rsi = (state_.rsi & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_DIL: state_.rdi = (state_.rdi & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_SPL: state_.rsp = (state_.rsp & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_BPL: state_.rbp = (state_.rbp & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R8B:  state_.r8  = (state_.r8  & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R9B:  state_.r9  = (state_.r9  & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R10B: state_.r10 = (state_.r10 & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R11B: state_.r11 = (state_.r11 & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R12B: state_.r12 = (state_.r12 & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R13B: state_.r13 = (state_.r13 & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R14B: state_.r14 = (state_.r14 & ~0xFFULL) | (val & 0xFF); break;
        case X86_REG_R15B: state_.r15 = (state_.r15 & ~0xFFULL) | (val & 0xFF); break;

        // 8-bit high: merge
        case X86_REG_AH: state_.rax = (state_.rax & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_REG_CH: state_.rcx = (state_.rcx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_REG_DH: state_.rdx = (state_.rdx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;
        case X86_REG_BH: state_.rbx = (state_.rbx & ~0xFF00ULL) | ((val & 0xFF) << 8); break;

        // Segment registers
        case X86_REG_CS: state_.cs = static_cast<uint16_t>(val); break;
        case X86_REG_DS: state_.ds = static_cast<uint16_t>(val); break;
        case X86_REG_ES: state_.es = static_cast<uint16_t>(val); break;
        case X86_REG_FS: state_.fs = static_cast<uint16_t>(val); break;
        case X86_REG_GS: state_.gs = static_cast<uint16_t>(val); break;
        case X86_REG_SS: state_.ss = static_cast<uint16_t>(val); break;

        default: break;
    }
}

// ============================================================
// read_operand / write_operand
// ============================================================

uint64_t X64Backend::read_operand(const cs_x86_op& op, int size) const {
    switch (op.type) {
        case X86_OP_REG:
            return cs_reg_to_vx_val(op.reg);

        case X86_OP_IMM:
            return static_cast<uint64_t>(op.imm);

        case X86_OP_MEM: {
            // Note: effective_address needs insn context for RIP-relative;
            // callers must use the explicit overload. This fallback uses 0/0
            // and should not be reached for RIP-relative operands.
            uint64_t addr = effective_address(op, 0, 0);
            uint64_t val = 0;
            vmem_.read(addr, &val, size);
            return val;
        }

        default:
            return 0;
    }
}

void X64Backend::write_operand(const cs_x86_op& op, uint64_t val, int size) {
    switch (op.type) {
        case X86_OP_REG:
            cs_reg_write(op.reg, val);
            break;

        case X86_OP_MEM: {
            uint64_t addr = effective_address(op, 0, 0);
            vmem_.write(addr, &val, size);
            break;
        }

        default:
            break;
    }
}

// ============================================================
// Flag update helpers (64-bit aware)
// ============================================================

/// Compute parity of low byte: PF=1 if even number of set bits
static bool parity(uint64_t val) {
    uint8_t b = val & 0xFF;
    b ^= (b >> 4);
    b ^= (b >> 2);
    b ^= (b >> 1);
    return (b & 1) == 0;
}

/// Mask for the sign bit at given operand size
static uint64_t sign_bit(int size) {
    switch (size) {
        case 1: return 0x80ULL;
        case 2: return 0x8000ULL;
        case 4: return 0x80000000ULL;
        case 8: return 0x8000000000000000ULL;
        default: return 0x80000000ULL;
    }
}

/// Mask for the operand size
static uint64_t size_mask(int size) {
    switch (size) {
        case 1: return 0xFFULL;
        case 2: return 0xFFFFULL;
        case 4: return 0xFFFFFFFFULL;
        case 8: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0xFFFFFFFFULL;
    }
}

void X64Backend::update_flags_add(uint64_t a, uint64_t b, uint64_t result, int size) {
    uint64_t mask = size_mask(size);
    uint64_t sb = sign_bit(size);
    uint64_t r = result & mask;
    uint64_t a_m = a & mask;
    uint64_t b_m = b & mask;

    // CF: unsigned overflow
    bool cf;
    if (size == 8) {
        // For 64-bit, check if addition wrapped
        cf = (r < a_m);
    } else {
        uint64_t full = a_m + b_m;
        cf = (full >> (size * 8)) != 0;
    }

    bool zf = (r == 0);
    bool sf = (r & sb) != 0;
    bool of = ((~(a_m ^ b_m)) & (a_m ^ r) & sb) != 0;
    bool af = ((a ^ b ^ result) & 0x10) != 0;
    bool pf_val = parity(r);

    state_.rflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    if (cf) state_.rflags |= EFLAG_CF;
    if (zf) state_.rflags |= EFLAG_ZF;
    if (sf) state_.rflags |= EFLAG_SF;
    if (of) state_.rflags |= EFLAG_OF;
    if (af) state_.rflags |= EFLAG_AF;
    if (pf_val) state_.rflags |= EFLAG_PF;
}

void X64Backend::update_flags_sub(uint64_t a, uint64_t b, uint64_t result, int size) {
    uint64_t mask = size_mask(size);
    uint64_t sb = sign_bit(size);
    uint64_t r = result & mask;
    uint64_t a_m = a & mask;
    uint64_t b_m = b & mask;

    bool cf = (a_m < b_m);
    bool zf = (r == 0);
    bool sf = (r & sb) != 0;
    bool of = (((a_m ^ b_m) & (a_m ^ r)) & sb) != 0;
    bool af = ((a ^ b ^ result) & 0x10) != 0;
    bool pf_val = parity(r);

    state_.rflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    if (cf) state_.rflags |= EFLAG_CF;
    if (zf) state_.rflags |= EFLAG_ZF;
    if (sf) state_.rflags |= EFLAG_SF;
    if (of) state_.rflags |= EFLAG_OF;
    if (af) state_.rflags |= EFLAG_AF;
    if (pf_val) state_.rflags |= EFLAG_PF;
}

void X64Backend::update_flags_logic(uint64_t result, int size) {
    uint64_t mask = size_mask(size);
    uint64_t sb = sign_bit(size);
    uint64_t r = result & mask;

    bool zf = (r == 0);
    bool sf = (r & sb) != 0;
    bool pf_val = parity(r);

    state_.rflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_SF | EFLAG_OF | EFLAG_AF | EFLAG_PF);
    // CF and OF are always cleared by logic ops
    if (zf) state_.rflags |= EFLAG_ZF;
    if (sf) state_.rflags |= EFLAG_SF;
    // AF is undefined after logic ops, we clear it
    if (pf_val) state_.rflags |= EFLAG_PF;
}

} // namespace vx
