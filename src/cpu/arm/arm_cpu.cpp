/**
 * VXEngine ARM32 CPU Backend — Core Implementation
 *
 * Capstone-based decoder with custom instruction interpreter.
 * This file contains:
 *   - Constructor/Destructor (dual Capstone handle init: ARM + Thumb)
 *   - Execution loop (step, step_over, run_until, run_block)
 *   - Condition code evaluation (N/Z/C/V)
 *   - Register read/write
 *   - State snapshot/restore
 *   - Disassembly (mode-aware)
 *   - Hook management
 *   - Barrel shifter
 *   - Effective address computation
 *   - Stack operations
 *   - ICpuBackend factory registration
 */

#include "vxengine/cpu/arm/arm_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>
#include <stdexcept>

namespace vx {

// Forward declarations for instruction dispatch (implemented in arm_insns.cpp)
extern ARMBackend::ExecResult arm_dispatch_insn(ARMBackend& cpu, const cs_insn* insn, VirtualMemory& vmem);
extern ARMBackend::ExecResult arm_dispatch_vfp(ARMBackend& cpu, const cs_insn* insn, VirtualMemory& vmem);

// ============================================================
// Constructor / Destructor
// ============================================================

ARMBackend::ARMBackend(VirtualMemory& vmem)
    : vmem_(vmem)
{
    // Initialize Capstone for ARM mode (32-bit ARM instructions)
    cs_err err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &cs_arm_handle_);
    if (err != CS_ERR_OK) {
        throw std::runtime_error(std::string("Capstone ARM init failed: ") + cs_strerror(err));
    }
    cs_option(cs_arm_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize Capstone for Thumb mode (16/32-bit Thumb instructions)
    err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &cs_thumb_handle_);
    if (err != CS_ERR_OK) {
        cs_close(&cs_arm_handle_);
        throw std::runtime_error(std::string("Capstone Thumb init failed: ") + cs_strerror(err));
    }
    cs_option(cs_thumb_handle_, CS_OPT_DETAIL, CS_OPT_ON);

    // Initialize CPU state to sane defaults
    std::memset(&state_, 0, sizeof(state_));
    state_.cpsr = 0x10;  // User mode (0b10000), ARM mode (T=0)
    state_.fpscr = 0;
}

ARMBackend::~ARMBackend() {
    if (cs_arm_handle_) {
        cs_close(&cs_arm_handle_);
        cs_arm_handle_ = 0;
    }
    if (cs_thumb_handle_) {
        cs_close(&cs_thumb_handle_);
        cs_thumb_handle_ = 0;
    }
}

// ============================================================
// Condition code evaluation
// ============================================================

bool ARMBackend::evaluate_condition(arm_cc cc) const {
    bool N = state_.flag_n();
    bool Z = state_.flag_z();
    bool C = state_.flag_c();
    bool V = state_.flag_v();

    switch (cc) {
        case ARM_CC_EQ: return Z;                    // Equal (Z==1)
        case ARM_CC_NE: return !Z;                   // Not equal (Z==0)
        case ARM_CC_HS: return C;                    // Carry set / unsigned >= (C==1)
        case ARM_CC_LO: return !C;                   // Carry clear / unsigned < (C==0)
        case ARM_CC_MI: return N;                    // Minus / negative (N==1)
        case ARM_CC_PL: return !N;                   // Plus / positive or zero (N==0)
        case ARM_CC_VS: return V;                    // Overflow (V==1)
        case ARM_CC_VC: return !V;                   // No overflow (V==0)
        case ARM_CC_HI: return C && !Z;              // Unsigned higher (C==1 && Z==0)
        case ARM_CC_LS: return !C || Z;              // Unsigned lower or same
        case ARM_CC_GE: return N == V;               // Signed >=
        case ARM_CC_LT: return N != V;               // Signed <
        case ARM_CC_GT: return !Z && (N == V);       // Signed >
        case ARM_CC_LE: return Z || (N != V);        // Signed <=
        case ARM_CC_AL: return true;                 // Always
        case ARM_CC_INVALID: return true;            // No condition = always execute
        default: return true;
    }
}

// ============================================================
// Barrel shifter
// ============================================================

uint32_t ARMBackend::barrel_shift(uint32_t value, arm_shifter type,
                                   uint32_t amount, bool& carry_out) const {
    carry_out = state_.flag_c();  // Default: preserve current carry

    if (amount == 0 && type != ARM_SFT_RRX) {
        return value;
    }

    switch (type) {
        case ARM_SFT_LSL:
        case ARM_SFT_LSL_REG:
            if (amount == 0) return value;
            if (amount < 32) {
                carry_out = (value >> (32 - amount)) & 1;
                return value << amount;
            }
            if (amount == 32) {
                carry_out = value & 1;
                return 0;
            }
            carry_out = false;
            return 0;

        case ARM_SFT_LSR:
        case ARM_SFT_LSR_REG:
            if (amount == 0 || amount == 32) {
                carry_out = (value >> 31) & 1;
                return 0;
            }
            if (amount < 32) {
                carry_out = (value >> (amount - 1)) & 1;
                return value >> amount;
            }
            carry_out = false;
            return 0;

        case ARM_SFT_ASR:
        case ARM_SFT_ASR_REG: {
            int32_t sval = static_cast<int32_t>(value);
            if (amount == 0 || amount >= 32) {
                carry_out = (value >> 31) & 1;
                return static_cast<uint32_t>(sval >> 31);
            }
            carry_out = (value >> (amount - 1)) & 1;
            return static_cast<uint32_t>(sval >> amount);
        }

        case ARM_SFT_ROR:
        case ARM_SFT_ROR_REG: {
            uint32_t rot = amount & 31;
            if (amount == 0) return value;
            if (rot == 0) {
                carry_out = (value >> 31) & 1;
                return value;
            }
            uint32_t result = (value >> rot) | (value << (32 - rot));
            carry_out = (result >> 31) & 1;
            return result;
        }

        case ARM_SFT_RRX: {
            // Rotate right extended: 33-bit rotation through carry
            bool old_carry = state_.flag_c();
            carry_out = value & 1;
            return (value >> 1) | (old_carry ? (1u << 31) : 0);
        }

        default:
            return value;
    }
}

// ============================================================
// Execution: execute_one
// ============================================================

ARMBackend::ExecResult ARMBackend::execute_one() {
    bool thumb = state_.thumb();
    csh handle = thumb ? cs_thumb_handle_ : cs_arm_handle_;

    // Fetch bytes at current PC
    // ARM mode: always 4 bytes; Thumb mode: 2 or 4 bytes (fetch 4 to cover Thumb-2)
    uint8_t code[4];
    size_t fetch_size = 4;
    if (!vmem_.fetch(state_.pc(), code, fetch_size)) {
        return { false, StopReason::ERROR, state_.pc() };
    }

    // Decode one instruction
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, fetch_size, state_.pc(), 1, &insn);
    if (count == 0) {
        return { false, StopReason::ERROR, state_.pc() };
    }

    // Fire code hooks
    fire_code_hooks(state_.pc(), static_cast<uint32_t>(insn->size));

    // Default: advance PC past the current instruction
    uint32_t next_pc = static_cast<uint32_t>(insn->address) + insn->size;

    // Check condition code — every ARM instruction can be conditional
    const cs_arm& arm = insn->detail->arm;
    if (!evaluate_condition(arm.cc)) {
        // Condition not met: skip instruction, advance PC
        state_.pc() = next_pc;
        insn_count_++;
        cs_free(insn, count);
        return { true, StopReason::STEP, 0 };
    }

    // Dispatch to instruction handler
    ExecResult result;
    bool is_vfp = false;
    switch (insn->id) {
        case ARM_INS_VLDR: case ARM_INS_VSTR:
        case ARM_INS_VMOV: case ARM_INS_VADD:
        case ARM_INS_VSUB: case ARM_INS_VMUL:
        case ARM_INS_VDIV: case ARM_INS_VCMP:
        case ARM_INS_VCVT: case ARM_INS_VMRS:
        case ARM_INS_VMSR: case ARM_INS_VNEG:
        case ARM_INS_VABS: case ARM_INS_VSQRT:
            is_vfp = true;
            break;
        default:
            break;
    }

    if (is_vfp) {
        result = arm_dispatch_vfp(*this, insn, vmem_);
    } else {
        result = arm_dispatch_insn(*this, insn, vmem_);
    }

    // If the instruction handler didn't set next_pc, advance past instruction
    if (result.ok && result.next_pc == 0) {
        state_.pc() = next_pc;
    } else if (result.ok) {
        state_.pc() = static_cast<uint32_t>(result.next_pc);
    }

    insn_count_++;
    cs_free(insn, count);
    return result;
}

// ============================================================
// Execution: step
// ============================================================

StepResult ARMBackend::step() {
    StepResult sr;
    sr.addr = state_.pc();
    sr.regs_before = snapshot();

    // Disassemble for the step result
    sr.disasm = disasm(state_.pc());

    // Fetch instruction size
    csh handle = active_cs_handle();
    uint8_t code[4];
    if (vmem_.fetch(state_.pc(), code, sizeof(code))) {
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle, code, sizeof(code), state_.pc(), 1, &insn);
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

StepResult ARMBackend::step_over() {
    uint8_t code[4];
    if (!vmem_.fetch(state_.pc(), code, sizeof(code))) {
        return step();
    }

    csh handle = active_cs_handle();
    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, sizeof(code), state_.pc(), 1, &insn);
    if (count == 0) {
        return step();
    }

    bool is_call = (insn->id == ARM_INS_BL || insn->id == ARM_INS_BLX);
    uint32_t next_addr = static_cast<uint32_t>(insn->address) + insn->size;
    cs_free(insn, count);

    if (is_call) {
        StepResult sr;
        sr.addr = state_.pc();
        sr.regs_before = snapshot();
        sr.disasm = disasm(state_.pc());

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

RunResult ARMBackend::run_until(uint64_t addr, uint64_t max_insns) {
    RunResult rr;
    rr.insn_count = 0;

    uint64_t limit = (max_insns > 0) ? max_insns : 0xFFFFFFFFULL;

    while (rr.insn_count < limit) {
        if (state_.pc() == static_cast<uint32_t>(addr)) {
            rr.reason = StopReason::ADDRESS_HIT;
            rr.stop_addr = state_.pc();
            return rr;
        }

        if (breakpoints_.count(state_.pc()) && rr.insn_count > 0) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.pc();
            return rr;
        }

        auto result = execute_one();
        rr.insn_count++;

        if (!result.ok) {
            rr.reason = result.stop;
            rr.stop_addr = state_.pc();
            return rr;
        }

        if (result.stop == StopReason::HALT || result.stop == StopReason::EXCEPTION ||
            result.stop == StopReason::SENTINEL_HIT) {
            rr.reason = result.stop;
            rr.stop_addr = state_.pc();
            return rr;
        }
    }

    rr.reason = StopReason::MAX_INSNS;
    rr.stop_addr = state_.pc();
    return rr;
}

// ============================================================
// Execution: run_block (execute until branch/call/ret)
// ============================================================

RunResult ARMBackend::run_block() {
    RunResult rr;
    rr.insn_count = 0;

    while (true) {
        if (breakpoints_.count(state_.pc()) && rr.insn_count > 0) {
            rr.reason = StopReason::BREAKPOINT;
            rr.stop_addr = state_.pc();
            return rr;
        }

        uint8_t code[4];
        if (!vmem_.fetch(state_.pc(), code, sizeof(code))) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.pc();
            return rr;
        }

        csh handle = active_cs_handle();
        cs_insn* insn = nullptr;
        size_t count = cs_disasm(handle, code, sizeof(code), state_.pc(), 1, &insn);
        if (count == 0) {
            rr.reason = StopReason::ERROR;
            rr.stop_addr = state_.pc();
            return rr;
        }

        bool is_block_end = false;
        switch (insn->id) {
            case ARM_INS_B:
            case ARM_INS_BL:
            case ARM_INS_BX:
            case ARM_INS_BLX:
            case ARM_INS_SVC:
            case ARM_INS_BKPT:
                is_block_end = true;
                break;
            default:
                // Check for POP {pc} or MOV pc, lr (function return patterns)
                if (insn->detail) {
                    for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
                        if (insn->detail->groups[g] == ARM_GRP_JUMP ||
                            insn->detail->groups[g] == ARM_GRP_BRANCH_RELATIVE) {
                            is_block_end = true;
                            break;
                        }
                    }
                }
                break;
        }

        cs_free(insn, count);

        auto result = execute_one();
        rr.insn_count++;

        if (!result.ok || result.stop == StopReason::HALT ||
            result.stop == StopReason::EXCEPTION ||
            result.stop == StopReason::SENTINEL_HIT) {
            rr.reason = result.ok ? result.stop : StopReason::ERROR;
            rr.stop_addr = state_.pc();
            return rr;
        }

        if (is_block_end) {
            rr.reason = StopReason::STEP;
            rr.stop_addr = state_.pc();
            return rr;
        }
    }
}

// ============================================================
// Capstone ARM register mapping
// ============================================================

int ARMBackend::cs_arm_reg_to_index(arm_reg reg) const {
    if (reg >= ARM_REG_R0 && reg <= ARM_REG_R12) {
        return reg - ARM_REG_R0;
    }
    switch (reg) {
        case ARM_REG_SP: return 13;
        case ARM_REG_LR: return 14;
        case ARM_REG_PC: return 15;
        default: return -1;
    }
}

uint32_t ARMBackend::cs_arm_reg_value(arm_reg reg) const {
    int idx = cs_arm_reg_to_index(reg);
    if (idx >= 0 && idx < 16) {
        return state_.r[idx];
    }
    if (reg == ARM_REG_CPSR) return state_.cpsr;
    if (reg == ARM_REG_SPSR) return state_.spsr;
    return 0;
}

void ARMBackend::cs_arm_reg_write(arm_reg reg, uint32_t val) {
    int idx = cs_arm_reg_to_index(reg);
    if (idx >= 0 && idx < 16) {
        state_.r[idx] = val;
        return;
    }
    if (reg == ARM_REG_CPSR) { state_.cpsr = val; return; }
    if (reg == ARM_REG_SPSR) { state_.spsr = val; return; }
}

// ============================================================
// Register access (via ARMReg enum)
// ============================================================

uint64_t ARMBackend::reg(int id) const {
    // General purpose R0-R15
    if (id >= ARM_R0 && id <= ARM_PC) {
        return state_.r[id - ARM_R0];
    }

    switch (id) {
        case ARM_CPSR: return state_.cpsr;
        case ARM_SPSR: return state_.spsr;
        default: break;
    }

    // VFP single-precision S0-S31
    if (id >= ARM_S0 && id <= ARM_S31) {
        int idx = id - ARM_S0;
        uint32_t raw;
        std::memcpy(&raw, &state_.s[idx], sizeof(raw));
        return raw;
    }

    // VFP double-precision D0-D31
    if (id >= ARM_D0 && id <= ARM_D31) {
        int idx = id - ARM_D0;
        uint64_t raw;
        std::memcpy(&raw, &state_.d[idx], sizeof(raw));
        return raw;
    }

    return 0;
}

void ARMBackend::set_reg(int id, uint64_t val) {
    uint32_t v32 = static_cast<uint32_t>(val);

    // General purpose R0-R15
    if (id >= ARM_R0 && id <= ARM_PC) {
        state_.r[id - ARM_R0] = v32;
        return;
    }

    switch (id) {
        case ARM_CPSR: state_.cpsr = v32; return;
        case ARM_SPSR: state_.spsr = v32; return;
        default: break;
    }

    // VFP single-precision
    if (id >= ARM_S0 && id <= ARM_S31) {
        int idx = id - ARM_S0;
        std::memcpy(&state_.s[idx], &v32, sizeof(float));
        return;
    }

    // VFP double-precision
    if (id >= ARM_D0 && id <= ARM_D31) {
        int idx = id - ARM_D0;
        std::memcpy(&state_.d[idx], &val, sizeof(double));
        return;
    }
}

// ============================================================
// Snapshot / Restore
// ============================================================

RegSnapshot ARMBackend::snapshot() const {
    RegSnapshot snap{};

    // Map ARM registers into the x86-centric RegSnapshot as best we can
    // R0-R7 -> rax,rbx,rcx,rdx,rsi,rdi,rbp,rsp area (repurposed)
    snap.rax = state_.r[0];
    snap.rbx = state_.r[1];
    snap.rcx = state_.r[2];
    snap.rdx = state_.r[3];
    snap.rsi = state_.r[4];
    snap.rdi = state_.r[5];
    snap.rbp = state_.r[6];
    snap.rsp = state_.r[13];   // SP
    snap.r8  = state_.r[7];
    snap.r9  = state_.r[8];
    snap.r10 = state_.r[9];
    snap.r11 = state_.r[10];
    snap.r12 = state_.r[11];
    snap.r13 = state_.r[12];
    snap.r14 = state_.r[14];   // LR
    snap.r15 = state_.spsr;
    snap.rip = state_.r[15];   // PC
    snap.eflags = state_.cpsr;

    return snap;
}

void ARMBackend::restore(const RegSnapshot& snap) {
    state_.r[0]  = static_cast<uint32_t>(snap.rax);
    state_.r[1]  = static_cast<uint32_t>(snap.rbx);
    state_.r[2]  = static_cast<uint32_t>(snap.rcx);
    state_.r[3]  = static_cast<uint32_t>(snap.rdx);
    state_.r[4]  = static_cast<uint32_t>(snap.rsi);
    state_.r[5]  = static_cast<uint32_t>(snap.rdi);
    state_.r[6]  = static_cast<uint32_t>(snap.rbp);
    state_.r[13] = static_cast<uint32_t>(snap.rsp);
    state_.r[7]  = static_cast<uint32_t>(snap.r8);
    state_.r[8]  = static_cast<uint32_t>(snap.r9);
    state_.r[9]  = static_cast<uint32_t>(snap.r10);
    state_.r[10] = static_cast<uint32_t>(snap.r11);
    state_.r[11] = static_cast<uint32_t>(snap.r12);
    state_.r[12] = static_cast<uint32_t>(snap.r13);
    state_.r[14] = static_cast<uint32_t>(snap.r14);
    state_.spsr  = static_cast<uint32_t>(snap.r15);
    state_.r[15] = static_cast<uint32_t>(snap.rip);
    state_.cpsr  = snap.eflags;
}

// ============================================================
// Disassembly
// ============================================================

std::string ARMBackend::disasm(uint64_t addr) const {
    uint8_t code[4];
    if (!vmem_.fetch(addr, code, sizeof(code))) {
        return "<fetch error>";
    }

    // Use the correct Capstone handle based on current mode
    csh handle = state_.thumb() ? cs_thumb_handle_ : cs_arm_handle_;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, sizeof(code), addr, 1, &insn);
    if (count == 0) {
        return "<decode error>";
    }

    std::string result = std::string(insn->mnemonic) + " " + insn->op_str;
    cs_free(insn, count);
    return result;
}

std::string ARMBackend::disasm_at_pc() const {
    return disasm(state_.pc());
}

// ============================================================
// Hooks
// ============================================================

HookID ARMBackend::add_code_hook(uint64_t begin, uint64_t end, CodeCallback cb) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, std::move(cb), nullptr, AccessType::EXEC, true };
    return id;
}

HookID ARMBackend::add_mem_hook(uint64_t begin, uint64_t end,
                                 MemCallback cb, AccessType type) {
    HookID id = next_hook_id_++;
    hooks_[id] = { begin, end, nullptr, std::move(cb), type, false };
    return id;
}

void ARMBackend::remove_hook(HookID id) {
    hooks_.erase(id);
}

void ARMBackend::fire_code_hooks(uint64_t addr, uint32_t size) {
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

void ARMBackend::add_breakpoint(uint64_t addr) {
    breakpoints_.insert(addr);
}

void ARMBackend::remove_breakpoint(uint64_t addr) {
    breakpoints_.erase(addr);
}

bool ARMBackend::has_breakpoint(uint64_t addr) const {
    return breakpoints_.count(addr) > 0;
}

// ============================================================
// Stack operations
// ============================================================

void ARMBackend::push32(uint32_t val) {
    state_.sp() -= 4;
    vmem_.write32(state_.sp(), val);
}

uint32_t ARMBackend::pop32() {
    uint32_t val = vmem_.read32(state_.sp());
    state_.sp() += 4;
    return val;
}

// ============================================================
// Operand read/write helpers
// ============================================================

uint32_t ARMBackend::read_operand(const cs_arm_op& op) const {
    switch (op.type) {
        case ARM_OP_REG:
            return cs_arm_reg_value(static_cast<arm_reg>(op.reg));
        case ARM_OP_IMM:
            return static_cast<uint32_t>(op.imm);
        case ARM_OP_MEM:
            return vmem_.read32(effective_address(op));
        default:
            return 0;
    }
}

void ARMBackend::write_operand(const cs_arm_op& op, uint32_t val) {
    switch (op.type) {
        case ARM_OP_REG:
            cs_arm_reg_write(static_cast<arm_reg>(op.reg), val);
            break;
        case ARM_OP_MEM:
            vmem_.write32(effective_address(op), val);
            break;
        default:
            break;
    }
}

// ============================================================
// Effective address computation for LDR/STR
// ============================================================

uint32_t ARMBackend::effective_address(const cs_arm_op& op) const {
    assert(op.type == ARM_OP_MEM);

    uint32_t addr = 0;

    // Base register
    if (op.mem.base != ARM_REG_INVALID) {
        addr = cs_arm_reg_value(op.mem.base);
    }

    // Index register (with optional shift)
    if (op.mem.index != ARM_REG_INVALID) {
        uint32_t index_val = cs_arm_reg_value(op.mem.index);

        // Apply shift if present
        if (op.shift.type != ARM_SFT_INVALID && op.shift.value > 0) {
            bool carry;
            index_val = barrel_shift(index_val, op.shift.type, op.shift.value, carry);
        }

        // Subtracted index check (op.subtracted in Capstone)
        if (op.subtracted) {
            addr -= index_val;
        } else {
            addr += index_val;
        }
    }

    // Displacement (immediate offset)
    addr += static_cast<uint32_t>(op.mem.disp);

    return addr;
}

// ============================================================
// Flag update helpers
// ============================================================

void ARMBackend::update_flags_nz(uint32_t result) {
    state_.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z);
    if (result == 0) state_.cpsr |= ARM_FLAG_Z;
    if (result & (1u << 31)) state_.cpsr |= ARM_FLAG_N;
}

void ARMBackend::update_flags_add(uint32_t a, uint32_t b, uint32_t result) {
    state_.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z | ARM_FLAG_C | ARM_FLAG_V);
    if (result == 0) state_.cpsr |= ARM_FLAG_Z;
    if (result & (1u << 31)) state_.cpsr |= ARM_FLAG_N;
    // Carry: unsigned overflow
    if (static_cast<uint64_t>(a) + static_cast<uint64_t>(b) > 0xFFFFFFFFULL) {
        state_.cpsr |= ARM_FLAG_C;
    }
    // Overflow: signed overflow
    uint32_t sign_a = a >> 31;
    uint32_t sign_b = b >> 31;
    uint32_t sign_r = result >> 31;
    if ((sign_a == sign_b) && (sign_a != sign_r)) {
        state_.cpsr |= ARM_FLAG_V;
    }
}

void ARMBackend::update_flags_sub(uint32_t a, uint32_t b, uint32_t result) {
    state_.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z | ARM_FLAG_C | ARM_FLAG_V);
    if (result == 0) state_.cpsr |= ARM_FLAG_Z;
    if (result & (1u << 31)) state_.cpsr |= ARM_FLAG_N;
    // Carry: no borrow (ARM convention: C = NOT borrow)
    if (a >= b) state_.cpsr |= ARM_FLAG_C;
    // Overflow: signed overflow
    uint32_t sign_a = a >> 31;
    uint32_t sign_b = b >> 31;
    uint32_t sign_r = result >> 31;
    if ((sign_a != sign_b) && (sign_a != sign_r)) {
        state_.cpsr |= ARM_FLAG_V;
    }
}

// ============================================================
// Factory: ICpuBackend::create — add ARM_32 case
// ============================================================
// NOTE: The factory is defined in x86_cpu.cpp. This file registers
// the ARM backend by being linked. The factory switch in x86_cpu.cpp
// must be updated to include:
//   case Arch::ARM_32: return std::make_unique<ARMBackend>(vmem);

} // namespace vx
