/**
 * VXEngine ARM32 CPU Backend — Instruction Semantics
 *
 * This file implements all ARM32 instruction handlers:
 *   - Data Processing: MOV, MVN, ADD, ADC, SUB, SBC, RSB, RSC, AND, ORR, EOR, BIC,
 *                       TST, TEQ, CMP, CMN (with barrel shifter operand2)
 *   - Multiply: MUL, MLA, UMULL, UMLAL, SMULL, SMLAL
 *   - Load/Store: LDR, LDRB, LDRH, LDRSB, LDRSH, STR, STRB, STRH
 *   - Block Transfer: LDM, STM, PUSH, POP
 *   - Branch: B, BL, BX, BLX (ARM<->Thumb interworking)
 *   - Status: MRS, MSR
 *   - Misc: NOP, BKPT, SVC, CLZ, REV, REV16, REVSH
 *   - VFP: VLDR, VSTR, VMOV, VADD, VSUB, VMUL, VDIV, VCMP, VCVT, VMRS, VMSR
 *
 * Capstone normalizes both ARM and Thumb instructions into the same cs_insn
 * structure, so Thumb-2 is handled transparently.
 */

#include "vxengine/cpu/arm/arm_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>
#include <cmath>

namespace vx {

// ============================================================
// Helper: resolve operand2 with barrel shifter for data processing
// ============================================================

static uint32_t resolve_operand2(const ARMBackend& cpu, const cs_arm& arm,
                                  int op_index, bool& carry_out) {
    if (op_index >= arm.op_count) {
        carry_out = cpu.state().flag_c();
        return 0;
    }

    const cs_arm_op& op = arm.operands[op_index];

    if (op.type == ARM_OP_IMM) {
        carry_out = cpu.state().flag_c();
        return static_cast<uint32_t>(op.imm);
    }

    if (op.type == ARM_OP_REG) {
        uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(op.reg));

        // Apply shift if present
        if (op.shift.type != ARM_SFT_INVALID && op.shift.value > 0) {
            val = cpu.barrel_shift(val, op.shift.type, op.shift.value, carry_out);
        } else {
            carry_out = cpu.state().flag_c();
        }
        return val;
    }

    carry_out = cpu.state().flag_c();
    return 0;
}

// ============================================================
// Helper: check if instruction updates flags (S suffix)
// ============================================================

static bool updates_flags(const cs_arm& arm) {
    return arm.update_flags;
}

// ============================================================
// Helper: count leading zeros (CLZ)
// ============================================================

static uint32_t count_leading_zeros(uint32_t val) {
    if (val == 0) return 32;
    uint32_t n = 0;
    if ((val & 0xFFFF0000) == 0) { n += 16; val <<= 16; }
    if ((val & 0xFF000000) == 0) { n += 8;  val <<= 8; }
    if ((val & 0xF0000000) == 0) { n += 4;  val <<= 4; }
    if ((val & 0xC0000000) == 0) { n += 2;  val <<= 2; }
    if ((val & 0x80000000) == 0) { n += 1; }
    return n;
}

// ============================================================
// Main instruction dispatcher
// ============================================================

ARMBackend::ExecResult arm_dispatch_insn(ARMBackend& cpu, const cs_insn* insn,
                                          VirtualMemory& vmem) {
    ARMBackend::ExecResult result;
    ARMState& st = cpu.state();
    const cs_arm& arm = insn->detail->arm;

    auto get_rd = [&]() -> arm_reg {
        return (arm.op_count > 0) ? static_cast<arm_reg>(arm.operands[0].reg) : ARM_REG_INVALID;
    };

    auto get_rn_val = [&](int idx = 1) -> uint32_t {
        if (idx >= arm.op_count) return 0;
        const cs_arm_op& op = arm.operands[idx];
        if (op.type == ARM_OP_REG) return cpu.cs_arm_reg_value(static_cast<arm_reg>(op.reg));
        if (op.type == ARM_OP_IMM) return static_cast<uint32_t>(op.imm);
        return 0;
    };

    switch (insn->id) {

    // ============================================================
    // Data Processing: MOV, MVN
    // ============================================================

    case ARM_INS_MOV: {
        bool carry;
        uint32_t val = resolve_operand2(cpu, arm, 1, carry);
        cpu.cs_arm_reg_write(get_rd(), val);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(val);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
            // If Rd == PC and S bit, special behavior (CPSR = SPSR)
            if (get_rd() == ARM_REG_PC) {
                st.cpsr = st.spsr;
            }
        }
        // MOV PC, Rm can switch modes (check bit 0 for Thumb)
        if (get_rd() == ARM_REG_PC) {
            if (val & 1) {
                st.cpsr |= ARM_FLAG_T;
                result.next_pc = val & ~1u;
            } else {
                st.cpsr &= ~ARM_FLAG_T;
                result.next_pc = val & ~3u;
            }
        }
        break;
    }

    case ARM_INS_MVN: {
        bool carry;
        uint32_t val = ~resolve_operand2(cpu, arm, 1, carry);
        cpu.cs_arm_reg_write(get_rd(), val);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(val);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    // ============================================================
    // Data Processing: ADD, ADC, SUB, SBC, RSB, RSC
    // ============================================================

    case ARM_INS_ADD: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn + op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) cpu.update_flags_add(rn, op2, res);
        if (get_rd() == ARM_REG_PC) result.next_pc = res;
        break;
    }

    case ARM_INS_ADC: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t c = st.flag_c() ? 1u : 0u;
        uint32_t res = rn + op2 + c;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            // ADC carry/overflow considers the carry-in
            uint64_t full = static_cast<uint64_t>(rn) + op2 + c;
            st.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z | ARM_FLAG_C | ARM_FLAG_V);
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
            if (res & (1u << 31)) st.cpsr |= ARM_FLAG_N;
            if (full > 0xFFFFFFFFULL) st.cpsr |= ARM_FLAG_C;
            uint32_t sa = rn >> 31, sb = op2 >> 31, sr = res >> 31;
            if ((sa == sb) && (sa != sr)) st.cpsr |= ARM_FLAG_V;
        }
        break;
    }

    case ARM_INS_SUB: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn - op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) cpu.update_flags_sub(rn, op2, res);
        if (get_rd() == ARM_REG_PC) result.next_pc = res;
        break;
    }

    case ARM_INS_SBC: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t c = st.flag_c() ? 0u : 1u;  // NOT carry = borrow
        uint32_t res = rn - op2 - c;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            st.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z | ARM_FLAG_C | ARM_FLAG_V);
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
            if (res & (1u << 31)) st.cpsr |= ARM_FLAG_N;
            if (static_cast<uint64_t>(rn) >= static_cast<uint64_t>(op2) + c) st.cpsr |= ARM_FLAG_C;
            uint32_t sa = rn >> 31, sb = op2 >> 31, sr = res >> 31;
            if ((sa != sb) && (sa != sr)) st.cpsr |= ARM_FLAG_V;
        }
        break;
    }

    case ARM_INS_RSB: {
        // Reverse subtract: Rd = Op2 - Rn
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = op2 - rn;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) cpu.update_flags_sub(op2, rn, res);
        break;
    }

    case ARM_INS_RSC: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t c = st.flag_c() ? 0u : 1u;
        uint32_t res = op2 - rn - c;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            st.cpsr &= ~(ARM_FLAG_N | ARM_FLAG_Z | ARM_FLAG_C | ARM_FLAG_V);
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
            if (res & (1u << 31)) st.cpsr |= ARM_FLAG_N;
            if (static_cast<uint64_t>(op2) >= static_cast<uint64_t>(rn) + c) st.cpsr |= ARM_FLAG_C;
            uint32_t sa = op2 >> 31, sb = rn >> 31, sr = res >> 31;
            if ((sa != sb) && (sa != sr)) st.cpsr |= ARM_FLAG_V;
        }
        break;
    }

    // ============================================================
    // Data Processing: AND, ORR, EOR, BIC
    // ============================================================

    case ARM_INS_AND: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn & op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_ORR: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn | op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_EOR: {
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn ^ op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_BIC: {
        // Bit clear: Rd = Rn AND NOT Op2
        uint32_t rn = get_rn_val(1);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 2, carry);
        uint32_t res = rn & ~op2;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    // ============================================================
    // Data Processing: TST, TEQ, CMP, CMN (flags only, no writeback)
    // ============================================================

    case ARM_INS_TST: {
        uint32_t rn = get_rn_val(0);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 1, carry);
        uint32_t res = rn & op2;
        cpu.update_flags_nz(res);
        if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        break;
    }

    case ARM_INS_TEQ: {
        uint32_t rn = get_rn_val(0);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 1, carry);
        uint32_t res = rn ^ op2;
        cpu.update_flags_nz(res);
        if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        break;
    }

    case ARM_INS_CMP: {
        uint32_t rn = get_rn_val(0);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 1, carry);
        uint32_t res = rn - op2;
        cpu.update_flags_sub(rn, op2, res);
        break;
    }

    case ARM_INS_CMN: {
        uint32_t rn = get_rn_val(0);
        bool carry;
        uint32_t op2 = resolve_operand2(cpu, arm, 1, carry);
        uint32_t res = rn + op2;
        cpu.update_flags_add(rn, op2, res);
        break;
    }

    // ============================================================
    // Multiply: MUL, MLA
    // ============================================================

    case ARM_INS_MUL: {
        // MUL Rd, Rm, Rs  =>  Rd = Rm * Rs
        uint32_t rm = get_rn_val(1);
        uint32_t rs = get_rn_val(2);
        uint32_t res = rm * rs;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) cpu.update_flags_nz(res);
        break;
    }

    case ARM_INS_MLA: {
        // MLA Rd, Rm, Rs, Rn  =>  Rd = Rm * Rs + Rn
        uint32_t rm = get_rn_val(1);
        uint32_t rs = get_rn_val(2);
        uint32_t rn = get_rn_val(3);
        uint32_t res = rm * rs + rn;
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) cpu.update_flags_nz(res);
        break;
    }

    // ============================================================
    // Multiply Long: UMULL, UMLAL, SMULL, SMLAL
    // ============================================================

    case ARM_INS_UMULL: {
        // UMULL RdLo, RdHi, Rm, Rs
        arm_reg rd_lo = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rd_hi = static_cast<arm_reg>(arm.operands[1].reg);
        uint32_t rm = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[2].reg));
        uint32_t rs = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[3].reg));
        uint64_t res = static_cast<uint64_t>(rm) * static_cast<uint64_t>(rs);
        cpu.cs_arm_reg_write(rd_lo, static_cast<uint32_t>(res));
        cpu.cs_arm_reg_write(rd_hi, static_cast<uint32_t>(res >> 32));
        if (updates_flags(arm)) {
            cpu.update_flags_nz(static_cast<uint32_t>(res >> 32));
            // Z is set if the entire 64-bit result is zero
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
        }
        break;
    }

    case ARM_INS_UMLAL: {
        arm_reg rd_lo = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rd_hi = static_cast<arm_reg>(arm.operands[1].reg);
        uint32_t rm = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[2].reg));
        uint32_t rs = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[3].reg));
        uint64_t acc = (static_cast<uint64_t>(cpu.cs_arm_reg_value(rd_hi)) << 32) |
                        cpu.cs_arm_reg_value(rd_lo);
        uint64_t res = static_cast<uint64_t>(rm) * static_cast<uint64_t>(rs) + acc;
        cpu.cs_arm_reg_write(rd_lo, static_cast<uint32_t>(res));
        cpu.cs_arm_reg_write(rd_hi, static_cast<uint32_t>(res >> 32));
        if (updates_flags(arm)) {
            cpu.update_flags_nz(static_cast<uint32_t>(res >> 32));
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
        }
        break;
    }

    case ARM_INS_SMULL: {
        arm_reg rd_lo = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rd_hi = static_cast<arm_reg>(arm.operands[1].reg);
        int32_t rm = static_cast<int32_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[2].reg)));
        int32_t rs = static_cast<int32_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[3].reg)));
        int64_t res = static_cast<int64_t>(rm) * static_cast<int64_t>(rs);
        cpu.cs_arm_reg_write(rd_lo, static_cast<uint32_t>(res));
        cpu.cs_arm_reg_write(rd_hi, static_cast<uint32_t>(static_cast<uint64_t>(res) >> 32));
        if (updates_flags(arm)) {
            cpu.update_flags_nz(static_cast<uint32_t>(static_cast<uint64_t>(res) >> 32));
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
        }
        break;
    }

    case ARM_INS_SMLAL: {
        arm_reg rd_lo = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rd_hi = static_cast<arm_reg>(arm.operands[1].reg);
        int32_t rm = static_cast<int32_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[2].reg)));
        int32_t rs = static_cast<int32_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[3].reg)));
        int64_t acc = static_cast<int64_t>(
            (static_cast<uint64_t>(cpu.cs_arm_reg_value(rd_hi)) << 32) |
             cpu.cs_arm_reg_value(rd_lo));
        int64_t res = static_cast<int64_t>(rm) * static_cast<int64_t>(rs) + acc;
        cpu.cs_arm_reg_write(rd_lo, static_cast<uint32_t>(res));
        cpu.cs_arm_reg_write(rd_hi, static_cast<uint32_t>(static_cast<uint64_t>(res) >> 32));
        if (updates_flags(arm)) {
            cpu.update_flags_nz(static_cast<uint32_t>(static_cast<uint64_t>(res) >> 32));
            if (res == 0) st.cpsr |= ARM_FLAG_Z;
        }
        break;
    }

    // ============================================================
    // Load/Store: LDR, LDRB, LDRH, LDRSB, LDRSH
    // ============================================================

    case ARM_INS_LDR: {
        // LDR Rd, [Rn, #offset] / [Rn, Rm] / etc.
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];

        uint32_t addr = cpu.effective_address(src);
        uint32_t val = vmem.read32(addr);

        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), val);

        // Writeback: pre-index with ! or post-index
        if (insn->detail->writeback && src.type == ARM_OP_MEM && src.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(src.mem.base, addr);
        }

        // LDR PC -> possible mode switch
        if (dst.reg == ARM_REG_PC) {
            if (val & 1) {
                st.cpsr |= ARM_FLAG_T;
                result.next_pc = val & ~1u;
            } else {
                st.cpsr &= ~ARM_FLAG_T;
                result.next_pc = val & ~3u;
            }
        }
        break;
    }

    case ARM_INS_LDRB: {
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);
        uint8_t byte = 0;
        vmem.read(addr, &byte, 1);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), byte);
        if (insn->detail->writeback && src.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(src.mem.base, addr);
        }
        break;
    }

    case ARM_INS_LDRH: {
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);
        uint16_t half = 0;
        vmem.read(addr, &half, 2);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), half);
        if (insn->detail->writeback && src.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(src.mem.base, addr);
        }
        break;
    }

    case ARM_INS_LDRSB: {
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);
        int8_t byte = 0;
        vmem.read(addr, &byte, 1);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), static_cast<uint32_t>(static_cast<int32_t>(byte)));
        if (insn->detail->writeback && src.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(src.mem.base, addr);
        }
        break;
    }

    case ARM_INS_LDRSH: {
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);
        int16_t half = 0;
        vmem.read(addr, &half, 2);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), static_cast<uint32_t>(static_cast<int32_t>(half)));
        if (insn->detail->writeback && src.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(src.mem.base, addr);
        }
        break;
    }

    // ============================================================
    // Load/Store: STR, STRB, STRH
    // ============================================================

    case ARM_INS_STR: {
        const cs_arm_op& src_reg = arm.operands[0];
        const cs_arm_op& dst_mem = arm.operands[1];
        uint32_t addr = cpu.effective_address(dst_mem);
        uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(src_reg.reg));
        vmem.write32(addr, val);
        if (insn->detail->writeback && dst_mem.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(dst_mem.mem.base, addr);
        }
        break;
    }

    case ARM_INS_STRB: {
        const cs_arm_op& src_reg = arm.operands[0];
        const cs_arm_op& dst_mem = arm.operands[1];
        uint32_t addr = cpu.effective_address(dst_mem);
        uint8_t byte = static_cast<uint8_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(src_reg.reg)));
        vmem.write(addr, &byte, 1);
        if (insn->detail->writeback && dst_mem.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(dst_mem.mem.base, addr);
        }
        break;
    }

    case ARM_INS_STRH: {
        const cs_arm_op& src_reg = arm.operands[0];
        const cs_arm_op& dst_mem = arm.operands[1];
        uint32_t addr = cpu.effective_address(dst_mem);
        uint16_t half = static_cast<uint16_t>(cpu.cs_arm_reg_value(static_cast<arm_reg>(src_reg.reg)));
        vmem.write(addr, &half, 2);
        if (insn->detail->writeback && dst_mem.mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(dst_mem.mem.base, addr);
        }
        break;
    }

    // ============================================================
    // Block Transfer: LDM, STM (IA/IB/DA/DB), PUSH, POP
    // ============================================================

    case ARM_INS_LDM: {
        // LDM{mode} Rn{!}, {register list}
        // Capstone: operands[0] = Rn, operands[1..n] = register list
        uint32_t base_val = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[0].reg));
        uint32_t addr = base_val;

        for (int i = 1; i < arm.op_count; i++) {
            uint32_t val = vmem.read32(addr);
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[i].reg), val);
            addr += 4;
        }

        if (insn->detail->writeback) {
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[0].reg), addr);
        }

        // Check if PC was loaded (mode switch)
        for (int i = 1; i < arm.op_count; i++) {
            if (arm.operands[i].reg == ARM_REG_PC) {
                uint32_t pc_val = st.pc();
                if (pc_val & 1) {
                    st.cpsr |= ARM_FLAG_T;
                    result.next_pc = pc_val & ~1u;
                } else {
                    st.cpsr &= ~ARM_FLAG_T;
                    result.next_pc = pc_val & ~3u;
                }
                break;
            }
        }
        break;
    }

    case ARM_INS_STM: {
        uint32_t base_val = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[0].reg));
        uint32_t addr = base_val;

        for (int i = 1; i < arm.op_count; i++) {
            uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[i].reg));
            vmem.write32(addr, val);
            addr += 4;
        }

        if (insn->detail->writeback) {
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[0].reg), addr);
        }
        break;
    }

    case ARM_INS_PUSH: {
        // PUSH {reglist} is STM SP!, {reglist} (decrement before)
        int reg_count = arm.op_count;
        uint32_t new_sp = st.sp() - (reg_count * 4);
        uint32_t addr = new_sp;

        for (int i = 0; i < arm.op_count; i++) {
            uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[i].reg));
            vmem.write32(addr, val);
            addr += 4;
        }
        st.sp() = new_sp;
        break;
    }

    case ARM_INS_POP: {
        // POP {reglist} is LDM SP!, {reglist}
        uint32_t addr = st.sp();

        for (int i = 0; i < arm.op_count; i++) {
            uint32_t val = vmem.read32(addr);
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[i].reg), val);
            addr += 4;
        }
        st.sp() = addr;

        // Check if PC was popped (return / mode switch)
        for (int i = 0; i < arm.op_count; i++) {
            if (arm.operands[i].reg == ARM_REG_PC) {
                uint32_t pc_val = st.pc();
                if (pc_val & 1) {
                    st.cpsr |= ARM_FLAG_T;
                    result.next_pc = pc_val & ~1u;
                } else {
                    st.cpsr &= ~ARM_FLAG_T;
                    result.next_pc = pc_val & ~3u;
                }
                break;
            }
        }
        break;
    }

    // ============================================================
    // Branch: B, BL, BX, BLX
    // ============================================================

    case ARM_INS_B: {
        // Branch (unconditional or conditional — condition already checked)
        if (arm.op_count > 0 && arm.operands[0].type == ARM_OP_IMM) {
            result.next_pc = static_cast<uint32_t>(arm.operands[0].imm);
        }
        break;
    }

    case ARM_INS_BL: {
        // Branch with link: LR = address of next instruction
        st.lr() = static_cast<uint32_t>(insn->address) + insn->size;
        // In Thumb mode, bit 0 of LR should be set
        if (st.thumb()) st.lr() |= 1;
        if (arm.op_count > 0 && arm.operands[0].type == ARM_OP_IMM) {
            result.next_pc = static_cast<uint32_t>(arm.operands[0].imm);
        }
        break;
    }

    case ARM_INS_BX: {
        // Branch and exchange: Rm[0] determines ARM/Thumb mode
        uint32_t target = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[0].reg));
        if (target & 1) {
            st.cpsr |= ARM_FLAG_T;
            result.next_pc = target & ~1u;
        } else {
            st.cpsr &= ~ARM_FLAG_T;
            result.next_pc = target & ~3u;
        }
        break;
    }

    case ARM_INS_BLX: {
        // Branch with link and exchange
        st.lr() = static_cast<uint32_t>(insn->address) + insn->size;
        if (st.thumb()) st.lr() |= 1;

        if (arm.op_count > 0 && arm.operands[0].type == ARM_OP_REG) {
            uint32_t target = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[0].reg));
            if (target & 1) {
                st.cpsr |= ARM_FLAG_T;
                result.next_pc = target & ~1u;
            } else {
                st.cpsr &= ~ARM_FLAG_T;
                result.next_pc = target & ~3u;
            }
        } else if (arm.op_count > 0 && arm.operands[0].type == ARM_OP_IMM) {
            uint32_t target = static_cast<uint32_t>(arm.operands[0].imm);
            // BLX immediate always switches mode
            if (st.thumb()) {
                st.cpsr &= ~ARM_FLAG_T;  // Thumb -> ARM
            } else {
                st.cpsr |= ARM_FLAG_T;   // ARM -> Thumb
            }
            result.next_pc = target;
        }
        break;
    }

    // ============================================================
    // Status register: MRS, MSR
    // ============================================================

    case ARM_INS_MRS: {
        // MRS Rd, CPSR/SPSR
        if (arm.op_count >= 2) {
            uint32_t val;
            if (arm.operands[1].reg == ARM_REG_CPSR) {
                val = st.cpsr;
            } else {
                val = st.spsr;
            }
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[0].reg), val);
        }
        break;
    }

    case ARM_INS_MSR: {
        // MSR CPSR/SPSR, Rm/imm
        uint32_t val = 0;
        if (arm.op_count >= 2) {
            if (arm.operands[1].type == ARM_OP_REG) {
                val = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[1].reg));
            } else if (arm.operands[1].type == ARM_OP_IMM) {
                val = static_cast<uint32_t>(arm.operands[1].imm);
            }

            // MSR typically writes to specific fields (flags, control, etc.)
            // For simplicity, write the full value (user mode can only write flags)
            if (arm.operands[0].reg == ARM_REG_CPSR) {
                // In user mode, only allow writing to flag bits (top 4 bits)
                uint32_t mask = 0xF0000000;  // NZCV flags
                st.cpsr = (st.cpsr & ~mask) | (val & mask);
            } else {
                st.spsr = val;
            }
        }
        break;
    }

    // ============================================================
    // Shift instructions (standalone): LSL, LSR, ASR, ROR, RRX
    // ============================================================

    case ARM_INS_LSL: {
        uint32_t val = get_rn_val(1);
        uint32_t amount = get_rn_val(2);
        bool carry;
        uint32_t res = cpu.barrel_shift(val, ARM_SFT_LSL, amount, carry);
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_LSR: {
        uint32_t val = get_rn_val(1);
        uint32_t amount = get_rn_val(2);
        bool carry;
        uint32_t res = cpu.barrel_shift(val, ARM_SFT_LSR, amount, carry);
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_ASR: {
        uint32_t val = get_rn_val(1);
        uint32_t amount = get_rn_val(2);
        bool carry;
        uint32_t res = cpu.barrel_shift(val, ARM_SFT_ASR, amount, carry);
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_ROR: {
        uint32_t val = get_rn_val(1);
        uint32_t amount = get_rn_val(2);
        bool carry;
        uint32_t res = cpu.barrel_shift(val, ARM_SFT_ROR, amount, carry);
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    case ARM_INS_RRX: {
        uint32_t val = get_rn_val(1);
        bool carry;
        uint32_t res = cpu.barrel_shift(val, ARM_SFT_RRX, 1, carry);
        cpu.cs_arm_reg_write(get_rd(), res);
        if (updates_flags(arm)) {
            cpu.update_flags_nz(res);
            if (carry) st.cpsr |= ARM_FLAG_C; else st.cpsr &= ~ARM_FLAG_C;
        }
        break;
    }

    // ============================================================
    // Misc: NOP, BKPT, SVC, CLZ, REV, REV16, REVSH
    // ============================================================

    case ARM_INS_HINT:       // Capstone v6: NOP is encoded as HINT
#ifdef ARM_INS_ALIAS_NOP
    case ARM_INS_ALIAS_NOP:
#endif
        // Do nothing
        break;

    case ARM_INS_BKPT: {
        result.stop = StopReason::EXCEPTION;
        break;
    }

    case ARM_INS_SVC: {
        // Supervisor call — treat as sentinel/syscall hook point
        result.stop = StopReason::SENTINEL_HIT;
        break;
    }

    case ARM_INS_CLZ: {
        uint32_t val = get_rn_val(1);
        cpu.cs_arm_reg_write(get_rd(), count_leading_zeros(val));
        break;
    }

    case ARM_INS_REV: {
        // Byte-reverse a 32-bit word
        uint32_t val = get_rn_val(1);
        uint32_t res = ((val & 0xFF) << 24) | ((val & 0xFF00) << 8) |
                       ((val >> 8) & 0xFF00) | ((val >> 24) & 0xFF);
        cpu.cs_arm_reg_write(get_rd(), res);
        break;
    }

    case ARM_INS_REV16: {
        // Byte-reverse each halfword independently
        uint32_t val = get_rn_val(1);
        uint32_t lo = ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
        uint32_t hi = ((val & 0xFF0000) << 8) | ((val >> 8) & 0xFF0000);
        // Corrected: swap bytes within each halfword
        uint32_t res = ((val >> 8) & 0x00FF00FF) | ((val << 8) & 0xFF00FF00);
        cpu.cs_arm_reg_write(get_rd(), res);
        break;
    }

    case ARM_INS_REVSH: {
        // Byte-reverse signed halfword
        uint32_t val = get_rn_val(1);
        int16_t half = static_cast<int16_t>(((val & 0xFF) << 8) | ((val >> 8) & 0xFF));
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(static_cast<int32_t>(half)));
        break;
    }

    // ============================================================
    // Bit field: UBFX, SBFX, BFI, BFC
    // ============================================================

    case ARM_INS_UBFX: {
        // Unsigned Bit Field Extract: UBFX Rd, Rn, #lsb, #width
        uint32_t rn = get_rn_val(1);
        uint32_t lsb = static_cast<uint32_t>(arm.operands[2].imm);
        uint32_t width = static_cast<uint32_t>(arm.operands[3].imm);
        uint32_t mask = (1u << width) - 1;
        cpu.cs_arm_reg_write(get_rd(), (rn >> lsb) & mask);
        break;
    }

    case ARM_INS_SBFX: {
        // Signed Bit Field Extract
        int32_t rn = static_cast<int32_t>(get_rn_val(1));
        uint32_t lsb = static_cast<uint32_t>(arm.operands[2].imm);
        uint32_t width = static_cast<uint32_t>(arm.operands[3].imm);
        int32_t val = (rn << (32 - lsb - width)) >> (32 - width);
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(val));
        break;
    }

    case ARM_INS_BFI: {
        // Bit Field Insert: BFI Rd, Rn, #lsb, #width
        uint32_t rd = cpu.cs_arm_reg_value(get_rd());
        uint32_t rn = get_rn_val(1);
        uint32_t lsb = static_cast<uint32_t>(arm.operands[2].imm);
        uint32_t width = static_cast<uint32_t>(arm.operands[3].imm);
        uint32_t mask = ((1u << width) - 1) << lsb;
        uint32_t res = (rd & ~mask) | ((rn << lsb) & mask);
        cpu.cs_arm_reg_write(get_rd(), res);
        break;
    }

    case ARM_INS_BFC: {
        // Bit Field Clear: BFC Rd, #lsb, #width
        uint32_t rd = cpu.cs_arm_reg_value(get_rd());
        uint32_t lsb = static_cast<uint32_t>(arm.operands[1].imm);
        uint32_t width = static_cast<uint32_t>(arm.operands[2].imm);
        uint32_t mask = ((1u << width) - 1) << lsb;
        cpu.cs_arm_reg_write(get_rd(), rd & ~mask);
        break;
    }

    // ============================================================
    // Extend: SXTH, SXTB, UXTH, UXTB
    // ============================================================

    case ARM_INS_SXTH: {
        int16_t val = static_cast<int16_t>(get_rn_val(1) & 0xFFFF);
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(static_cast<int32_t>(val)));
        break;
    }

    case ARM_INS_SXTB: {
        int8_t val = static_cast<int8_t>(get_rn_val(1) & 0xFF);
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(static_cast<int32_t>(val)));
        break;
    }

    case ARM_INS_UXTH: {
        cpu.cs_arm_reg_write(get_rd(), get_rn_val(1) & 0xFFFF);
        break;
    }

    case ARM_INS_UXTB: {
        cpu.cs_arm_reg_write(get_rd(), get_rn_val(1) & 0xFF);
        break;
    }

    // ============================================================
    // Load/Store exclusive: LDREX, STREX (simplified)
    // ============================================================

    case ARM_INS_LDREX: {
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);
        uint32_t val = vmem.read32(addr);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), val);
        // In a full implementation, we would track the exclusive monitor
        break;
    }

    case ARM_INS_STREX: {
        // STREX Rd, Rt, [Rn] — Rd = 0 on success (always succeed in emulator)
        const cs_arm_op& status = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        const cs_arm_op& mem = arm.operands[2];
        uint32_t addr = cpu.effective_address(mem);
        uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(src.reg));
        vmem.write32(addr, val);
        cpu.cs_arm_reg_write(static_cast<arm_reg>(status.reg), 0);  // Success
        break;
    }

    // ============================================================
    // Data Memory Barrier / Synchronization
    // ============================================================

    case ARM_INS_DMB:
    case ARM_INS_DSB:
    case ARM_INS_ISB:
        // Memory barriers — no-op in single-core emulator
        break;

    // ============================================================
    // Conditional select (IT block handled by Capstone condition)
    // ============================================================

    case ARM_INS_IT:
        // IT (If-Then) block prefix — Capstone handles condition propagation
        // to subsequent instructions, so this is effectively a no-op for us
        break;

    // ============================================================
    // Coprocessor (stub): MRC, MCR
    // ============================================================

    case ARM_INS_MRC: {
        // Move from coprocessor — stub: return 0
        if (arm.op_count > 0 && arm.operands[0].type == ARM_OP_REG) {
            cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[0].reg), 0);
        }
        break;
    }

    case ARM_INS_MCR:
        // Move to coprocessor — stub: ignore
        break;

    // ============================================================
    // MOVW / MOVT (16-bit immediate moves)
    // ============================================================

    case ARM_INS_MOVW: {
        // Move 16-bit immediate to bottom half, zero top half
        uint32_t imm = static_cast<uint32_t>(arm.operands[1].imm) & 0xFFFF;
        cpu.cs_arm_reg_write(get_rd(), imm);
        break;
    }

    case ARM_INS_MOVT: {
        // Move 16-bit immediate to top half, preserve bottom half
        uint32_t rd_val = cpu.cs_arm_reg_value(get_rd());
        uint32_t imm = static_cast<uint32_t>(arm.operands[1].imm) & 0xFFFF;
        cpu.cs_arm_reg_write(get_rd(), (rd_val & 0xFFFF) | (imm << 16));
        break;
    }

    // ============================================================
    // Table Branch: TBB, TBH
    // ============================================================

    case ARM_INS_TBB: {
        // Table Branch Byte: PC += table[Rn + Rm] * 2
        uint32_t addr = cpu.effective_address(arm.operands[0]);
        uint8_t offset = 0;
        vmem.read(addr, &offset, 1);
        result.next_pc = static_cast<uint32_t>(insn->address) + insn->size + (offset * 2);
        break;
    }

    case ARM_INS_TBH: {
        // Table Branch Halfword: PC += table[Rn + Rm*2] * 2
        uint32_t addr = cpu.effective_address(arm.operands[0]);
        uint16_t offset = 0;
        vmem.read(addr, &offset, 2);
        result.next_pc = static_cast<uint32_t>(insn->address) + insn->size + (offset * 2);
        break;
    }

    // ============================================================
    // Saturating arithmetic (stubs): QADD, QSUB, USAT, SSAT
    // ============================================================

    case ARM_INS_USAT: {
        uint32_t sat_bit = static_cast<uint32_t>(arm.operands[1].imm);
        int32_t val = static_cast<int32_t>(get_rn_val(2));
        uint32_t max_val = (1u << sat_bit) - 1;
        if (val < 0) val = 0;
        if (static_cast<uint32_t>(val) > max_val) val = max_val;
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(val));
        break;
    }

    case ARM_INS_SSAT: {
        uint32_t sat_bit = static_cast<uint32_t>(arm.operands[1].imm);
        int32_t val = static_cast<int32_t>(get_rn_val(2));
        int32_t max_val = (1 << (sat_bit - 1)) - 1;
        int32_t min_val = -(1 << (sat_bit - 1));
        if (val > max_val) val = max_val;
        if (val < min_val) val = min_val;
        cpu.cs_arm_reg_write(get_rd(), static_cast<uint32_t>(val));
        break;
    }

    // ============================================================
    // Load/Store dual: LDRD, STRD
    // ============================================================

    case ARM_INS_LDRD: {
        // LDRD Rt, Rt2, [Rn, #offset]
        arm_reg rt  = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rt2 = static_cast<arm_reg>(arm.operands[1].reg);
        uint32_t addr = cpu.effective_address(arm.operands[2]);
        cpu.cs_arm_reg_write(rt,  vmem.read32(addr));
        cpu.cs_arm_reg_write(rt2, vmem.read32(addr + 4));
        if (insn->detail->writeback && arm.operands[2].mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(arm.operands[2].mem.base, addr);
        }
        break;
    }

    case ARM_INS_STRD: {
        arm_reg rt  = static_cast<arm_reg>(arm.operands[0].reg);
        arm_reg rt2 = static_cast<arm_reg>(arm.operands[1].reg);
        uint32_t addr = cpu.effective_address(arm.operands[2]);
        vmem.write32(addr,     cpu.cs_arm_reg_value(rt));
        vmem.write32(addr + 4, cpu.cs_arm_reg_value(rt2));
        if (insn->detail->writeback && arm.operands[2].mem.base != ARM_REG_INVALID) {
            cpu.cs_arm_reg_write(arm.operands[2].mem.base, addr);
        }
        break;
    }

    // ============================================================
    // Fallback: unhandled instruction
    // ============================================================

    default:
        // Unknown instruction — signal error
        result.ok = false;
        result.stop = StopReason::ERROR;
        break;

    } // switch(insn->id)

    return result;
}

// ============================================================
// VFP instruction dispatcher
// ============================================================

ARMBackend::ExecResult arm_dispatch_vfp(ARMBackend& cpu, const cs_insn* insn,
                                         VirtualMemory& vmem) {
    ARMBackend::ExecResult result;
    ARMState& st = cpu.state();
    const cs_arm& arm = insn->detail->arm;

    // Helper to get VFP single-precision register index from Capstone
    // Takes int because cs_arm_op::reg is int in Capstone v6
    auto s_index = [](int reg) -> int {
        if (reg >= ARM_REG_S0 && reg <= ARM_REG_S31) return reg - ARM_REG_S0;
        return -1;
    };

    // Helper to get VFP double-precision register index from Capstone
    auto d_index = [](int reg) -> int {
        if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) return reg - ARM_REG_D0;
        return -1;
    };

    switch (insn->id) {

    case ARM_INS_VLDR: {
        // VLDR Sd/Dd, [Rn, #offset]
        const cs_arm_op& dst = arm.operands[0];
        const cs_arm_op& src = arm.operands[1];
        uint32_t addr = cpu.effective_address(src);

        int si = s_index(dst.reg);
        int di = d_index(dst.reg);

        if (si >= 0) {
            // Single-precision load
            vmem.read(addr, &st.s[si], 4);
        } else if (di >= 0) {
            // Double-precision load
            vmem.read(addr, &st.d[di], 8);
        }
        break;
    }

    case ARM_INS_VSTR: {
        const cs_arm_op& src = arm.operands[0];
        const cs_arm_op& dst = arm.operands[1];
        uint32_t addr = cpu.effective_address(dst);

        int si = s_index(src.reg);
        int di = d_index(src.reg);

        if (si >= 0) {
            vmem.write(addr, &st.s[si], 4);
        } else if (di >= 0) {
            vmem.write(addr, &st.d[di], 8);
        }
        break;
    }

    case ARM_INS_VMOV: {
        // VMOV has many forms. Handle the common ones.
        if (arm.op_count == 2) {
            const cs_arm_op& dst = arm.operands[0];
            const cs_arm_op& src = arm.operands[1];

            int dst_si = s_index(dst.reg);
            int dst_di = d_index(dst.reg);
            int src_si = s_index(src.reg);
            int src_di = d_index(src.reg);

            if (dst_si >= 0 && src.type == ARM_OP_IMM) {
                // VMOV Sd, #imm
                float fval = static_cast<float>(src.imm);
                st.s[dst_si] = fval;
            } else if (dst_si >= 0 && src_si >= 0) {
                // VMOV Sd, Sm
                st.s[dst_si] = st.s[src_si];
            } else if (dst_di >= 0 && src_di >= 0) {
                // VMOV Dd, Dm
                st.d[dst_di] = st.d[src_di];
            } else if (dst_si >= 0 && src.type == ARM_OP_REG) {
                // VMOV Sn, Rt (core reg to single)
                uint32_t val = cpu.cs_arm_reg_value(static_cast<arm_reg>(src.reg));
                std::memcpy(&st.s[dst_si], &val, 4);
            } else if (dst.type == ARM_OP_REG && src_si >= 0) {
                // VMOV Rt, Sn (single to core reg)
                uint32_t val;
                std::memcpy(&val, &st.s[src_si], 4);
                cpu.cs_arm_reg_write(static_cast<arm_reg>(dst.reg), val);
            }
        }
        break;
    }

    case ARM_INS_VADD: {
        if (arm.op_count >= 3) {
            int di = d_index(arm.operands[0].reg);
            int si = s_index(arm.operands[0].reg);
            if (di >= 0) {
                int dn = d_index(arm.operands[1].reg);
                int dm = d_index(arm.operands[2].reg);
                if (dn >= 0 && dm >= 0) st.d[di] = st.d[dn] + st.d[dm];
            } else if (si >= 0) {
                int sn = s_index(arm.operands[1].reg);
                int sm = s_index(arm.operands[2].reg);
                if (sn >= 0 && sm >= 0) st.s[si] = st.s[sn] + st.s[sm];
            }
        }
        break;
    }

    case ARM_INS_VSUB: {
        if (arm.op_count >= 3) {
            int di = d_index(arm.operands[0].reg);
            int si = s_index(arm.operands[0].reg);
            if (di >= 0) {
                int dn = d_index(arm.operands[1].reg);
                int dm = d_index(arm.operands[2].reg);
                if (dn >= 0 && dm >= 0) st.d[di] = st.d[dn] - st.d[dm];
            } else if (si >= 0) {
                int sn = s_index(arm.operands[1].reg);
                int sm = s_index(arm.operands[2].reg);
                if (sn >= 0 && sm >= 0) st.s[si] = st.s[sn] - st.s[sm];
            }
        }
        break;
    }

    case ARM_INS_VMUL: {
        if (arm.op_count >= 3) {
            int di = d_index(arm.operands[0].reg);
            int si = s_index(arm.operands[0].reg);
            if (di >= 0) {
                int dn = d_index(arm.operands[1].reg);
                int dm = d_index(arm.operands[2].reg);
                if (dn >= 0 && dm >= 0) st.d[di] = st.d[dn] * st.d[dm];
            } else if (si >= 0) {
                int sn = s_index(arm.operands[1].reg);
                int sm = s_index(arm.operands[2].reg);
                if (sn >= 0 && sm >= 0) st.s[si] = st.s[sn] * st.s[sm];
            }
        }
        break;
    }

    case ARM_INS_VDIV: {
        if (arm.op_count >= 3) {
            int di = d_index(arm.operands[0].reg);
            int si = s_index(arm.operands[0].reg);
            if (di >= 0) {
                int dn = d_index(arm.operands[1].reg);
                int dm = d_index(arm.operands[2].reg);
                if (dn >= 0 && dm >= 0) st.d[di] = st.d[dn] / st.d[dm];
            } else if (si >= 0) {
                int sn = s_index(arm.operands[1].reg);
                int sm = s_index(arm.operands[2].reg);
                if (sn >= 0 && sm >= 0) st.s[si] = st.s[sn] / st.s[sm];
            }
        }
        break;
    }

    case ARM_INS_VCMP: {
        // VCMP Sd, Sm  or  VCMP Dd, Dm — sets FPSCR NZCV
        if (arm.op_count >= 2) {
            double a = 0.0, b = 0.0;
            int si = s_index(arm.operands[0].reg);
            int di = d_index(arm.operands[0].reg);

            if (si >= 0) {
                a = st.s[si];
                int sm = s_index(arm.operands[1].reg);
                if (sm >= 0) b = st.s[sm];
            } else if (di >= 0) {
                a = st.d[di];
                int dm = d_index(arm.operands[1].reg);
                if (dm >= 0) b = st.d[dm];
            }

            // Set FPSCR flags
            st.fpscr &= 0x0FFFFFFFu;
            if (std::isnan(a) || std::isnan(b)) {
                st.fpscr |= ARM_FLAG_C | ARM_FLAG_V;  // Unordered
            } else if (a == b) {
                st.fpscr |= ARM_FLAG_Z | ARM_FLAG_C;  // Equal
            } else if (a < b) {
                st.fpscr |= ARM_FLAG_N;               // Less than
            } else {
                st.fpscr |= ARM_FLAG_C;               // Greater than
            }
        } else if (arm.op_count == 1) {
            // VCMP Sd, #0.0
            double a = 0.0;
            int si = s_index(arm.operands[0].reg);
            int di = d_index(arm.operands[0].reg);
            if (si >= 0) a = st.s[si];
            else if (di >= 0) a = st.d[di];

            st.fpscr &= 0x0FFFFFFFu;
            if (std::isnan(a)) {
                st.fpscr |= ARM_FLAG_C | ARM_FLAG_V;
            } else if (a == 0.0) {
                st.fpscr |= ARM_FLAG_Z | ARM_FLAG_C;
            } else if (a < 0.0) {
                st.fpscr |= ARM_FLAG_N;
            } else {
                st.fpscr |= ARM_FLAG_C;
            }
        }
        break;
    }

    case ARM_INS_VCVT: {
        // Type conversion — simplified: handle common S<->D, int<->float
        if (arm.op_count >= 2) {
            int dst_si = s_index(arm.operands[0].reg);
            int dst_di = d_index(arm.operands[0].reg);
            int src_si = s_index(arm.operands[1].reg);
            int src_di = d_index(arm.operands[1].reg);

            if (dst_di >= 0 && src_si >= 0) {
                // F32 -> F64
                st.d[dst_di] = static_cast<double>(st.s[src_si]);
            } else if (dst_si >= 0 && src_di >= 0) {
                // F64 -> F32
                st.s[dst_si] = static_cast<float>(st.d[src_di]);
            } else if (dst_si >= 0 && src_si >= 0) {
                // Could be int -> float or float -> int
                // Check Capstone vector_data for specifics
                // Simplified: float -> int32 (truncate)
                int32_t ival = static_cast<int32_t>(st.s[src_si]);
                std::memcpy(&st.s[dst_si], &ival, 4);
            }
        }
        break;
    }

    case ARM_INS_VMRS: {
        // VMRS Rt, FPSCR — move FPSCR to core register (or APSR_nzcv)
        if (arm.op_count >= 1) {
            if (arm.operands[0].reg == ARM_REG_CPSR) {
                // VMRS APSR_nzcv, FPSCR — copy FPSCR flags to CPSR flags
                st.cpsr = (st.cpsr & 0x0FFFFFFFu) | (st.fpscr & 0xF0000000u);
            } else {
                cpu.cs_arm_reg_write(static_cast<arm_reg>(arm.operands[0].reg), st.fpscr);
            }
        }
        break;
    }

    case ARM_INS_VMSR: {
        // VMSR FPSCR, Rt
        if (arm.op_count >= 1) {
            st.fpscr = cpu.cs_arm_reg_value(static_cast<arm_reg>(arm.operands[0].reg));
        }
        break;
    }

    case ARM_INS_VNEG: {
        if (arm.op_count >= 2) {
            int dst_si = s_index(arm.operands[0].reg);
            int dst_di = d_index(arm.operands[0].reg);
            int src_si = s_index(arm.operands[1].reg);
            int src_di = d_index(arm.operands[1].reg);

            if (dst_si >= 0 && src_si >= 0) st.s[dst_si] = -st.s[src_si];
            else if (dst_di >= 0 && src_di >= 0) st.d[dst_di] = -st.d[src_di];
        }
        break;
    }

    case ARM_INS_VABS: {
        if (arm.op_count >= 2) {
            int dst_si = s_index(arm.operands[0].reg);
            int dst_di = d_index(arm.operands[0].reg);
            int src_si = s_index(arm.operands[1].reg);
            int src_di = d_index(arm.operands[1].reg);

            if (dst_si >= 0 && src_si >= 0) st.s[dst_si] = std::fabs(st.s[src_si]);
            else if (dst_di >= 0 && src_di >= 0) st.d[dst_di] = std::fabs(st.d[src_di]);
        }
        break;
    }

    case ARM_INS_VSQRT: {
        if (arm.op_count >= 2) {
            int dst_si = s_index(arm.operands[0].reg);
            int dst_di = d_index(arm.operands[0].reg);
            int src_si = s_index(arm.operands[1].reg);
            int src_di = d_index(arm.operands[1].reg);

            if (dst_si >= 0 && src_si >= 0) st.s[dst_si] = std::sqrt(st.s[src_si]);
            else if (dst_di >= 0 && src_di >= 0) st.d[dst_di] = std::sqrt(st.d[src_di]);
        }
        break;
    }

    default:
        result.ok = false;
        result.stop = StopReason::ERROR;
        break;
    }

    return result;
}

} // namespace vx
