/**
 * VXEngine x86-32 Instruction Semantics
 *
 * This file implements the core x86-32 instruction set handlers.
 * Each handler reads operands, computes the result, writes it back,
 * and updates EFLAGS as appropriate.
 *
 * Organized by category:
 *   - Data movement (MOV, MOVZX, MOVSX, LEA, XCHG, PUSH, POP, etc.)
 *   - Arithmetic (ADD, SUB, MUL, IMUL, DIV, IDIV, INC, DEC, NEG, ADC, SBB)
 *   - Logic (AND, OR, XOR, NOT, TEST, SHL, SHR, SAR, ROL, ROR, etc.)
 *   - Control flow (JMP, Jcc, CALL, RET, LOOP)
 *   - Comparison (CMP, TEST)
 *   - String (REP MOVS, REP STOS, REP CMPS, REP SCAS)
 *   - Stack (ENTER, LEAVE)
 *   - Flag manipulation (CLC, STC, CMC, CLD, STD, CLI, STI, LAHF, SAHF)
 *   - Bit manipulation (BSF, BSR, BT, BTS, BTR, BTC, BSWAP)
 *   - Misc (NOP, INT3, HLT, CPUID, RDTSC, XADD, CMPXCHG, CMOVcc, SETcc)
 */

#include "vxengine/cpu/x86/x86_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>

namespace vx {

// ============================================================
// Helper: operand size in bytes from Capstone operand
// ============================================================
static int op_size(const cs_x86_op& op) {
    return op.size;
}

// Helper: get operand size for instruction (from first non-imm operand, or default 4)
static int insn_op_size(const cs_insn* insn) {
    const cs_x86& x86 = insn->detail->x86;
    for (int i = 0; i < x86.op_count; i++) {
        if (x86.operands[i].type != X86_OP_IMM) {
            return x86.operands[i].size;
        }
    }
    return 4;
}

// Helper: mask for operand size
static uint32_t sz_mask(int size) {
    switch (size) {
        case 1: return 0xFF;
        case 2: return 0xFFFF;
        case 4: return 0xFFFFFFFF;
        default: return 0xFFFFFFFF;
    }
}

// Helper: sign bit for operand size
static uint32_t sz_sign(int size) {
    switch (size) {
        case 1: return 0x80;
        case 2: return 0x8000;
        case 4: return 0x80000000;
        default: return 0x80000000;
    }
}

// Helper: sign-extend from a given bit width to 32 bits
static uint32_t sign_extend(uint32_t val, int from_bits) {
    uint32_t sign = 1U << (from_bits - 1);
    return (val ^ sign) - sign;
}

// Helper: evaluate Jcc condition
static bool eval_condition(unsigned int cc, uint32_t eflags) {
    bool cf = (eflags & EFLAG_CF) != 0;
    bool zf = (eflags & EFLAG_ZF) != 0;
    bool sf = (eflags & EFLAG_SF) != 0;
    bool of = (eflags & EFLAG_OF) != 0;
    bool pf = (eflags & EFLAG_PF) != 0;

    switch (cc) {
        case X86_INS_JO:   return of;
        case X86_INS_JNO:  return !of;
        case X86_INS_JB:   return cf;          // JB/JNAE/JC
        case X86_INS_JAE:  return !cf;         // JAE/JNB/JNC
        case X86_INS_JE:   return zf;          // JE/JZ
        case X86_INS_JNE:  return !zf;         // JNE/JNZ
        case X86_INS_JBE:  return cf || zf;    // JBE/JNA
        case X86_INS_JA:   return !cf && !zf;  // JA/JNBE
        case X86_INS_JS:   return sf;
        case X86_INS_JNS:  return !sf;
        case X86_INS_JP:   return pf;          // JP/JPE
        case X86_INS_JNP:  return !pf;         // JNP/JPO
        case X86_INS_JL:   return sf != of;    // JL/JNGE
        case X86_INS_JGE:  return sf == of;    // JGE/JNL
        case X86_INS_JLE:  return zf || (sf != of);  // JLE/JNG
        case X86_INS_JG:   return !zf && (sf == of); // JG/JNLE
        case X86_INS_JCXZ: return false;       // handled separately
        case X86_INS_JECXZ:return false;       // handled separately
        default:           return false;
    }
}

// Helper: evaluate SETcc / CMOVcc condition (same logic, different insn IDs)
static bool eval_setcc_condition(unsigned int insn_id, uint32_t eflags) {
    bool cf = (eflags & EFLAG_CF) != 0;
    bool zf = (eflags & EFLAG_ZF) != 0;
    bool sf = (eflags & EFLAG_SF) != 0;
    bool of = (eflags & EFLAG_OF) != 0;
    bool pf = (eflags & EFLAG_PF) != 0;

    switch (insn_id) {
        case X86_INS_SETO:  case X86_INS_CMOVO:   return of;
        case X86_INS_SETNO: case X86_INS_CMOVNO:  return !of;
        case X86_INS_SETB:  case X86_INS_CMOVB:   return cf;
        case X86_INS_SETAE: case X86_INS_CMOVAE:  return !cf;
        case X86_INS_SETE:  case X86_INS_CMOVE:   return zf;
        case X86_INS_SETNE: case X86_INS_CMOVNE:  return !zf;
        case X86_INS_SETBE: case X86_INS_CMOVBE:  return cf || zf;
        case X86_INS_SETA:  case X86_INS_CMOVA:   return !cf && !zf;
        case X86_INS_SETS:  case X86_INS_CMOVS:   return sf;
        case X86_INS_SETNS: case X86_INS_CMOVNS:  return !sf;
        case X86_INS_SETP:  case X86_INS_CMOVP:   return pf;
        case X86_INS_SETNP: case X86_INS_CMOVNP:  return !pf;
        case X86_INS_SETL:  case X86_INS_CMOVL:   return sf != of;
        case X86_INS_SETGE: case X86_INS_CMOVGE:  return sf == of;
        case X86_INS_SETLE: case X86_INS_CMOVLE:  return zf || (sf != of);
        case X86_INS_SETG:  case X86_INS_CMOVG:   return !zf && (sf == of);
        default: return false;
    }
}

// ============================================================
// Main dispatch: x86_dispatch_insn
// ============================================================

X86Backend::ExecResult x86_dispatch_insn(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem) {
    X86Backend::ExecResult res;
    res.ok = true;
    res.stop = StopReason::STEP;
    res.next_pc = 0;  // 0 = advance by insn size (default)

    X86State& st = cpu.state_;
    const cs_x86& x86 = insn->detail->x86;
    const cs_x86_op* ops = x86.operands;
    int nops = x86.op_count;

    // Shorthand for reading/writing operands
    auto read_op = [&](int idx, int size) -> uint32_t {
        return cpu.read_operand(ops[idx], size);
    };
    auto write_op = [&](int idx, uint32_t val, int size) {
        cpu.write_operand(ops[idx], val, size);
    };
    auto ea = [&](int idx) -> uint32_t {
        return cpu.effective_address(ops[idx]);
    };

    switch (insn->id) {

    // ================================================================
    // DATA MOVEMENT
    // ================================================================

    case X86_INS_MOV: {
        int sz = op_size(ops[0]);
        uint32_t val = read_op(1, op_size(ops[1]));
        write_op(0, val, sz);
        break;
    }

    case X86_INS_MOVZX: {
        int src_sz = op_size(ops[1]);
        int dst_sz = op_size(ops[0]);
        uint32_t val = read_op(1, src_sz) & sz_mask(src_sz);
        write_op(0, val, dst_sz);
        break;
    }

    case X86_INS_MOVSX:
    case X86_INS_MOVSXD: {
        int src_sz = op_size(ops[1]);
        int dst_sz = op_size(ops[0]);
        uint32_t val = read_op(1, src_sz);
        val = sign_extend(val & sz_mask(src_sz), src_sz * 8);
        write_op(0, val, dst_sz);
        break;
    }

    case X86_INS_LEA: {
        // LEA loads the effective address itself, not the value at that address
        uint32_t addr = ea(1);
        write_op(0, addr, op_size(ops[0]));
        break;
    }

    case X86_INS_XCHG: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, sz);
        write_op(0, b, sz);
        write_op(1, a, sz);
        break;
    }

    case X86_INS_PUSH: {
        if (nops == 1) {
            int sz = op_size(ops[0]);
            uint32_t val = read_op(0, sz);
            // PUSH always pushes 32-bit in 32-bit mode (sign-extended if needed)
            if (sz == 2) {
                st.esp -= 2;
                vmem.write(st.esp, &val, 2);
            } else {
                cpu.push32(val);
            }
        }
        break;
    }

    case X86_INS_POP: {
        if (nops == 1) {
            int sz = op_size(ops[0]);
            if (sz == 2) {
                uint16_t val = 0;
                vmem.read(st.esp, &val, 2);
                st.esp += 2;
                write_op(0, val, 2);
            } else {
                uint32_t val = cpu.pop32();
                write_op(0, val, sz);
            }
        }
        break;
    }

    case X86_INS_PUSHAD: {
        // Push EAX, ECX, EDX, EBX, original ESP, EBP, ESI, EDI
        uint32_t old_esp = st.esp;
        cpu.push32(st.eax);
        cpu.push32(st.ecx);
        cpu.push32(st.edx);
        cpu.push32(st.ebx);
        cpu.push32(old_esp);
        cpu.push32(st.ebp);
        cpu.push32(st.esi);
        cpu.push32(st.edi);
        break;
    }

    case X86_INS_POPAD: {
        // Pop EDI, ESI, EBP, skip ESP, EBX, EDX, ECX, EAX
        st.edi = cpu.pop32();
        st.esi = cpu.pop32();
        st.ebp = cpu.pop32();
        cpu.pop32();  // Skip ESP
        st.ebx = cpu.pop32();
        st.edx = cpu.pop32();
        st.ecx = cpu.pop32();
        st.eax = cpu.pop32();
        break;
    }

    case X86_INS_PUSHFD: {
        cpu.push32(st.eflags);
        break;
    }

    case X86_INS_POPFD: {
        st.eflags = cpu.pop32();
        // Preserve reserved bit 1
        st.eflags |= 0x2;
        break;
    }

    // ================================================================
    // ARITHMETIC
    // ================================================================

    case X86_INS_ADD: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        // Sign-extend immediate if needed
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a + b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_add(a, b, result, sz);
        break;
    }

    case X86_INS_ADC: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t carry = (st.eflags & EFLAG_CF) ? 1 : 0;
        uint64_t full = static_cast<uint64_t>(a & sz_mask(sz)) + (b & sz_mask(sz)) + carry;
        uint32_t result = static_cast<uint32_t>(full) & sz_mask(sz);
        write_op(0, result, sz);
        // For ADC, carry flag considers the carry input too
        cpu.update_flags_add(a, b + carry, result, sz);
        // Fix CF for the full 3-operand add
        bool cf = (full >> (sz * 8)) != 0;
        st.eflags = cf ? (st.eflags | EFLAG_CF) : (st.eflags & ~EFLAG_CF);
        break;
    }

    case X86_INS_SUB: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a - b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(a, b, result, sz);
        break;
    }

    case X86_INS_SBB: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t borrow = (st.eflags & EFLAG_CF) ? 1 : 0;
        uint64_t sub_val = static_cast<uint64_t>(b & sz_mask(sz)) + borrow;
        uint32_t result = static_cast<uint32_t>((a & sz_mask(sz)) - sub_val) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(a, static_cast<uint32_t>(sub_val), result, sz);
        break;
    }

    case X86_INS_INC: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t result = (a + 1) & sz_mask(sz);
        write_op(0, result, sz);
        // INC doesn't affect CF
        uint32_t saved_cf = st.eflags & EFLAG_CF;
        cpu.update_flags_add(a, 1, result, sz);
        st.eflags = (st.eflags & ~EFLAG_CF) | saved_cf;
        break;
    }

    case X86_INS_DEC: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t result = (a - 1) & sz_mask(sz);
        write_op(0, result, sz);
        // DEC doesn't affect CF
        uint32_t saved_cf = st.eflags & EFLAG_CF;
        cpu.update_flags_sub(a, 1, result, sz);
        st.eflags = (st.eflags & ~EFLAG_CF) | saved_cf;
        break;
    }

    case X86_INS_NEG: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t result = (0 - a) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(0, a, result, sz);
        // CF = 1 if operand was non-zero
        if (a != 0) st.eflags |= EFLAG_CF;
        else st.eflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_MUL: {
        // Unsigned multiply: AL/AX/EAX * operand => AX/DX:AX/EDX:EAX
        int sz = op_size(ops[0]);
        uint32_t src = read_op(0, sz);
        switch (sz) {
            case 1: {
                uint16_t result = static_cast<uint16_t>(st.eax & 0xFF) * static_cast<uint16_t>(src & 0xFF);
                st.eax = (st.eax & 0xFFFF0000) | result;
                bool overflow = (result >> 8) != 0;
                if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
            case 2: {
                uint32_t result = static_cast<uint32_t>(st.eax & 0xFFFF) * static_cast<uint32_t>(src & 0xFFFF);
                st.eax = (st.eax & 0xFFFF0000) | (result & 0xFFFF);
                st.edx = (st.edx & 0xFFFF0000) | (result >> 16);
                bool overflow = (result >> 16) != 0;
                if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
            case 4: {
                uint64_t result = static_cast<uint64_t>(st.eax) * static_cast<uint64_t>(src);
                st.eax = static_cast<uint32_t>(result);
                st.edx = static_cast<uint32_t>(result >> 32);
                bool overflow = st.edx != 0;
                if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
        }
        break;
    }

    case X86_INS_IMUL: {
        // IMUL has 1, 2, or 3 operand forms
        if (nops == 1) {
            // One-operand form: signed multiply like MUL but signed
            int sz = op_size(ops[0]);
            int32_t src = static_cast<int32_t>(sign_extend(read_op(0, sz), sz * 8));
            switch (sz) {
                case 1: {
                    int16_t result = static_cast<int16_t>(static_cast<int8_t>(st.eax & 0xFF)) * static_cast<int16_t>(static_cast<int8_t>(src));
                    st.eax = (st.eax & 0xFFFF0000) | static_cast<uint16_t>(result);
                    bool overflow = (result != static_cast<int8_t>(result & 0xFF));
                    if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                    else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
                case 2: {
                    int32_t result = static_cast<int32_t>(static_cast<int16_t>(st.eax & 0xFFFF)) * static_cast<int32_t>(static_cast<int16_t>(src));
                    st.eax = (st.eax & 0xFFFF0000) | (static_cast<uint32_t>(result) & 0xFFFF);
                    st.edx = (st.edx & 0xFFFF0000) | ((static_cast<uint32_t>(result) >> 16) & 0xFFFF);
                    bool overflow = (result != static_cast<int16_t>(result & 0xFFFF));
                    if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                    else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
                case 4: {
                    int64_t result = static_cast<int64_t>(static_cast<int32_t>(st.eax)) * static_cast<int64_t>(src);
                    st.eax = static_cast<uint32_t>(result);
                    st.edx = static_cast<uint32_t>(static_cast<uint64_t>(result) >> 32);
                    bool overflow = (result != static_cast<int32_t>(st.eax));
                    if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
                    else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
            }
        } else if (nops == 2) {
            // Two-operand: dst = dst * src (truncated to operand size)
            int sz = op_size(ops[0]);
            int32_t a = static_cast<int32_t>(sign_extend(read_op(0, sz), sz * 8));
            int32_t b = static_cast<int32_t>(sign_extend(read_op(1, op_size(ops[1])), op_size(ops[1]) * 8));
            int64_t result = static_cast<int64_t>(a) * static_cast<int64_t>(b);
            uint32_t trunc = static_cast<uint32_t>(result) & sz_mask(sz);
            write_op(0, trunc, sz);
            bool overflow = (result != static_cast<int32_t>(sign_extend(trunc, sz * 8)));
            if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
            else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
        } else if (nops == 3) {
            // Three-operand: dst = src1 * imm
            int sz = op_size(ops[0]);
            int32_t a = static_cast<int32_t>(sign_extend(read_op(1, op_size(ops[1])), op_size(ops[1]) * 8));
            int32_t b = static_cast<int32_t>(sign_extend(read_op(2, op_size(ops[2])), op_size(ops[2]) * 8));
            int64_t result = static_cast<int64_t>(a) * static_cast<int64_t>(b);
            uint32_t trunc = static_cast<uint32_t>(result) & sz_mask(sz);
            write_op(0, trunc, sz);
            bool overflow = (result != static_cast<int32_t>(sign_extend(trunc, sz * 8)));
            if (overflow) st.eflags |= (EFLAG_CF | EFLAG_OF);
            else st.eflags &= ~(EFLAG_CF | EFLAG_OF);
        }
        break;
    }

    case X86_INS_DIV: {
        // Unsigned divide
        int sz = op_size(ops[0]);
        uint32_t divisor = read_op(0, sz);
        if (divisor == 0) {
            res.ok = false;
            res.stop = StopReason::EXCEPTION;
            return res;
        }
        switch (sz) {
            case 1: {
                uint16_t dividend = static_cast<uint16_t>(st.eax & 0xFFFF);
                uint8_t quotient = static_cast<uint8_t>(dividend / divisor);
                uint8_t remainder = static_cast<uint8_t>(dividend % divisor);
                st.eax = (st.eax & 0xFFFF0000) | (static_cast<uint16_t>(remainder) << 8) | quotient;
                break;
            }
            case 2: {
                uint32_t dividend = (static_cast<uint32_t>(st.edx & 0xFFFF) << 16) | (st.eax & 0xFFFF);
                uint16_t quotient = static_cast<uint16_t>(dividend / (divisor & 0xFFFF));
                uint16_t remainder = static_cast<uint16_t>(dividend % (divisor & 0xFFFF));
                st.eax = (st.eax & 0xFFFF0000) | quotient;
                st.edx = (st.edx & 0xFFFF0000) | remainder;
                break;
            }
            case 4: {
                uint64_t dividend = (static_cast<uint64_t>(st.edx) << 32) | st.eax;
                uint32_t quotient = static_cast<uint32_t>(dividend / divisor);
                uint32_t remainder = static_cast<uint32_t>(dividend % divisor);
                st.eax = quotient;
                st.edx = remainder;
                break;
            }
        }
        break;
    }

    case X86_INS_IDIV: {
        // Signed divide
        int sz = op_size(ops[0]);
        int32_t divisor = static_cast<int32_t>(sign_extend(read_op(0, sz), sz * 8));
        if (divisor == 0) {
            res.ok = false;
            res.stop = StopReason::EXCEPTION;
            return res;
        }
        switch (sz) {
            case 1: {
                int16_t dividend = static_cast<int16_t>(st.eax & 0xFFFF);
                int8_t quotient = static_cast<int8_t>(dividend / static_cast<int8_t>(divisor));
                int8_t remainder = static_cast<int8_t>(dividend % static_cast<int8_t>(divisor));
                st.eax = (st.eax & 0xFFFF0000) | (static_cast<uint8_t>(remainder) << 8) | static_cast<uint8_t>(quotient);
                break;
            }
            case 2: {
                int32_t dividend = static_cast<int32_t>((static_cast<uint32_t>(st.edx & 0xFFFF) << 16) | (st.eax & 0xFFFF));
                int16_t quotient = static_cast<int16_t>(dividend / static_cast<int16_t>(divisor));
                int16_t remainder = static_cast<int16_t>(dividend % static_cast<int16_t>(divisor));
                st.eax = (st.eax & 0xFFFF0000) | static_cast<uint16_t>(quotient);
                st.edx = (st.edx & 0xFFFF0000) | static_cast<uint16_t>(remainder);
                break;
            }
            case 4: {
                int64_t dividend = static_cast<int64_t>((static_cast<uint64_t>(st.edx) << 32) | st.eax);
                int32_t quotient = static_cast<int32_t>(dividend / divisor);
                int32_t remainder = static_cast<int32_t>(dividend % divisor);
                st.eax = static_cast<uint32_t>(quotient);
                st.edx = static_cast<uint32_t>(remainder);
                break;
            }
        }
        break;
    }

    // ================================================================
    // LOGIC
    // ================================================================

    case X86_INS_AND: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a & b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_OR: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a | b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_XOR: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a ^ b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_NOT: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t result = (~a) & sz_mask(sz);
        write_op(0, result, sz);
        // NOT does not affect flags
        break;
    }

    case X86_INS_TEST: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        uint32_t result = (a & b) & sz_mask(sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_SHL:
    case X86_INS_SAL: {
        int sz = op_size(ops[0]);
        uint32_t val = read_op(0, sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        if (count == 0) break;

        uint32_t mask = sz_mask(sz);
        uint32_t result = (val << count) & mask;

        // CF = last bit shifted out
        bool cf = ((val << (count - 1)) & sz_sign(sz)) != 0;

        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        if (cf) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;

        // OF defined only for count=1: OF = MSB(result) XOR CF
        if (count == 1) {
            bool of = ((result & sz_sign(sz)) != 0) != cf;
            if (of) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_SHR: {
        int sz = op_size(ops[0]);
        uint32_t val = read_op(0, sz) & sz_mask(sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        if (count == 0) break;

        // CF = last bit shifted out
        bool cf = ((val >> (count - 1)) & 1) != 0;

        uint32_t result = (val >> count) & sz_mask(sz);

        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        if (cf) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;

        // OF defined only for count=1: OF = MSB of original operand
        if (count == 1) {
            bool of = (val & sz_sign(sz)) != 0;
            if (of) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_SAR: {
        int sz = op_size(ops[0]);
        int32_t val = static_cast<int32_t>(sign_extend(read_op(0, sz), sz * 8));
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        if (count == 0) break;

        bool cf = ((val >> (count - 1)) & 1) != 0;
        int32_t result = val >> count;
        uint32_t uresult = static_cast<uint32_t>(result) & sz_mask(sz);

        write_op(0, uresult, sz);
        cpu.update_flags_logic(uresult, sz);
        if (cf) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;

        // OF=0 for count=1 (sign doesn't change)
        if (count == 1) st.eflags &= ~EFLAG_OF;
        break;
    }

    case X86_INS_ROL: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t val = read_op(0, sz) & sz_mask(sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        if (count == 0) break;
        count %= bits;
        if (count == 0) { count = bits; } // full rotate, but effectively same

        uint32_t result = ((val << count) | (val >> (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);

        // CF = LSB of result
        if (result & 1) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        // OF defined only for count=1: OF = MSB(result) XOR CF
        if (count == 1) {
            bool of = ((result & sz_sign(sz)) != 0) != ((result & 1) != 0);
            if (of) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_ROR: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t val = read_op(0, sz) & sz_mask(sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        if (count == 0) break;
        count %= bits;
        if (count == 0) { count = bits; }

        uint32_t result = ((val >> count) | (val << (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);

        // CF = MSB of result
        if (result & sz_sign(sz)) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        // OF defined only for count=1: OF = MSB(result) XOR second-MSB(result)
        if (count == 1) {
            bool b1 = (result & sz_sign(sz)) != 0;
            bool b2 = (result & (sz_sign(sz) >> 1)) != 0;
            if (b1 != b2) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_RCL: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t val = read_op(0, sz) & sz_mask(sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        count %= (bits + 1);
        if (count == 0) break;

        bool cf = (st.eflags & EFLAG_CF) != 0;
        for (uint32_t i = 0; i < count; i++) {
            bool new_cf = (val & sz_sign(sz)) != 0;
            val = ((val << 1) | (cf ? 1 : 0)) & sz_mask(sz);
            cf = new_cf;
        }
        write_op(0, val, sz);
        if (cf) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        if (count == 1) {
            bool of = ((val & sz_sign(sz)) != 0) != cf;
            if (of) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_RCR: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t val = read_op(0, sz) & sz_mask(sz);
        uint32_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & 0x1F) : 1;
        count %= (bits + 1);
        if (count == 0) break;

        bool cf = (st.eflags & EFLAG_CF) != 0;
        // OF defined for count=1 before rotation
        if (count == 1) {
            bool of = ((val & sz_sign(sz)) != 0) != cf;
            if (of) st.eflags |= EFLAG_OF; else st.eflags &= ~EFLAG_OF;
        }
        for (uint32_t i = 0; i < count; i++) {
            bool new_cf = (val & 1) != 0;
            val = ((val >> 1) | (cf ? sz_sign(sz) : 0)) & sz_mask(sz);
            cf = new_cf;
        }
        write_op(0, val, sz);
        if (cf) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_SHLD: {
        // SHLD dst, src, count: shift dst left, filling with bits from src
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t dst = read_op(0, sz) & sz_mask(sz);
        uint32_t src = read_op(1, sz) & sz_mask(sz);
        uint32_t count = read_op(2, op_size(ops[2])) & 0x1F;
        if (count == 0) break;
        if (count > static_cast<uint32_t>(bits)) {
            // Undefined, but we handle it
            break;
        }
        uint32_t result = ((dst << count) | (src >> (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);
        // CF = last bit shifted out of dst
        bool cf_val = ((dst << (count - 1)) & sz_sign(sz)) != 0;
        cpu.update_flags_logic(result, sz);
        if (cf_val) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_SHRD: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint32_t dst = read_op(0, sz) & sz_mask(sz);
        uint32_t src = read_op(1, sz) & sz_mask(sz);
        uint32_t count = read_op(2, op_size(ops[2])) & 0x1F;
        if (count == 0) break;
        if (count > static_cast<uint32_t>(bits)) break;

        uint32_t result = ((dst >> count) | (src << (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);
        bool cf_val = ((dst >> (count - 1)) & 1) != 0;
        cpu.update_flags_logic(result, sz);
        if (cf_val) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        break;
    }

    // ================================================================
    // COMPARISON
    // ================================================================

    case X86_INS_CMP: {
        int sz = op_size(ops[0]);
        uint32_t a = read_op(0, sz);
        uint32_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint32_t result = (a - b) & sz_mask(sz);
        cpu.update_flags_sub(a, b, result, sz);
        break;
    }

    // ================================================================
    // CONTROL FLOW
    // ================================================================

    case X86_INS_JMP: {
        uint32_t target;
        if (ops[0].type == X86_OP_IMM) {
            target = static_cast<uint32_t>(ops[0].imm);
        } else {
            target = read_op(0, op_size(ops[0]));
        }
        res.next_pc = target;
        break;
    }

    // All conditional jumps
    case X86_INS_JO: case X86_INS_JNO:
    case X86_INS_JB: case X86_INS_JAE:
    case X86_INS_JE: case X86_INS_JNE:
    case X86_INS_JBE: case X86_INS_JA:
    case X86_INS_JS: case X86_INS_JNS:
    case X86_INS_JP: case X86_INS_JNP:
    case X86_INS_JL: case X86_INS_JGE:
    case X86_INS_JLE: case X86_INS_JG: {
        if (eval_condition(insn->id, st.eflags)) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        // else: fall through (next_pc = 0 => advance by insn size)
        break;
    }

    case X86_INS_JCXZ: {
        if ((st.ecx & 0xFFFF) == 0) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_JECXZ: {
        if (st.ecx == 0) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_CALL: {
        uint32_t ret_addr = static_cast<uint32_t>(insn->address) + insn->size;
        cpu.push32(ret_addr);

        uint32_t target;
        if (ops[0].type == X86_OP_IMM) {
            target = static_cast<uint32_t>(ops[0].imm);
        } else {
            target = read_op(0, op_size(ops[0]));
        }

        // Check if target is a sentinel address (IAT stub)
        if (target >= SENTINEL_BASE && target < SENTINEL_BASE + 0x10000) {
            res.stop = StopReason::SENTINEL_HIT;
            res.next_pc = target;
            return res;
        }

        res.next_pc = target;
        break;
    }

    case X86_INS_RET:
    case X86_INS_RETF: {
        uint32_t ret_addr = cpu.pop32();
        // Check for stack cleanup (RET imm16)
        if (nops > 0 && ops[0].type == X86_OP_IMM) {
            st.esp += static_cast<uint32_t>(ops[0].imm);
        }
        res.next_pc = ret_addr;
        break;
    }

    case X86_INS_LOOP: {
        st.ecx--;
        if (st.ecx != 0) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_LOOPE: {
        st.ecx--;
        if (st.ecx != 0 && (st.eflags & EFLAG_ZF)) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_LOOPNE: {
        st.ecx--;
        if (st.ecx != 0 && !(st.eflags & EFLAG_ZF)) {
            res.next_pc = static_cast<uint32_t>(ops[0].imm);
        }
        break;
    }

    // ================================================================
    // STRING INSTRUCTIONS (with REP/REPNE prefix support)
    // ================================================================

    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD: {
        int sz = (insn->id == X86_INS_MOVSB) ? 1 : (insn->id == X86_INS_MOVSW) ? 2 : 4;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int dir = (st.eflags & EFLAG_DF) ? -1 : 1;

        auto do_movs = [&]() {
            uint32_t src_addr = st.esi + cpu.segment_base(st.ds);
            uint32_t dst_addr = st.edi + cpu.segment_base(st.es);
            uint32_t val = 0;
            vmem.read(src_addr, &val, sz);
            vmem.write(dst_addr, &val, sz);
            st.esi += dir * sz;
            st.edi += dir * sz;
        };

        if (has_rep) {
            while (st.ecx != 0) {
                do_movs();
                st.ecx--;
            }
        } else {
            do_movs();
        }
        break;
    }

    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD: {
        int sz = (insn->id == X86_INS_STOSB) ? 1 : (insn->id == X86_INS_STOSW) ? 2 : 4;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int dir = (st.eflags & EFLAG_DF) ? -1 : 1;
        uint32_t val = st.eax & sz_mask(sz);

        auto do_stos = [&]() {
            uint32_t dst_addr = st.edi + cpu.segment_base(st.es);
            vmem.write(dst_addr, &val, sz);
            st.edi += dir * sz;
        };

        if (has_rep) {
            while (st.ecx != 0) {
                do_stos();
                st.ecx--;
            }
        } else {
            do_stos();
        }
        break;
    }

    case X86_INS_CMPSB:
    case X86_INS_CMPSW:
    case X86_INS_CMPSD: {
        int sz = (insn->id == X86_INS_CMPSB) ? 1 : (insn->id == X86_INS_CMPSW) ? 2 : 4;
        bool has_repe = (x86.prefix[0] == X86_PREFIX_REPE);
        bool has_repne = (x86.prefix[0] == X86_PREFIX_REPNE);
        int dir = (st.eflags & EFLAG_DF) ? -1 : 1;

        auto do_cmps = [&]() {
            uint32_t src_addr = st.esi + cpu.segment_base(st.ds);
            uint32_t dst_addr = st.edi + cpu.segment_base(st.es);
            uint32_t a = 0, b = 0;
            vmem.read(src_addr, &a, sz);
            vmem.read(dst_addr, &b, sz);
            uint32_t result = (a - b) & sz_mask(sz);
            cpu.update_flags_sub(a, b, result, sz);
            st.esi += dir * sz;
            st.edi += dir * sz;
        };

        if (has_repe) {
            while (st.ecx != 0) {
                do_cmps();
                st.ecx--;
                if (!(st.eflags & EFLAG_ZF)) break;  // Stop if not equal
            }
        } else if (has_repne) {
            while (st.ecx != 0) {
                do_cmps();
                st.ecx--;
                if (st.eflags & EFLAG_ZF) break;  // Stop if equal
            }
        } else {
            do_cmps();
        }
        break;
    }

    case X86_INS_SCASB:
    case X86_INS_SCASW:
    case X86_INS_SCASD: {
        int sz = (insn->id == X86_INS_SCASB) ? 1 : (insn->id == X86_INS_SCASW) ? 2 : 4;
        bool has_repe = (x86.prefix[0] == X86_PREFIX_REPE);
        bool has_repne = (x86.prefix[0] == X86_PREFIX_REPNE);
        int dir = (st.eflags & EFLAG_DF) ? -1 : 1;
        uint32_t a = st.eax & sz_mask(sz);

        auto do_scas = [&]() {
            uint32_t dst_addr = st.edi + cpu.segment_base(st.es);
            uint32_t b = 0;
            vmem.read(dst_addr, &b, sz);
            uint32_t result = (a - b) & sz_mask(sz);
            cpu.update_flags_sub(a, b, result, sz);
            st.edi += dir * sz;
        };

        if (has_repe) {
            while (st.ecx != 0) {
                do_scas();
                st.ecx--;
                if (!(st.eflags & EFLAG_ZF)) break;
            }
        } else if (has_repne) {
            while (st.ecx != 0) {
                do_scas();
                st.ecx--;
                if (st.eflags & EFLAG_ZF) break;
            }
        } else {
            do_scas();
        }
        break;
    }

    case X86_INS_LODSB:
    case X86_INS_LODSW:
    case X86_INS_LODSD: {
        int sz = (insn->id == X86_INS_LODSB) ? 1 : (insn->id == X86_INS_LODSW) ? 2 : 4;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int dir = (st.eflags & EFLAG_DF) ? -1 : 1;

        auto do_lods = [&]() {
            uint32_t src_addr = st.esi + cpu.segment_base(st.ds);
            uint32_t val = 0;
            vmem.read(src_addr, &val, sz);
            if (sz == 1) st.eax = (st.eax & 0xFFFFFF00) | (val & 0xFF);
            else if (sz == 2) st.eax = (st.eax & 0xFFFF0000) | (val & 0xFFFF);
            else st.eax = val;
            st.esi += dir * sz;
        };

        if (has_rep) {
            while (st.ecx != 0) {
                do_lods();
                st.ecx--;
            }
        } else {
            do_lods();
        }
        break;
    }

    // ================================================================
    // STACK: ENTER / LEAVE
    // ================================================================

    case X86_INS_ENTER: {
        uint16_t alloc_size = static_cast<uint16_t>(ops[0].imm);
        uint8_t nesting = static_cast<uint8_t>(ops[1].imm);
        cpu.push32(st.ebp);
        uint32_t frame_temp = st.esp;

        if (nesting > 0) {
            for (uint8_t i = 1; i < nesting; i++) {
                st.ebp -= 4;
                cpu.push32(vmem.read32(st.ebp));
            }
            cpu.push32(frame_temp);
        }

        st.ebp = frame_temp;
        st.esp -= alloc_size;
        break;
    }

    case X86_INS_LEAVE: {
        st.esp = st.ebp;
        st.ebp = cpu.pop32();
        break;
    }

    // ================================================================
    // FLAG MANIPULATION
    // ================================================================

    case X86_INS_CLC: st.eflags &= ~EFLAG_CF; break;
    case X86_INS_STC: st.eflags |= EFLAG_CF; break;
    case X86_INS_CMC: st.eflags ^= EFLAG_CF; break;
    case X86_INS_CLD: st.eflags &= ~EFLAG_DF; break;
    case X86_INS_STD: st.eflags |= EFLAG_DF; break;
    case X86_INS_CLI: st.eflags &= ~EFLAG_IF; break;
    case X86_INS_STI: st.eflags |= EFLAG_IF; break;

    case X86_INS_LAHF: {
        // AH = SF:ZF:0:AF:0:PF:1:CF (bits 7,6,5,4,3,2,1,0 of low byte of eflags)
        uint8_t ah = static_cast<uint8_t>(st.eflags & 0xFF);
        st.eax = (st.eax & 0xFFFF00FF) | (static_cast<uint32_t>(ah) << 8);
        break;
    }

    case X86_INS_SAHF: {
        // Load SF:ZF:0:AF:0:PF:1:CF from AH
        uint8_t ah = static_cast<uint8_t>((st.eax >> 8) & 0xFF);
        st.eflags = (st.eflags & 0xFFFFFF00) | ah;
        // Ensure reserved bit 1 is set
        st.eflags |= 0x2;
        break;
    }

    // ================================================================
    // BIT MANIPULATION
    // ================================================================

    case X86_INS_BSF: {
        int sz = op_size(ops[0]);
        uint32_t src = read_op(1, sz) & sz_mask(sz);
        if (src == 0) {
            st.eflags |= EFLAG_ZF;
        } else {
            st.eflags &= ~EFLAG_ZF;
            uint32_t idx = 0;
            while (!(src & (1U << idx))) idx++;
            write_op(0, idx, sz);
        }
        break;
    }

    case X86_INS_BSR: {
        int sz = op_size(ops[0]);
        uint32_t src = read_op(1, sz) & sz_mask(sz);
        if (src == 0) {
            st.eflags |= EFLAG_ZF;
        } else {
            st.eflags &= ~EFLAG_ZF;
            int bits = sz * 8;
            uint32_t idx = bits - 1;
            while (!(src & (1U << idx))) idx--;
            write_op(0, idx, sz);
        }
        break;
    }

    case X86_INS_BT: {
        int sz = op_size(ops[0]);
        uint32_t base = read_op(0, sz);
        uint32_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_BTS: {
        int sz = op_size(ops[0]);
        uint32_t base = read_op(0, sz);
        uint32_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        write_op(0, base | (1U << offset), sz);
        break;
    }

    case X86_INS_BTR: {
        int sz = op_size(ops[0]);
        uint32_t base = read_op(0, sz);
        uint32_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        write_op(0, base & ~(1U << offset), sz);
        break;
    }

    case X86_INS_BTC: {
        int sz = op_size(ops[0]);
        uint32_t base = read_op(0, sz);
        uint32_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.eflags |= EFLAG_CF; else st.eflags &= ~EFLAG_CF;
        write_op(0, base ^ (1U << offset), sz);
        break;
    }

    case X86_INS_BSWAP: {
        uint32_t val = read_op(0, 4);
        val = ((val & 0xFF000000) >> 24) |
              ((val & 0x00FF0000) >> 8) |
              ((val & 0x0000FF00) << 8) |
              ((val & 0x000000FF) << 24);
        write_op(0, val, 4);
        break;
    }

    // ================================================================
    // SIGN EXTENSION
    // ================================================================

    case X86_INS_CBW: {
        // AL -> AX (sign extend)
        int8_t al = static_cast<int8_t>(st.eax & 0xFF);
        st.eax = (st.eax & 0xFFFF0000) | static_cast<uint16_t>(static_cast<int16_t>(al));
        break;
    }

    case X86_INS_CWDE: {
        // AX -> EAX (sign extend)
        int16_t ax = static_cast<int16_t>(st.eax & 0xFFFF);
        st.eax = static_cast<uint32_t>(static_cast<int32_t>(ax));
        break;
    }

    case X86_INS_CWD: {
        // AX -> DX:AX (sign extend)
        int16_t ax = static_cast<int16_t>(st.eax & 0xFFFF);
        int32_t ext = static_cast<int32_t>(ax);
        st.eax = (st.eax & 0xFFFF0000) | (static_cast<uint32_t>(ext) & 0xFFFF);
        st.edx = (st.edx & 0xFFFF0000) | ((static_cast<uint32_t>(ext) >> 16) & 0xFFFF);
        break;
    }

    case X86_INS_CDQ: {
        // EAX -> EDX:EAX (sign extend)
        st.edx = (static_cast<int32_t>(st.eax) < 0) ? 0xFFFFFFFF : 0;
        break;
    }

    case X86_INS_CDQE: {
        // In 32-bit mode, same as CWDE
        int16_t ax = static_cast<int16_t>(st.eax & 0xFFFF);
        st.eax = static_cast<uint32_t>(static_cast<int32_t>(ax));
        break;
    }

    // ================================================================
    // CONDITIONAL MOVE (CMOVcc)
    // ================================================================

    case X86_INS_CMOVO:  case X86_INS_CMOVNO:
    case X86_INS_CMOVB:  case X86_INS_CMOVAE:
    case X86_INS_CMOVE:  case X86_INS_CMOVNE:
    case X86_INS_CMOVBE: case X86_INS_CMOVA:
    case X86_INS_CMOVS:  case X86_INS_CMOVNS:
    case X86_INS_CMOVP:  case X86_INS_CMOVNP:
    case X86_INS_CMOVL:  case X86_INS_CMOVGE:
    case X86_INS_CMOVLE: case X86_INS_CMOVG: {
        if (eval_setcc_condition(insn->id, st.eflags)) {
            int sz = op_size(ops[0]);
            uint32_t val = read_op(1, sz);
            write_op(0, val, sz);
        }
        break;
    }

    // ================================================================
    // SET BYTE ON CONDITION (SETcc)
    // ================================================================

    case X86_INS_SETO:  case X86_INS_SETNO:
    case X86_INS_SETB:  case X86_INS_SETAE:
    case X86_INS_SETE:  case X86_INS_SETNE:
    case X86_INS_SETBE: case X86_INS_SETA:
    case X86_INS_SETS:  case X86_INS_SETNS:
    case X86_INS_SETP:  case X86_INS_SETNP:
    case X86_INS_SETL:  case X86_INS_SETGE:
    case X86_INS_SETLE: case X86_INS_SETG: {
        uint32_t val = eval_setcc_condition(insn->id, st.eflags) ? 1 : 0;
        write_op(0, val, 1);
        break;
    }

    // ================================================================
    // EXCHANGE AND ADD / COMPARE AND EXCHANGE
    // ================================================================

    case X86_INS_XADD: {
        int sz = op_size(ops[0]);
        uint32_t dst_val = read_op(0, sz);
        uint32_t src_val = read_op(1, sz);
        uint32_t result = (dst_val + src_val) & sz_mask(sz);
        write_op(0, result, sz);  // dst = dst + src
        write_op(1, dst_val, sz);  // src = old dst
        cpu.update_flags_add(dst_val, src_val, result, sz);
        break;
    }

    case X86_INS_CMPXCHG: {
        int sz = op_size(ops[0]);
        uint32_t dst_val = read_op(0, sz);
        uint32_t acc;
        if (sz == 1) acc = st.eax & 0xFF;
        else if (sz == 2) acc = st.eax & 0xFFFF;
        else acc = st.eax;

        uint32_t cmp_result = (acc - dst_val) & sz_mask(sz);
        cpu.update_flags_sub(acc, dst_val, cmp_result, sz);

        if (acc == dst_val) {
            // Equal: ZF=1, dst = src
            uint32_t src_val = read_op(1, sz);
            write_op(0, src_val, sz);
        } else {
            // Not equal: ZF=0, accumulator = dst
            if (sz == 1) st.eax = (st.eax & 0xFFFFFF00) | (dst_val & 0xFF);
            else if (sz == 2) st.eax = (st.eax & 0xFFFF0000) | (dst_val & 0xFFFF);
            else st.eax = dst_val;
        }
        break;
    }

    // ================================================================
    // MISC
    // ================================================================

    case X86_INS_NOP:
    case X86_INS_FNOP:
        break;

    case X86_INS_INT3: {
        // Check if this is a stealth breakpoint
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    case X86_INS_INT: {
        // Generic interrupt
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    case X86_INS_HLT: {
        res.stop = StopReason::HALT;
        return res;
    }

    case X86_INS_CPUID: {
        // Return fake CPUID info
        uint32_t leaf = st.eax;
        switch (leaf) {
            case 0:
                // Maximum CPUID leaf and vendor string
                st.eax = 0x0D;               // Max leaf
                st.ebx = 0x756E6547;         // "Genu"
                st.edx = 0x49656E69;         // "ineI"
                st.ecx = 0x6C65746E;         // "ntel"
                break;
            case 1:
                // Processor info and features
                st.eax = 0x000306C3;         // Family 6, Model 3C (Haswell)
                st.ebx = 0x00100800;
                st.ecx = 0x7FFAFBBF;         // SSE4.2, AES, etc.
                st.edx = 0xBFEBFBFF;         // SSE2, MMX, etc.
                break;
            default:
                st.eax = st.ebx = st.ecx = st.edx = 0;
                break;
        }
        break;
    }

    case X86_INS_RDTSC: {
        // Return a fake but incrementing timestamp
        static uint64_t fake_tsc = 0x100000000ULL;
        fake_tsc += 100;
        st.eax = static_cast<uint32_t>(fake_tsc);
        st.edx = static_cast<uint32_t>(fake_tsc >> 32);
        break;
    }

    // ================================================================
    // SEGMENT REGISTER OPERATIONS
    // ================================================================
    // Capstone may decode PUSH SS / POP SS / MOV seg, r / MOV r, seg
    // as regular MOV/PUSH/POP with segment register operands.
    // Those are already handled above since read_operand/write_operand
    // understand X86_OP_REG for segment registers.

    // ================================================================
    // DEFAULT: unhandled instruction
    // ================================================================

    default: {
        // Unknown instruction - signal error
        res.ok = false;
        res.stop = StopReason::ERROR;
        return res;
    }

    } // end switch

    return res;
}

} // namespace vx
