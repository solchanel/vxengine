/**
 * VXEngine x86-64 Instruction Semantics
 *
 * This file implements the x64 instruction set handlers.
 * Most x86 instructions work identically in 64-bit mode -- the key
 * differences handled here are:
 *
 *   - All operands go through 64-bit read_operand/write_operand which
 *     handle the zero-extension rule (32-bit writes zero-extend to 64)
 *   - RIP-relative addressing in effective_address
 *   - PUSH/POP are always 64-bit in long mode (no 32-bit push/pop)
 *   - MOVSXD (sign-extend 32 to 64)
 *   - CDQE (sign-extend EAX to RAX)
 *   - CQO (sign-extend RAX to RDX:RAX)
 *   - SYSCALL / SYSRET
 *   - 64-bit MUL/DIV/IMUL/IDIV
 *   - JRCXZ instead of JECXZ
 *   - String ops use RSI/RDI/RCX instead of ESI/EDI/ECX
 *   - PUSHFQ/POPFQ instead of PUSHFD/POPFD
 *   - No PUSHAD/POPAD in 64-bit mode
 *
 * Organized by category (same layout as x86_insns.cpp):
 *   - Data movement (MOV, MOVZX, MOVSX, MOVSXD, LEA, XCHG, PUSH, POP)
 *   - Arithmetic (ADD, SUB, MUL, IMUL, DIV, IDIV, INC, DEC, NEG, ADC, SBB)
 *   - Logic (AND, OR, XOR, NOT, TEST, SHL, SHR, SAR, ROL, ROR, etc.)
 *   - Control flow (JMP, Jcc, CALL, RET, LOOP)
 *   - Comparison (CMP, TEST)
 *   - String (REP MOVS, REP STOS, REP CMPS, REP SCAS)
 *   - Stack (ENTER, LEAVE)
 *   - Flag manipulation (CLC, STC, CMC, CLD, STD, CLI, STI, LAHF, SAHF)
 *   - Bit manipulation (BSF, BSR, BT, BTS, BTR, BTC, BSWAP)
 *   - Sign extension (CBW, CWDE, CDQE, CWD, CDQ, CQO)
 *   - Misc (NOP, INT3, HLT, CPUID, RDTSC, XADD, CMPXCHG, CMOVcc, SETcc)
 *   - x64-only (SYSCALL, SYSRET)
 */

#include "vxengine/cpu/x64/x64_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cassert>

// Portable 64x64->128 multiply helpers (works on all compilers/targets)
#if defined(_MSC_VER) && defined(_M_X64)
#include <intrin.h>
static inline void umul128(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) {
    lo = _umul128(a, b, &hi);
}
static inline void imul128(int64_t a, int64_t b, int64_t& hi, uint64_t& lo) {
    lo = static_cast<uint64_t>(_mul128(a, b, &hi));
}
#elif !defined(_MSC_VER)
// GCC/Clang with __uint128_t (defined in #else below)
#else
// MSVC 32-bit or other — software 64x64->128
static inline void umul128(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) {
    uint32_t a_lo = static_cast<uint32_t>(a), a_hi = static_cast<uint32_t>(a >> 32);
    uint32_t b_lo = static_cast<uint32_t>(b), b_hi = static_cast<uint32_t>(b >> 32);
    uint64_t p0 = static_cast<uint64_t>(a_lo) * b_lo;
    uint64_t p1 = static_cast<uint64_t>(a_lo) * b_hi;
    uint64_t p2 = static_cast<uint64_t>(a_hi) * b_lo;
    uint64_t p3 = static_cast<uint64_t>(a_hi) * b_hi;
    uint64_t mid = (p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF);
    lo = (p0 & 0xFFFFFFFF) | ((mid & 0xFFFFFFFF) << 32);
    hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
}
static inline void imul128(int64_t a, int64_t b, int64_t& hi, uint64_t& lo) {
    bool neg = (a < 0) != (b < 0);
    uint64_t ua = a < 0 ? static_cast<uint64_t>(-a) : static_cast<uint64_t>(a);
    uint64_t ub = b < 0 ? static_cast<uint64_t>(-b) : static_cast<uint64_t>(b);
    uint64_t uhi;
    umul128(ua, ub, uhi, lo);
    if (neg) { lo = ~lo + 1; uhi = ~uhi + (lo == 0 ? 1 : 0); }
    hi = static_cast<int64_t>(uhi);
}
#endif
// GCC/Clang path (has __uint128_t)
#if !defined(_MSC_VER)
static inline void umul128(uint64_t a, uint64_t b, uint64_t& hi, uint64_t& lo) {
    __uint128_t r = static_cast<__uint128_t>(a) * b;
    lo = static_cast<uint64_t>(r);
    hi = static_cast<uint64_t>(r >> 64);
}
static inline void imul128(int64_t a, int64_t b, int64_t& hi, uint64_t& lo) {
    __int128_t r = static_cast<__int128_t>(a) * b;
    lo = static_cast<uint64_t>(r);
    hi = static_cast<int64_t>(static_cast<__uint128_t>(r) >> 64);
}
#endif

namespace vx {

// ============================================================
// Helper: operand size in bytes from Capstone operand
// ============================================================
static int op_size(const cs_x86_op& op) {
    return op.size;
}

// Helper: mask for operand size (up to 64-bit)
static uint64_t sz_mask(int size) {
    switch (size) {
        case 1: return 0xFFULL;
        case 2: return 0xFFFFULL;
        case 4: return 0xFFFFFFFFULL;
        case 8: return 0xFFFFFFFFFFFFFFFFULL;
        default: return 0xFFFFFFFFULL;
    }
}

// Helper: sign bit for operand size
static uint64_t sz_sign(int size) {
    switch (size) {
        case 1: return 0x80ULL;
        case 2: return 0x8000ULL;
        case 4: return 0x80000000ULL;
        case 8: return 0x8000000000000000ULL;
        default: return 0x80000000ULL;
    }
}

// Helper: sign-extend from a given bit width to 64 bits
static uint64_t sign_extend(uint64_t val, int from_bits) {
    if (from_bits >= 64) return val;
    uint64_t sign = 1ULL << (from_bits - 1);
    val &= (1ULL << from_bits) - 1;
    return (val ^ sign) - sign;
}

// Helper: evaluate Jcc condition
static bool eval_condition(unsigned int cc, uint64_t rflags) {
    bool cf = (rflags & EFLAG_CF) != 0;
    bool zf = (rflags & EFLAG_ZF) != 0;
    bool sf = (rflags & EFLAG_SF) != 0;
    bool of = (rflags & EFLAG_OF) != 0;
    bool pf = (rflags & EFLAG_PF) != 0;

    switch (cc) {
        case X86_INS_JO:   return of;
        case X86_INS_JNO:  return !of;
        case X86_INS_JB:   return cf;
        case X86_INS_JAE:  return !cf;
        case X86_INS_JE:   return zf;
        case X86_INS_JNE:  return !zf;
        case X86_INS_JBE:  return cf || zf;
        case X86_INS_JA:   return !cf && !zf;
        case X86_INS_JS:   return sf;
        case X86_INS_JNS:  return !sf;
        case X86_INS_JP:   return pf;
        case X86_INS_JNP:  return !pf;
        case X86_INS_JL:   return sf != of;
        case X86_INS_JGE:  return sf == of;
        case X86_INS_JLE:  return zf || (sf != of);
        case X86_INS_JG:   return !zf && (sf == of);
        case X86_INS_JCXZ: return false;  // handled separately
        case X86_INS_JECXZ:return false;
        case X86_INS_JRCXZ:return false;
        default:           return false;
    }
}

// Helper: evaluate SETcc / CMOVcc condition
static bool eval_setcc_condition(unsigned int insn_id, uint64_t rflags) {
    bool cf = (rflags & EFLAG_CF) != 0;
    bool zf = (rflags & EFLAG_ZF) != 0;
    bool sf = (rflags & EFLAG_SF) != 0;
    bool of = (rflags & EFLAG_OF) != 0;
    bool pf = (rflags & EFLAG_PF) != 0;

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
// Main dispatch: x64_dispatch_insn
// ============================================================

X64Backend::ExecResult x64_dispatch_insn(X64Backend& cpu, const cs_insn* insn, VirtualMemory& vmem) {
    X64Backend::ExecResult res;
    res.ok = true;
    res.stop = StopReason::STEP;
    res.next_pc = 0;  // 0 = advance by insn size (default)

    X64State& st = cpu.state_;
    const cs_x86& x86 = insn->detail->x86;
    const cs_x86_op* ops = x86.operands;
    int nops = x86.op_count;

    // Instruction address and size (needed for RIP-relative addressing)
    uint64_t insn_addr = insn->address;
    uint8_t insn_size = insn->size;

    // Shorthand for reading/writing operands
    // read_op handles RIP-relative via effective_address with insn context
    auto read_op = [&](int idx, int size) -> uint64_t {
        const cs_x86_op& op = ops[idx];
        if (op.type == X86_OP_MEM) {
            uint64_t addr = cpu.effective_address(op, insn_addr, insn_size);
            uint64_t val = 0;
            vmem.read(addr, &val, size);
            return val;
        }
        return cpu.read_operand(op, size);
    };

    auto write_op = [&](int idx, uint64_t val, int size) {
        const cs_x86_op& op = ops[idx];
        if (op.type == X86_OP_MEM) {
            uint64_t addr = cpu.effective_address(op, insn_addr, insn_size);
            vmem.write(addr, &val, size);
        } else {
            cpu.write_operand(op, val, size);
        }
    };

    auto ea = [&](int idx) -> uint64_t {
        return cpu.effective_address(ops[idx], insn_addr, insn_size);
    };

    switch (insn->id) {

    // ================================================================
    // DATA MOVEMENT
    // ================================================================

    case X86_INS_MOV: {
        int sz = op_size(ops[0]);
        uint64_t val = read_op(1, op_size(ops[1]));
        write_op(0, val, sz);
        break;
    }

    case X86_INS_MOVZX: {
        int src_sz = op_size(ops[1]);
        int dst_sz = op_size(ops[0]);
        uint64_t val = read_op(1, src_sz) & sz_mask(src_sz);
        write_op(0, val, dst_sz);
        break;
    }

    case X86_INS_MOVSX: {
        int src_sz = op_size(ops[1]);
        int dst_sz = op_size(ops[0]);
        uint64_t val = read_op(1, src_sz);
        val = sign_extend(val & sz_mask(src_sz), src_sz * 8);
        write_op(0, val, dst_sz);
        break;
    }

    case X86_INS_MOVSXD: {
        // x64-specific: sign-extend 32-bit to 64-bit
        int src_sz = op_size(ops[1]);
        int dst_sz = op_size(ops[0]);
        uint64_t val = read_op(1, src_sz);
        val = sign_extend(val & sz_mask(src_sz), src_sz * 8);
        write_op(0, val, dst_sz);
        break;
    }

    case X86_INS_LEA: {
        // LEA loads the effective address itself, not the value at that address
        // In 64-bit mode, this supports RIP-relative addressing
        uint64_t addr = ea(1);
        write_op(0, addr, op_size(ops[0]));
        break;
    }

    case X86_INS_XCHG: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, sz);
        write_op(0, b, sz);
        write_op(1, a, sz);
        break;
    }

    case X86_INS_PUSH: {
        if (nops == 1) {
            int sz = op_size(ops[0]);
            uint64_t val = read_op(0, sz);
            // In 64-bit mode, PUSH is always 64-bit (sign-extended if imm)
            if (sz < 8 && ops[0].type == X86_OP_IMM) {
                val = sign_extend(val, sz * 8);
            }
            cpu.push64(val);
        }
        break;
    }

    case X86_INS_POP: {
        if (nops == 1) {
            // In 64-bit mode, POP is always 64-bit
            uint64_t val = cpu.pop64();
            write_op(0, val, 8);
        }
        break;
    }

    // No PUSHAD/POPAD in 64-bit mode

    case X86_INS_PUSHFQ: {
        cpu.push64(st.rflags);
        break;
    }

    case X86_INS_POPFQ: {
        st.rflags = cpu.pop64();
        // Preserve reserved bit 1
        st.rflags |= 0x2;
        break;
    }

    // PUSHFD/POPFD can still appear if operand size override is used
    case X86_INS_PUSHFD: {
        cpu.push64(st.rflags & 0xFFFFFFFF);
        break;
    }

    case X86_INS_POPFD: {
        uint64_t val = cpu.pop64();
        st.rflags = (st.rflags & 0xFFFFFFFF00000000ULL) | (val & 0xFFFFFFFF);
        st.rflags |= 0x2;
        break;
    }

    // ================================================================
    // ARITHMETIC
    // ================================================================

    case X86_INS_ADD: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a + b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_add(a, b, result, sz);
        break;
    }

    case X86_INS_ADC: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t carry = (st.rflags & EFLAG_CF) ? 1 : 0;
        uint64_t ma = a & sz_mask(sz);
        uint64_t mb = b & sz_mask(sz);
        uint64_t result = (ma + mb + carry) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_add(a, b + carry, result, sz);
        // Carry out: if sum wrapped or adding carry wrapped
        bool cf = (ma + mb < ma) || (ma + mb + carry < carry) ||
                  ((sz < 8) && ((ma + mb + carry) >> (sz * 8)) != 0);
        st.rflags = cf ? (st.rflags | EFLAG_CF) : (st.rflags & ~EFLAG_CF);
        break;
    }

    case X86_INS_SUB: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a - b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(a, b, result, sz);
        break;
    }

    case X86_INS_SBB: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t borrow = (st.rflags & EFLAG_CF) ? 1 : 0;
        uint64_t sub_val = (b & sz_mask(sz)) + borrow;
        uint64_t result = ((a & sz_mask(sz)) - sub_val) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(a, sub_val, result, sz);
        break;
    }

    case X86_INS_INC: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t result = (a + 1) & sz_mask(sz);
        write_op(0, result, sz);
        // INC doesn't affect CF
        uint64_t saved_cf = st.rflags & EFLAG_CF;
        cpu.update_flags_add(a, 1, result, sz);
        st.rflags = (st.rflags & ~EFLAG_CF) | saved_cf;
        break;
    }

    case X86_INS_DEC: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t result = (a - 1) & sz_mask(sz);
        write_op(0, result, sz);
        uint64_t saved_cf = st.rflags & EFLAG_CF;
        cpu.update_flags_sub(a, 1, result, sz);
        st.rflags = (st.rflags & ~EFLAG_CF) | saved_cf;
        break;
    }

    case X86_INS_NEG: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t result = (0 - a) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_sub(0, a, result, sz);
        if ((a & sz_mask(sz)) != 0) st.rflags |= EFLAG_CF;
        else st.rflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_MUL: {
        int sz = op_size(ops[0]);
        uint64_t src = read_op(0, sz);
        switch (sz) {
            case 1: {
                uint16_t result = static_cast<uint16_t>(st.rax & 0xFF) * static_cast<uint16_t>(src & 0xFF);
                st.rax = (st.rax & ~0xFFFFULL) | result;
                bool overflow = (result >> 8) != 0;
                if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
            case 2: {
                uint32_t result = static_cast<uint32_t>(st.rax & 0xFFFF) * static_cast<uint32_t>(src & 0xFFFF);
                st.rax = (st.rax & ~0xFFFFULL) | (result & 0xFFFF);
                st.rdx = (st.rdx & ~0xFFFFULL) | (result >> 16);
                bool overflow = (result >> 16) != 0;
                if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
            case 4: {
                uint64_t result = static_cast<uint64_t>(st.rax & 0xFFFFFFFF) * static_cast<uint64_t>(src & 0xFFFFFFFF);
                // 32-bit MUL: result in EDX:EAX, zero-extended to RDX:RAX
                st.rax = result & 0xFFFFFFFF;
                st.rdx = (result >> 32) & 0xFFFFFFFF;
                bool overflow = st.rdx != 0;
                if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
            case 8: {
                uint64_t hi, lo;
                umul128(st.rax, src, hi, lo);
                st.rax = lo;
                st.rdx = hi;
                bool overflow = st.rdx != 0;
                if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                break;
            }
        }
        break;
    }

    case X86_INS_IMUL: {
        if (nops == 1) {
            int sz = op_size(ops[0]);
            int64_t src = static_cast<int64_t>(sign_extend(read_op(0, sz), sz * 8));
            switch (sz) {
                case 1: {
                    int16_t result = static_cast<int16_t>(static_cast<int8_t>(st.rax & 0xFF)) * static_cast<int16_t>(static_cast<int8_t>(src));
                    st.rax = (st.rax & ~0xFFFFULL) | static_cast<uint16_t>(result);
                    bool overflow = (result != static_cast<int8_t>(result & 0xFF));
                    if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                    else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
                case 2: {
                    int32_t result = static_cast<int32_t>(static_cast<int16_t>(st.rax & 0xFFFF)) * static_cast<int32_t>(static_cast<int16_t>(src));
                    st.rax = (st.rax & ~0xFFFFULL) | (static_cast<uint32_t>(result) & 0xFFFF);
                    st.rdx = (st.rdx & ~0xFFFFULL) | ((static_cast<uint32_t>(result) >> 16) & 0xFFFF);
                    bool overflow = (result != static_cast<int16_t>(result & 0xFFFF));
                    if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                    else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
                case 4: {
                    int64_t result = static_cast<int64_t>(static_cast<int32_t>(st.rax & 0xFFFFFFFF)) * static_cast<int64_t>(static_cast<int32_t>(src));
                    // Zero-extend both halves to 64 bits
                    st.rax = static_cast<uint64_t>(result) & 0xFFFFFFFF;
                    st.rdx = (static_cast<uint64_t>(result) >> 32) & 0xFFFFFFFF;
                    bool overflow = (result != static_cast<int32_t>(st.rax));
                    if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                    else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
                case 8: {
                    int64_t hi;
                    uint64_t lo;
                    imul128(static_cast<int64_t>(st.rax), static_cast<int64_t>(src), hi, lo);
                    st.rax = lo;
                    st.rdx = static_cast<uint64_t>(hi);
                    bool overflow = (hi != (static_cast<int64_t>(lo) >> 63));
                    if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
                    else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
                    break;
                }
            }
        } else if (nops == 2) {
            int sz = op_size(ops[0]);
            int64_t a = static_cast<int64_t>(sign_extend(read_op(0, sz), sz * 8));
            int64_t b = static_cast<int64_t>(sign_extend(read_op(1, op_size(ops[1])), op_size(ops[1]) * 8));
            int64_t hi; uint64_t lo;
            imul128(a, b, hi, lo);
            uint64_t trunc = lo & sz_mask(sz);
            write_op(0, trunc, sz);
            int64_t sext = static_cast<int64_t>(sign_extend(trunc, sz * 8));
            bool overflow = (hi != (sext >> 63)) || (lo != static_cast<uint64_t>(sext));
            if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
            else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
        } else if (nops == 3) {
            int sz = op_size(ops[0]);
            int64_t a = static_cast<int64_t>(sign_extend(read_op(1, op_size(ops[1])), op_size(ops[1]) * 8));
            int64_t b = static_cast<int64_t>(sign_extend(read_op(2, op_size(ops[2])), op_size(ops[2]) * 8));
            int64_t hi; uint64_t lo;
            imul128(a, b, hi, lo);
            uint64_t trunc = lo & sz_mask(sz);
            write_op(0, trunc, sz);
            int64_t sext = static_cast<int64_t>(sign_extend(trunc, sz * 8));
            bool overflow = (hi != (sext >> 63)) || (lo != static_cast<uint64_t>(sext));
            if (overflow) st.rflags |= (EFLAG_CF | EFLAG_OF);
            else st.rflags &= ~(EFLAG_CF | EFLAG_OF);
        }
        break;
    }

    case X86_INS_DIV: {
        int sz = op_size(ops[0]);
        uint64_t divisor = read_op(0, sz) & sz_mask(sz);
        if (divisor == 0) {
            res.ok = false;
            res.stop = StopReason::EXCEPTION;
            return res;
        }
        switch (sz) {
            case 1: {
                uint16_t dividend = static_cast<uint16_t>(st.rax & 0xFFFF);
                uint8_t quotient = static_cast<uint8_t>(dividend / divisor);
                uint8_t remainder = static_cast<uint8_t>(dividend % divisor);
                st.rax = (st.rax & ~0xFFFFULL) | (static_cast<uint16_t>(remainder) << 8) | quotient;
                break;
            }
            case 2: {
                uint32_t dividend = (static_cast<uint32_t>(st.rdx & 0xFFFF) << 16) | static_cast<uint32_t>(st.rax & 0xFFFF);
                uint16_t quotient = static_cast<uint16_t>(dividend / (divisor & 0xFFFF));
                uint16_t remainder = static_cast<uint16_t>(dividend % (divisor & 0xFFFF));
                st.rax = (st.rax & ~0xFFFFULL) | quotient;
                st.rdx = (st.rdx & ~0xFFFFULL) | remainder;
                break;
            }
            case 4: {
                uint64_t dividend = ((st.rdx & 0xFFFFFFFF) << 32) | (st.rax & 0xFFFFFFFF);
                uint32_t quotient = static_cast<uint32_t>(dividend / (divisor & 0xFFFFFFFF));
                uint32_t remainder = static_cast<uint32_t>(dividend % (divisor & 0xFFFFFFFF));
                // Zero-extend to 64-bit registers
                st.rax = quotient;
                st.rdx = remainder;
                break;
            }
            case 8: {
#if defined(_MSC_VER) && !defined(__clang__)
                // MSVC software 128-bit unsigned division fallback
                // _udiv128 requires MSVC 2019 16.4+ and may not be available.
                // Use shift-subtract algorithm for RDX:RAX / divisor.
                {
                    uint64_t hi = st.rdx, lo = st.rax;
                    if (hi == 0) {
                        st.rax = lo / divisor;
                        st.rdx = lo % divisor;
                    } else {
                        // Shift-subtract 128/64 division
                        uint64_t quot = 0, rem = 0;
                        for (int bit = 127; bit >= 0; --bit) {
                            rem = (rem << 1) | ((bit >= 64 ? (hi >> (bit - 64)) : (lo >> bit)) & 1);
                            if (rem >= divisor) {
                                rem -= divisor;
                                if (bit < 64) quot |= (1ULL << bit);
                            }
                        }
                        st.rax = quot;
                        st.rdx = rem;
                    }
                }
#else
                __uint128_t dividend = (static_cast<__uint128_t>(st.rdx) << 64) | st.rax;
                st.rax = static_cast<uint64_t>(dividend / divisor);
                st.rdx = static_cast<uint64_t>(dividend % divisor);
#endif
                break;
            }
        }
        break;
    }

    case X86_INS_IDIV: {
        int sz = op_size(ops[0]);
        int64_t divisor = static_cast<int64_t>(sign_extend(read_op(0, sz), sz * 8));
        if (divisor == 0) {
            res.ok = false;
            res.stop = StopReason::EXCEPTION;
            return res;
        }
        switch (sz) {
            case 1: {
                int16_t dividend = static_cast<int16_t>(st.rax & 0xFFFF);
                int8_t quotient = static_cast<int8_t>(dividend / static_cast<int8_t>(divisor));
                int8_t remainder = static_cast<int8_t>(dividend % static_cast<int8_t>(divisor));
                st.rax = (st.rax & ~0xFFFFULL) | (static_cast<uint8_t>(remainder) << 8) | static_cast<uint8_t>(quotient);
                break;
            }
            case 2: {
                int32_t dividend = static_cast<int32_t>((static_cast<uint32_t>(st.rdx & 0xFFFF) << 16) | static_cast<uint32_t>(st.rax & 0xFFFF));
                int16_t quotient = static_cast<int16_t>(dividend / static_cast<int16_t>(divisor));
                int16_t remainder = static_cast<int16_t>(dividend % static_cast<int16_t>(divisor));
                st.rax = (st.rax & ~0xFFFFULL) | static_cast<uint16_t>(quotient);
                st.rdx = (st.rdx & ~0xFFFFULL) | static_cast<uint16_t>(remainder);
                break;
            }
            case 4: {
                int64_t dividend = static_cast<int64_t>(((st.rdx & 0xFFFFFFFF) << 32) | (st.rax & 0xFFFFFFFF));
                int32_t quotient = static_cast<int32_t>(dividend / static_cast<int32_t>(divisor));
                int32_t remainder = static_cast<int32_t>(dividend % static_cast<int32_t>(divisor));
                st.rax = static_cast<uint32_t>(quotient);
                st.rdx = static_cast<uint32_t>(remainder);
                break;
            }
            case 8: {
#if defined(_MSC_VER) && !defined(__clang__)
                // MSVC software 128-bit signed division fallback
                // _div128 requires MSVC 2019 16.4+ and may not be available.
                {
                    int64_t s_hi = static_cast<int64_t>(st.rdx);
                    uint64_t s_lo = st.rax;
                    // Determine sign of dividend and divisor
                    bool neg_dividend = s_hi < 0;
                    bool neg_divisor = divisor < 0;
                    // Work with absolute values using unsigned division
                    uint64_t abs_hi, abs_lo, abs_div;
                    if (neg_dividend) {
                        // Negate 128-bit value: ~val + 1
                        abs_lo = ~s_lo + 1;
                        abs_hi = ~static_cast<uint64_t>(s_hi) + (abs_lo == 0 ? 1 : 0);
                    } else {
                        abs_hi = static_cast<uint64_t>(s_hi);
                        abs_lo = s_lo;
                    }
                    abs_div = neg_divisor ? static_cast<uint64_t>(-divisor) : static_cast<uint64_t>(divisor);
                    // Unsigned 128/64 division via shift-subtract
                    uint64_t quot = 0, rem = 0;
                    if (abs_hi == 0) {
                        quot = abs_lo / abs_div;
                        rem = abs_lo % abs_div;
                    } else {
                        for (int bit = 127; bit >= 0; --bit) {
                            rem = (rem << 1) | ((bit >= 64 ? (abs_hi >> (bit - 64)) : (abs_lo >> bit)) & 1);
                            if (rem >= abs_div) {
                                rem -= abs_div;
                                if (bit < 64) quot |= (1ULL << bit);
                            }
                        }
                    }
                    // Apply signs: quotient is negative if signs differ, remainder has sign of dividend
                    bool neg_quot = neg_dividend != neg_divisor;
                    st.rax = neg_quot ? static_cast<uint64_t>(-static_cast<int64_t>(quot)) : quot;
                    st.rdx = neg_dividend ? static_cast<uint64_t>(-static_cast<int64_t>(rem)) : rem;
                }
#else
                __int128_t dividend = (static_cast<__int128_t>(static_cast<int64_t>(st.rdx)) << 64) |
                                       static_cast<__uint128_t>(st.rax);
                st.rax = static_cast<uint64_t>(dividend / divisor);
                st.rdx = static_cast<uint64_t>(dividend % divisor);
#endif
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
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a & b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_OR: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a | b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_XOR: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a ^ b) & sz_mask(sz);
        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_NOT: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t result = (~a) & sz_mask(sz);
        write_op(0, result, sz);
        break;
    }

    case X86_INS_TEST: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        uint64_t result = (a & b) & sz_mask(sz);
        cpu.update_flags_logic(result, sz);
        break;
    }

    case X86_INS_SHL:
    case X86_INS_SAL: {
        int sz = op_size(ops[0]);
        uint64_t val = read_op(0, sz);
        // In 64-bit mode, shift count mask is 0x3F for 64-bit operands, 0x1F otherwise
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & count_mask) : 1;
        if (count == 0) break;

        uint64_t mask = sz_mask(sz);
        uint64_t result = (val << count) & mask;
        bool cf = ((val << (count - 1)) & sz_sign(sz)) != 0;

        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        if (cf) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;

        if (count == 1) {
            bool of_val = ((result & sz_sign(sz)) != 0) != cf;
            if (of_val) st.rflags |= EFLAG_OF; else st.rflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_SHR: {
        int sz = op_size(ops[0]);
        uint64_t val = read_op(0, sz) & sz_mask(sz);
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & count_mask) : 1;
        if (count == 0) break;

        bool cf = ((val >> (count - 1)) & 1) != 0;
        uint64_t result = (val >> count) & sz_mask(sz);

        write_op(0, result, sz);
        cpu.update_flags_logic(result, sz);
        if (cf) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;

        if (count == 1) {
            bool of_val = (val & sz_sign(sz)) != 0;
            if (of_val) st.rflags |= EFLAG_OF; else st.rflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_SAR: {
        int sz = op_size(ops[0]);
        int64_t val = static_cast<int64_t>(sign_extend(read_op(0, sz), sz * 8));
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & count_mask) : 1;
        if (count == 0) break;

        bool cf = ((val >> (count - 1)) & 1) != 0;
        int64_t result = val >> count;
        uint64_t uresult = static_cast<uint64_t>(result) & sz_mask(sz);

        write_op(0, uresult, sz);
        cpu.update_flags_logic(uresult, sz);
        if (cf) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        if (count == 1) st.rflags &= ~EFLAG_OF;
        break;
    }

    case X86_INS_ROL: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint64_t val = read_op(0, sz) & sz_mask(sz);
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & count_mask) : 1;
        if (count == 0) break;
        count %= bits;
        if (count == 0) { count = bits; }

        uint64_t result = ((val << count) | (val >> (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);

        if (result & 1) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        if (count == 1) {
            bool of_val = ((result & sz_sign(sz)) != 0) != ((result & 1) != 0);
            if (of_val) st.rflags |= EFLAG_OF; else st.rflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_ROR: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint64_t val = read_op(0, sz) & sz_mask(sz);
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = (nops > 1) ? (read_op(1, op_size(ops[1])) & count_mask) : 1;
        if (count == 0) break;
        count %= bits;
        if (count == 0) { count = bits; }

        uint64_t result = ((val >> count) | (val << (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);

        if (result & sz_sign(sz)) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        if (count == 1) {
            bool b1 = (result & sz_sign(sz)) != 0;
            bool b2 = (result & (sz_sign(sz) >> 1)) != 0;
            if (b1 != b2) st.rflags |= EFLAG_OF; else st.rflags &= ~EFLAG_OF;
        }
        break;
    }

    case X86_INS_SHLD: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint64_t dst = read_op(0, sz) & sz_mask(sz);
        uint64_t src = read_op(1, sz) & sz_mask(sz);
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = read_op(2, op_size(ops[2])) & count_mask;
        if (count == 0) break;
        if (count > static_cast<uint64_t>(bits)) break;

        uint64_t result = ((dst << count) | (src >> (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);
        bool cf_val = ((dst << (count - 1)) & sz_sign(sz)) != 0;
        cpu.update_flags_logic(result, sz);
        if (cf_val) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_SHRD: {
        int sz = op_size(ops[0]);
        int bits = sz * 8;
        uint64_t dst = read_op(0, sz) & sz_mask(sz);
        uint64_t src = read_op(1, sz) & sz_mask(sz);
        uint64_t count_mask = (sz == 8) ? 0x3F : 0x1F;
        uint64_t count = read_op(2, op_size(ops[2])) & count_mask;
        if (count == 0) break;
        if (count > static_cast<uint64_t>(bits)) break;

        uint64_t result = ((dst >> count) | (src << (bits - count))) & sz_mask(sz);
        write_op(0, result, sz);
        bool cf_val = ((dst >> (count - 1)) & 1) != 0;
        cpu.update_flags_logic(result, sz);
        if (cf_val) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        break;
    }

    // ================================================================
    // COMPARISON
    // ================================================================

    case X86_INS_CMP: {
        int sz = op_size(ops[0]);
        uint64_t a = read_op(0, sz);
        uint64_t b = read_op(1, op_size(ops[1]));
        if (ops[1].type == X86_OP_IMM && op_size(ops[1]) < sz) {
            b = sign_extend(b & sz_mask(op_size(ops[1])), op_size(ops[1]) * 8);
        }
        uint64_t result = (a - b) & sz_mask(sz);
        cpu.update_flags_sub(a, b, result, sz);
        break;
    }

    // ================================================================
    // CONTROL FLOW
    // ================================================================

    case X86_INS_JMP: {
        uint64_t target;
        if (ops[0].type == X86_OP_IMM) {
            target = static_cast<uint64_t>(ops[0].imm);
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
        if (eval_condition(insn->id, st.rflags)) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_JCXZ: {
        if ((st.rcx & 0xFFFF) == 0) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_JECXZ: {
        if ((st.rcx & 0xFFFFFFFF) == 0) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_JRCXZ: {
        // x64-specific: test full 64-bit RCX
        if (st.rcx == 0) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_CALL: {
        uint64_t ret_addr = insn_addr + insn_size;
        cpu.push64(ret_addr);

        uint64_t target;
        if (ops[0].type == X86_OP_IMM) {
            target = static_cast<uint64_t>(ops[0].imm);
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
    case X86_INS_RETF:
    case X86_INS_RETFQ: {
        uint64_t ret_addr = cpu.pop64();
        // Check for stack cleanup (RET imm16)
        if (nops > 0 && ops[0].type == X86_OP_IMM) {
            st.rsp += static_cast<uint64_t>(ops[0].imm);
        }
        res.next_pc = ret_addr;
        break;
    }

    case X86_INS_LOOP: {
        st.rcx--;
        if (st.rcx != 0) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_LOOPE: {
        st.rcx--;
        if (st.rcx != 0 && (st.rflags & EFLAG_ZF)) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    case X86_INS_LOOPNE: {
        st.rcx--;
        if (st.rcx != 0 && !(st.rflags & EFLAG_ZF)) {
            res.next_pc = static_cast<uint64_t>(ops[0].imm);
        }
        break;
    }

    // ================================================================
    // STRING INSTRUCTIONS (with REP/REPNE prefix support)
    // In 64-bit mode, use RSI/RDI/RCX instead of ESI/EDI/ECX.
    // Segment bases are 0 except FS/GS.
    // ================================================================

    case X86_INS_MOVSB:
    case X86_INS_MOVSW:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ: {
        int sz = (insn->id == X86_INS_MOVSB) ? 1 :
                 (insn->id == X86_INS_MOVSW) ? 2 :
                 (insn->id == X86_INS_MOVSD) ? 4 : 8;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int64_t dir = (st.rflags & EFLAG_DF) ? -1 : 1;

        auto do_movs = [&]() {
            uint64_t val = 0;
            vmem.read(st.rsi, &val, sz);
            vmem.write(st.rdi, &val, sz);
            st.rsi += dir * sz;
            st.rdi += dir * sz;
        };

        if (has_rep) {
            while (st.rcx != 0) {
                do_movs();
                st.rcx--;
            }
        } else {
            do_movs();
        }
        break;
    }

    case X86_INS_STOSB:
    case X86_INS_STOSW:
    case X86_INS_STOSD:
    case X86_INS_STOSQ: {
        int sz = (insn->id == X86_INS_STOSB) ? 1 :
                 (insn->id == X86_INS_STOSW) ? 2 :
                 (insn->id == X86_INS_STOSD) ? 4 : 8;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int64_t dir = (st.rflags & EFLAG_DF) ? -1 : 1;
        uint64_t val = st.rax & sz_mask(sz);

        auto do_stos = [&]() {
            vmem.write(st.rdi, &val, sz);
            st.rdi += dir * sz;
        };

        if (has_rep) {
            while (st.rcx != 0) {
                do_stos();
                st.rcx--;
            }
        } else {
            do_stos();
        }
        break;
    }

    case X86_INS_CMPSB:
    case X86_INS_CMPSW:
    case X86_INS_CMPSD:
    case X86_INS_CMPSQ: {
        int sz = (insn->id == X86_INS_CMPSB) ? 1 :
                 (insn->id == X86_INS_CMPSW) ? 2 :
                 (insn->id == X86_INS_CMPSD) ? 4 : 8;
        bool has_repe = (x86.prefix[0] == X86_PREFIX_REPE);
        bool has_repne = (x86.prefix[0] == X86_PREFIX_REPNE);
        int64_t dir = (st.rflags & EFLAG_DF) ? -1 : 1;

        auto do_cmps = [&]() {
            uint64_t a = 0, b = 0;
            vmem.read(st.rsi, &a, sz);
            vmem.read(st.rdi, &b, sz);
            uint64_t result = (a - b) & sz_mask(sz);
            cpu.update_flags_sub(a, b, result, sz);
            st.rsi += dir * sz;
            st.rdi += dir * sz;
        };

        if (has_repe) {
            while (st.rcx != 0) {
                do_cmps();
                st.rcx--;
                if (!(st.rflags & EFLAG_ZF)) break;
            }
        } else if (has_repne) {
            while (st.rcx != 0) {
                do_cmps();
                st.rcx--;
                if (st.rflags & EFLAG_ZF) break;
            }
        } else {
            do_cmps();
        }
        break;
    }

    case X86_INS_SCASB:
    case X86_INS_SCASW:
    case X86_INS_SCASD:
    case X86_INS_SCASQ: {
        int sz = (insn->id == X86_INS_SCASB) ? 1 :
                 (insn->id == X86_INS_SCASW) ? 2 :
                 (insn->id == X86_INS_SCASD) ? 4 : 8;
        bool has_repe = (x86.prefix[0] == X86_PREFIX_REPE);
        bool has_repne = (x86.prefix[0] == X86_PREFIX_REPNE);
        int64_t dir = (st.rflags & EFLAG_DF) ? -1 : 1;
        uint64_t a = st.rax & sz_mask(sz);

        auto do_scas = [&]() {
            uint64_t b = 0;
            vmem.read(st.rdi, &b, sz);
            uint64_t result = (a - b) & sz_mask(sz);
            cpu.update_flags_sub(a, b, result, sz);
            st.rdi += dir * sz;
        };

        if (has_repe) {
            while (st.rcx != 0) {
                do_scas();
                st.rcx--;
                if (!(st.rflags & EFLAG_ZF)) break;
            }
        } else if (has_repne) {
            while (st.rcx != 0) {
                do_scas();
                st.rcx--;
                if (st.rflags & EFLAG_ZF) break;
            }
        } else {
            do_scas();
        }
        break;
    }

    case X86_INS_LODSB:
    case X86_INS_LODSW:
    case X86_INS_LODSD:
    case X86_INS_LODSQ: {
        int sz = (insn->id == X86_INS_LODSB) ? 1 :
                 (insn->id == X86_INS_LODSW) ? 2 :
                 (insn->id == X86_INS_LODSD) ? 4 : 8;
        bool has_rep = (x86.prefix[0] == X86_PREFIX_REP || x86.prefix[0] == X86_PREFIX_REPE);
        int64_t dir = (st.rflags & EFLAG_DF) ? -1 : 1;

        auto do_lods = [&]() {
            uint64_t val = 0;
            vmem.read(st.rsi, &val, sz);
            if (sz == 1) st.rax = (st.rax & ~0xFFULL) | (val & 0xFF);
            else if (sz == 2) st.rax = (st.rax & ~0xFFFFULL) | (val & 0xFFFF);
            else if (sz == 4) st.rax = val & 0xFFFFFFFF;  // Zero-extends to 64
            else st.rax = val;
            st.rsi += dir * sz;
        };

        if (has_rep) {
            while (st.rcx != 0) {
                do_lods();
                st.rcx--;
            }
        } else {
            do_lods();
        }
        break;
    }

    // ================================================================
    // STACK: ENTER / LEAVE (64-bit mode)
    // ================================================================

    case X86_INS_ENTER: {
        uint16_t alloc_size = static_cast<uint16_t>(ops[0].imm);
        uint8_t nesting = static_cast<uint8_t>(ops[1].imm);
        cpu.push64(st.rbp);
        uint64_t frame_temp = st.rsp;

        if (nesting > 0) {
            for (uint8_t i = 1; i < nesting; i++) {
                st.rbp -= 8;
                cpu.push64(vmem.read64(st.rbp));
            }
            cpu.push64(frame_temp);
        }

        st.rbp = frame_temp;
        st.rsp -= alloc_size;
        break;
    }

    case X86_INS_LEAVE: {
        st.rsp = st.rbp;
        st.rbp = cpu.pop64();
        break;
    }

    // ================================================================
    // FLAG MANIPULATION
    // ================================================================

    case X86_INS_CLC: st.rflags &= ~EFLAG_CF; break;
    case X86_INS_STC: st.rflags |= EFLAG_CF; break;
    case X86_INS_CMC: st.rflags ^= EFLAG_CF; break;
    case X86_INS_CLD: st.rflags &= ~EFLAG_DF; break;
    case X86_INS_STD: st.rflags |= EFLAG_DF; break;
    case X86_INS_CLI: st.rflags &= ~EFLAG_IF; break;
    case X86_INS_STI: st.rflags |= EFLAG_IF; break;

    case X86_INS_LAHF: {
        uint8_t ah = static_cast<uint8_t>(st.rflags & 0xFF);
        st.rax = (st.rax & ~0xFF00ULL) | (static_cast<uint64_t>(ah) << 8);
        break;
    }

    case X86_INS_SAHF: {
        uint8_t ah = static_cast<uint8_t>((st.rax >> 8) & 0xFF);
        st.rflags = (st.rflags & ~0xFFULL) | ah;
        st.rflags |= 0x2;
        break;
    }

    // ================================================================
    // BIT MANIPULATION
    // ================================================================

    case X86_INS_BSF: {
        int sz = op_size(ops[0]);
        uint64_t src = read_op(1, sz) & sz_mask(sz);
        if (src == 0) {
            st.rflags |= EFLAG_ZF;
        } else {
            st.rflags &= ~EFLAG_ZF;
            uint64_t idx = 0;
            while (!(src & (1ULL << idx))) idx++;
            write_op(0, idx, sz);
        }
        break;
    }

    case X86_INS_BSR: {
        int sz = op_size(ops[0]);
        uint64_t src = read_op(1, sz) & sz_mask(sz);
        if (src == 0) {
            st.rflags |= EFLAG_ZF;
        } else {
            st.rflags &= ~EFLAG_ZF;
            int bits = sz * 8;
            uint64_t idx = bits - 1;
            while (!(src & (1ULL << idx))) idx--;
            write_op(0, idx, sz);
        }
        break;
    }

    case X86_INS_BT: {
        int sz = op_size(ops[0]);
        uint64_t base = read_op(0, sz);
        uint64_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        break;
    }

    case X86_INS_BTS: {
        int sz = op_size(ops[0]);
        uint64_t base = read_op(0, sz);
        uint64_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        write_op(0, base | (1ULL << offset), sz);
        break;
    }

    case X86_INS_BTR: {
        int sz = op_size(ops[0]);
        uint64_t base = read_op(0, sz);
        uint64_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        write_op(0, base & ~(1ULL << offset), sz);
        break;
    }

    case X86_INS_BTC: {
        int sz = op_size(ops[0]);
        uint64_t base = read_op(0, sz);
        uint64_t offset = read_op(1, op_size(ops[1])) & ((sz * 8) - 1);
        bool bit = (base >> offset) & 1;
        if (bit) st.rflags |= EFLAG_CF; else st.rflags &= ~EFLAG_CF;
        write_op(0, base ^ (1ULL << offset), sz);
        break;
    }

    case X86_INS_BSWAP: {
        int sz = op_size(ops[0]);
        if (sz == 4) {
            uint32_t val = static_cast<uint32_t>(read_op(0, 4));
            val = ((val & 0xFF000000) >> 24) |
                  ((val & 0x00FF0000) >> 8) |
                  ((val & 0x0000FF00) << 8) |
                  ((val & 0x000000FF) << 24);
            write_op(0, val, 4);
        } else if (sz == 8) {
            uint64_t val = read_op(0, 8);
            val = ((val & 0xFF00000000000000ULL) >> 56) |
                  ((val & 0x00FF000000000000ULL) >> 40) |
                  ((val & 0x0000FF0000000000ULL) >> 24) |
                  ((val & 0x000000FF00000000ULL) >> 8) |
                  ((val & 0x00000000FF000000ULL) << 8) |
                  ((val & 0x0000000000FF0000ULL) << 24) |
                  ((val & 0x000000000000FF00ULL) << 40) |
                  ((val & 0x00000000000000FFULL) << 56);
            write_op(0, val, 8);
        }
        break;
    }

    // ================================================================
    // SIGN EXTENSION
    // ================================================================

    case X86_INS_CBW: {
        // AL -> AX (sign extend)
        int8_t al = static_cast<int8_t>(st.rax & 0xFF);
        st.rax = (st.rax & ~0xFFFFULL) | static_cast<uint16_t>(static_cast<int16_t>(al));
        break;
    }

    case X86_INS_CWDE: {
        // AX -> EAX (sign extend, zero-extends to RAX in 64-bit mode)
        int16_t ax = static_cast<int16_t>(st.rax & 0xFFFF);
        st.rax = static_cast<uint32_t>(static_cast<int32_t>(ax));
        break;
    }

    case X86_INS_CDQE: {
        // EAX -> RAX (sign extend) -- x64-specific
        int32_t eax = static_cast<int32_t>(st.rax & 0xFFFFFFFF);
        st.rax = static_cast<uint64_t>(static_cast<int64_t>(eax));
        break;
    }

    case X86_INS_CWD: {
        // AX -> DX:AX (sign extend)
        int16_t ax = static_cast<int16_t>(st.rax & 0xFFFF);
        int32_t ext = static_cast<int32_t>(ax);
        st.rax = (st.rax & ~0xFFFFULL) | (static_cast<uint32_t>(ext) & 0xFFFF);
        st.rdx = (st.rdx & ~0xFFFFULL) | ((static_cast<uint32_t>(ext) >> 16) & 0xFFFF);
        break;
    }

    case X86_INS_CDQ: {
        // EAX -> EDX:EAX (sign extend)
        // In 64-bit mode, zero-extends to full RAX/RDX
        st.rdx = (static_cast<int32_t>(st.rax & 0xFFFFFFFF) < 0) ? 0xFFFFFFFF : 0;
        // Zero-extend both to 64 bits (32-bit write rule)
        st.rax = st.rax & 0xFFFFFFFF;
        break;
    }

    case X86_INS_CQO: {
        // RAX -> RDX:RAX (sign extend) -- x64-specific
        st.rdx = (static_cast<int64_t>(st.rax) < 0) ? 0xFFFFFFFFFFFFFFFFULL : 0;
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
        if (eval_setcc_condition(insn->id, st.rflags)) {
            int sz = op_size(ops[0]);
            uint64_t val = read_op(1, sz);
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
        uint64_t val = eval_setcc_condition(insn->id, st.rflags) ? 1 : 0;
        write_op(0, val, 1);
        break;
    }

    // ================================================================
    // EXCHANGE AND ADD / COMPARE AND EXCHANGE
    // ================================================================

    case X86_INS_XADD: {
        int sz = op_size(ops[0]);
        uint64_t dst_val = read_op(0, sz);
        uint64_t src_val = read_op(1, sz);
        uint64_t result = (dst_val + src_val) & sz_mask(sz);
        write_op(0, result, sz);
        write_op(1, dst_val, sz);
        cpu.update_flags_add(dst_val, src_val, result, sz);
        break;
    }

    case X86_INS_CMPXCHG: {
        int sz = op_size(ops[0]);
        uint64_t dst_val = read_op(0, sz);
        uint64_t acc = st.rax & sz_mask(sz);

        uint64_t cmp_result = (acc - dst_val) & sz_mask(sz);
        cpu.update_flags_sub(acc, dst_val, cmp_result, sz);

        if (acc == (dst_val & sz_mask(sz))) {
            uint64_t src_val = read_op(1, sz);
            write_op(0, src_val, sz);
        } else {
            // Not equal: accumulator = dst
            if (sz == 1) st.rax = (st.rax & ~0xFFULL) | (dst_val & 0xFF);
            else if (sz == 2) st.rax = (st.rax & ~0xFFFFULL) | (dst_val & 0xFFFF);
            else if (sz == 4) st.rax = dst_val & 0xFFFFFFFF;  // Zero-extends
            else st.rax = dst_val;
        }
        break;
    }

    // ================================================================
    // x64-SPECIFIC INSTRUCTIONS
    // ================================================================

    case X86_INS_SYSCALL: {
        // SYSCALL: we signal an exception for the environment layer to handle
        // In a real emulator, the environment would intercept and emulate the syscall
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    case X86_INS_SYSRET: {
        // SYSRET: typically not executed in usermode, signal exception
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    // ================================================================
    // MISC
    // ================================================================

    case X86_INS_NOP:
    case X86_INS_FNOP:
        break;

    case X86_INS_INT3: {
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    case X86_INS_INT: {
        res.stop = StopReason::EXCEPTION;
        return res;
    }

    case X86_INS_HLT: {
        res.stop = StopReason::HALT;
        return res;
    }

    case X86_INS_CPUID: {
        uint32_t leaf = static_cast<uint32_t>(st.rax);
        switch (leaf) {
            case 0:
                st.rax = 0x0D;
                st.rbx = 0x756E6547;  // "Genu"
                st.rdx = 0x49656E69;  // "ineI"
                st.rcx = 0x6C65746E;  // "ntel"
                break;
            case 1:
                st.rax = 0x000306C3;  // Family 6, Model 3C (Haswell)
                st.rbx = 0x00100800;
                st.rcx = 0x7FFAFBBF;  // SSE4.2, AES, etc.
                st.rdx = 0xBFEBFBFF;  // SSE2, MMX, etc.
                break;
            case 0x80000001:
                // Extended feature flags (LM bit = long mode)
                st.rax = 0;
                st.rbx = 0;
                st.rcx = 0x00000021;  // LAHF/SAHF in long mode
                st.rdx = 0x20100800;  // NX, LM, SYSCALL
                break;
            default:
                st.rax = st.rbx = st.rcx = st.rdx = 0;
                break;
        }
        break;
    }

    case X86_INS_RDTSC: {
        static uint64_t fake_tsc = 0x100000000ULL;
        fake_tsc += 100;
        st.rax = fake_tsc & 0xFFFFFFFF;
        st.rdx = (fake_tsc >> 32) & 0xFFFFFFFF;
        break;
    }

    // ================================================================
    // DEFAULT: unhandled instruction
    // ================================================================

    default: {
        res.ok = false;
        res.stop = StopReason::ERROR;
        return res;
    }

    } // end switch

    return res;
}

} // namespace vx
