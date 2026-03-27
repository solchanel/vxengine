/**
 * VXEngine x86-32 FPU & SSE Instruction Semantics
 *
 * This file implements:
 *   - x87 FPU instructions (FLD, FST, FADD, FMUL, etc.) with full stack model
 *   - SSE/SSE2 scalar and packed instructions (MOVSS, ADDSS, COMISS, etc.)
 *
 * FPU Stack Model:
 *   state_.fpu.st[0..7] holds the 8 FPU registers.
 *   state_.fpu.top is the current stack top index (0-7).
 *   ST(0) = st[(top) % 8], ST(1) = st[(top+1) % 8], etc.
 *   Push: top = (top - 1) & 7, then write to st[top]
 *   Pop:  read st[top], then top = (top + 1) & 7
 *
 * FPU Status Word (state_.fpu.sw):
 *   Bits 13-11: TOP field (stack top pointer)
 *   Bit 14:     C3
 *   Bit 10:     C2
 *   Bit 9:      C1
 *   Bit 8:      C0
 *   Bits 0-5:   Exception flags (IE, DE, ZE, OE, UE, PE)
 *
 * For comparisons: C3:C2:C0 encodes the result:
 *   ST > src:  0:0:0
 *   ST < src:  0:0:1
 *   ST = src:  1:0:0
 *   Unordered: 1:1:1
 */

// Ensure math constants are available on MSVC
#ifndef _USE_MATH_DEFINES
#define _USE_MATH_DEFINES
#endif

#include "vxengine/cpu/x86/x86_cpu.h"
#include "vxengine/memory.h"
#include <cstring>
#include <cmath>
#include <cassert>
#include <cfloat>

// Fallback definitions for math constants if not provided by the platform
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#ifndef M_LOG2E
#define M_LOG2E 1.44269504088896340736
#endif
#ifndef M_LN2
#define M_LN2 0.693147180559945309417
#endif

namespace vx {

// ============================================================
// FPU stack helpers
// ============================================================

/// Get reference to ST(i), where i is relative to current top
static double& fpu_st(X86FPUState& fpu, int i) {
    return fpu.st[(fpu.top + i) & 7];
}

static double fpu_st_val(const X86FPUState& fpu, int i) {
    return fpu.st[(fpu.top + i) & 7];
}

/// Push a value onto the FPU stack
static void fpu_push(X86FPUState& fpu, double val) {
    fpu.top = (fpu.top - 1) & 7;
    fpu.st[fpu.top] = val;
    // Update tag word: mark the slot as valid (tag = 00)
    uint16_t tag_mask = ~(3 << (fpu.top * 2));
    fpu.tw &= tag_mask;
    // Update status word TOP field
    fpu.sw = (fpu.sw & ~(7 << 11)) | (fpu.top << 11);
}

/// Pop from the FPU stack (returns value, marks slot empty)
static double fpu_pop(X86FPUState& fpu) {
    double val = fpu.st[fpu.top];
    // Mark slot as empty (tag = 11)
    fpu.tw |= (3 << (fpu.top * 2));
    fpu.top = (fpu.top + 1) & 7;
    // Update status word TOP field
    fpu.sw = (fpu.sw & ~(7 << 11)) | (fpu.top << 11);
    return val;
}

/// Set FPU comparison result flags (C3:C2:C0)
static void fpu_set_compare(X86FPUState& fpu, double a, double b) {
    // Clear C3, C2, C1, C0
    fpu.sw &= ~((1 << 14) | (1 << 10) | (1 << 9) | (1 << 8));

    if (std::isnan(a) || std::isnan(b)) {
        // Unordered: C3=1, C2=1, C0=1
        fpu.sw |= (1 << 14) | (1 << 10) | (1 << 8);
    } else if (a > b) {
        // Greater: C3=0, C2=0, C0=0 (all clear)
    } else if (a < b) {
        // Less: C0=1
        fpu.sw |= (1 << 8);
    } else {
        // Equal: C3=1
        fpu.sw |= (1 << 14);
    }
}

/// Set EFLAGS from FPU comparison (for FCOMI/FUCOMI or SSE COMISS/COMISD)
static void set_eflags_from_fp_compare(uint32_t& eflags, double a, double b) {
    eflags &= ~(EFLAG_CF | EFLAG_ZF | EFLAG_PF);

    if (std::isnan(a) || std::isnan(b)) {
        // Unordered: ZF=1, PF=1, CF=1
        eflags |= EFLAG_ZF | EFLAG_PF | EFLAG_CF;
    } else if (a > b) {
        // Greater: all clear
    } else if (a < b) {
        // Less: CF=1
        eflags |= EFLAG_CF;
    } else {
        // Equal: ZF=1
        eflags |= EFLAG_ZF;
    }
}

/// Extract the FPU register index from a Capstone operand (ST(i))
static int fpu_reg_index(const cs_x86_op& op) {
    if (op.type == X86_OP_REG) {
        // Capstone uses X86_REG_ST0 through X86_REG_ST7
        if (op.reg >= X86_REG_ST0 && op.reg <= X86_REG_ST7) {
            return op.reg - X86_REG_ST0;
        }
    }
    return 0;
}

/// Read a float32 from memory
static float read_float32(const VirtualMemory& vmem, uint32_t addr) {
    float val = 0;
    vmem.read(addr, &val, 4);
    return val;
}

/// Read a float64 from memory
static double read_float64(const VirtualMemory& vmem, uint32_t addr) {
    double val = 0;
    vmem.read(addr, &val, 8);
    return val;
}

/// Read an 80-bit extended precision float from memory (approximate as double)
static double read_float80(const VirtualMemory& vmem, uint32_t addr) {
    // Read 10 bytes, but we approximate with double since we use double internally
    uint8_t raw[10];
    vmem.read(addr, raw, 10);

    // Extract sign, exponent, mantissa
    uint16_t se = static_cast<uint16_t>(raw[9]) << 8 | raw[8];
    int sign = (se >> 15) & 1;
    int exponent = se & 0x7FFF;
    uint64_t mantissa = 0;
    std::memcpy(&mantissa, raw, 8);

    if (exponent == 0 && mantissa == 0) return sign ? -0.0 : 0.0;
    if (exponent == 0x7FFF) {
        if (mantissa == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }

    // Approximate: convert 80-bit to double
    // 80-bit: bias = 16383, 64-bit mantissa with explicit integer bit
    // double: bias = 1023, 52-bit mantissa without explicit integer bit
    double result = static_cast<double>(mantissa) / static_cast<double>(1ULL << 63);
    result *= std::ldexp(1.0, exponent - 16383);
    return sign ? -result : result;
}

/// Read a memory FPU operand (float32, float64, or float80 depending on size)
static double read_fpu_mem(const X86Backend& cpu, const cs_x86_op& op) {
    uint32_t addr = cpu.effective_address(op);
    switch (op.size) {
        case 4:  return static_cast<double>(read_float32(cpu.memory(), addr));
        case 8:  return read_float64(cpu.memory(), addr);
        case 10: return read_float80(cpu.memory(), addr);
        default: return read_float64(cpu.memory(), addr);
    }
}

/// Read an integer from memory for FILD
static double read_fpu_int_mem(const X86Backend& cpu, const cs_x86_op& op) {
    uint32_t addr = cpu.effective_address(op);
    switch (op.size) {
        case 2: {
            int16_t val = 0;
            cpu.memory().read(addr, &val, 2);
            return static_cast<double>(val);
        }
        case 4: {
            int32_t val = 0;
            cpu.memory().read(addr, &val, 4);
            return static_cast<double>(val);
        }
        case 8: {
            int64_t val = 0;
            cpu.memory().read(addr, &val, 8);
            return static_cast<double>(val);
        }
        default: {
            int32_t val = 0;
            cpu.memory().read(addr, &val, 4);
            return static_cast<double>(val);
        }
    }
}

/// Write a float to memory
static void write_fpu_mem(X86Backend& cpu, const cs_x86_op& op, double val) {
    uint32_t addr = cpu.effective_address(op);
    switch (op.size) {
        case 4: {
            float f = static_cast<float>(val);
            cpu.memory().write(addr, &f, 4);
            break;
        }
        case 8: {
            cpu.memory().write(addr, &val, 8);
            break;
        }
        case 10: {
            // Approximate 80-bit write: store as double in 10 bytes
            // This is a simplification; a real 80-bit format would be more complex
            uint8_t raw[10] = {};
            // Store the double in the first 8 bytes, zero the last 2
            std::memcpy(raw, &val, 8);
            cpu.memory().write(addr, raw, 10);
            break;
        }
        default:
            cpu.memory().write(addr, &val, 8);
            break;
    }
}

/// Write an integer to memory for FIST/FISTP
static void write_fpu_int_mem(X86Backend& cpu, const cs_x86_op& op, double val) {
    uint32_t addr = cpu.effective_address(op);
    // Round according to FPU control word rounding mode
    // Default: round-to-nearest
    long long ival = static_cast<long long>(std::llrint(val));
    switch (op.size) {
        case 2: {
            int16_t v = static_cast<int16_t>(ival);
            cpu.memory().write(addr, &v, 2);
            break;
        }
        case 4: {
            int32_t v = static_cast<int32_t>(ival);
            cpu.memory().write(addr, &v, 4);
            break;
        }
        case 8: {
            int64_t v = static_cast<int64_t>(ival);
            cpu.memory().write(addr, &v, 8);
            break;
        }
        default: {
            int32_t v = static_cast<int32_t>(ival);
            cpu.memory().write(addr, &v, 4);
            break;
        }
    }
}

// ============================================================
// SSE Helpers
// ============================================================

/// Get XMM register index from Capstone operand
static int xmm_index(const cs_x86_op& op) {
    if (op.type == X86_OP_REG) {
        if (op.reg >= X86_REG_XMM0 && op.reg <= X86_REG_XMM7) {
            return op.reg - X86_REG_XMM0;
        }
    }
    return 0;
}

/// Read float32 from XMM low 32 bits
static float xmm_read_ss(const SSEState& sse, int idx) {
    float val;
    std::memcpy(&val, &sse.xmm[idx].lo, sizeof(float));
    return val;
}

/// Write float32 to XMM low 32 bits (preserve upper bits)
static void xmm_write_ss(SSEState& sse, int idx, float val) {
    // Only write low 32 bits, preserve bits 32-127
    uint64_t lo = sse.xmm[idx].lo;
    uint32_t fval;
    std::memcpy(&fval, &val, 4);
    lo = (lo & 0xFFFFFFFF00000000ULL) | fval;
    sse.xmm[idx].lo = lo;
}

/// Read float64 from XMM low 64 bits
static double xmm_read_sd(const SSEState& sse, int idx) {
    double val;
    std::memcpy(&val, &sse.xmm[idx].lo, sizeof(double));
    return val;
}

/// Write float64 to XMM low 64 bits (preserve upper 64 bits)
static void xmm_write_sd(SSEState& sse, int idx, double val) {
    std::memcpy(&sse.xmm[idx].lo, &val, sizeof(double));
}

// ============================================================
// Main FPU/SSE dispatch
// ============================================================

X86Backend::ExecResult x86_dispatch_fpu(X86Backend& cpu, const cs_insn* insn, VirtualMemory& vmem) {
    X86Backend::ExecResult res;
    res.ok = true;
    res.stop = StopReason::STEP;
    res.next_pc = 0;

    X86State& st = cpu.state_;
    X86FPUState& fpu = st.fpu;
    SSEState& sse = st.sse;
    const cs_x86& x86 = insn->detail->x86;
    const cs_x86_op* ops = x86.operands;
    int nops = x86.op_count;

    switch (insn->id) {

    // ================================================================
    // x87 DATA TRANSFER
    // ================================================================

    case X86_INS_FLD: {
        double val;
        if (nops == 1 && ops[0].type == X86_OP_REG) {
            val = fpu_st_val(fpu, fpu_reg_index(ops[0]));
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            val = read_fpu_mem(cpu, ops[0]);
        } else {
            val = 0.0;
        }
        fpu_push(fpu, val);
        break;
    }

    case X86_INS_FST: {
        double val = fpu_st_val(fpu, 0);
        if (nops == 1 && ops[0].type == X86_OP_REG) {
            fpu_st(fpu, fpu_reg_index(ops[0])) = val;
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            write_fpu_mem(cpu, ops[0], val);
        }
        break;
    }

    case X86_INS_FSTP: {
        double val = fpu_st_val(fpu, 0);
        if (nops == 1 && ops[0].type == X86_OP_REG) {
            fpu_st(fpu, fpu_reg_index(ops[0])) = val;
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            write_fpu_mem(cpu, ops[0], val);
        }
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FILD: {
        double val = read_fpu_int_mem(cpu, ops[0]);
        fpu_push(fpu, val);
        break;
    }

    case X86_INS_FIST: {
        double val = fpu_st_val(fpu, 0);
        write_fpu_int_mem(cpu, ops[0], val);
        break;
    }

    case X86_INS_FISTP: {
        double val = fpu_st_val(fpu, 0);
        write_fpu_int_mem(cpu, ops[0], val);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FXCH: {
        int idx = (nops >= 1 && ops[0].type == X86_OP_REG) ? fpu_reg_index(ops[0]) : 1;
        double tmp = fpu_st_val(fpu, 0);
        fpu_st(fpu, 0) = fpu_st_val(fpu, idx);
        fpu_st(fpu, idx) = tmp;
        break;
    }

    // ================================================================
    // x87 ARITHMETIC
    // ================================================================

    case X86_INS_FADD: {
        // Capstone v6 merges FADDP into FADD — detect via mnemonic
        bool is_faddp = (insn->mnemonic[4] == 'p');
        if (nops == 0) {
            // FADD (no operands) = FADDP ST(1), ST(0)
            fpu_st(fpu, 1) += fpu_st_val(fpu, 0);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) += read_fpu_mem(cpu, ops[0]);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) += fpu_st_val(fpu, src);
            if (is_faddp) fpu_pop(fpu);
        }
        break;
    }

    case X86_INS_FSUB: {
        if (nops == 0) {
            fpu_st(fpu, 1) = fpu_st_val(fpu, 1) - fpu_st_val(fpu, 0);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) -= read_fpu_mem(cpu, ops[0]);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) = fpu_st_val(fpu, dst) - fpu_st_val(fpu, src);
        }
        break;
    }

    case X86_INS_FSUBP: {
        int dst = (nops >= 1) ? fpu_reg_index(ops[0]) : 1;
        fpu_st(fpu, dst) = fpu_st_val(fpu, dst) - fpu_st_val(fpu, 0);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FSUBR: {
        if (nops == 0) {
            fpu_st(fpu, 1) = fpu_st_val(fpu, 0) - fpu_st_val(fpu, 1);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) = read_fpu_mem(cpu, ops[0]) - fpu_st_val(fpu, 0);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) = fpu_st_val(fpu, src) - fpu_st_val(fpu, dst);
        }
        break;
    }

    case X86_INS_FSUBRP: {
        int dst = (nops >= 1) ? fpu_reg_index(ops[0]) : 1;
        fpu_st(fpu, dst) = fpu_st_val(fpu, 0) - fpu_st_val(fpu, dst);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FMUL: {
        if (nops == 0) {
            fpu_st(fpu, 1) *= fpu_st_val(fpu, 0);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) *= read_fpu_mem(cpu, ops[0]);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) *= fpu_st_val(fpu, src);
        }
        break;
    }

    case X86_INS_FMULP: {
        int dst = (nops >= 1) ? fpu_reg_index(ops[0]) : 1;
        fpu_st(fpu, dst) *= fpu_st_val(fpu, 0);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FDIV: {
        if (nops == 0) {
            fpu_st(fpu, 1) = fpu_st_val(fpu, 1) / fpu_st_val(fpu, 0);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) /= read_fpu_mem(cpu, ops[0]);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) = fpu_st_val(fpu, dst) / fpu_st_val(fpu, src);
        }
        break;
    }

    case X86_INS_FDIVP: {
        int dst = (nops >= 1) ? fpu_reg_index(ops[0]) : 1;
        fpu_st(fpu, dst) = fpu_st_val(fpu, dst) / fpu_st_val(fpu, 0);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FDIVR: {
        if (nops == 0) {
            fpu_st(fpu, 1) = fpu_st_val(fpu, 0) / fpu_st_val(fpu, 1);
            fpu_pop(fpu);
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            fpu_st(fpu, 0) = read_fpu_mem(cpu, ops[0]) / fpu_st_val(fpu, 0);
        } else if (nops == 2) {
            int dst = fpu_reg_index(ops[0]);
            int src = fpu_reg_index(ops[1]);
            fpu_st(fpu, dst) = fpu_st_val(fpu, src) / fpu_st_val(fpu, dst);
        }
        break;
    }

    case X86_INS_FDIVRP: {
        int dst = (nops >= 1) ? fpu_reg_index(ops[0]) : 1;
        fpu_st(fpu, dst) = fpu_st_val(fpu, 0) / fpu_st_val(fpu, dst);
        fpu_pop(fpu);
        break;
    }

    // ================================================================
    // x87 UNARY OPERATIONS
    // ================================================================

    case X86_INS_FCHS: {
        fpu_st(fpu, 0) = -fpu_st_val(fpu, 0);
        break;
    }

    case X86_INS_FABS: {
        fpu_st(fpu, 0) = std::fabs(fpu_st_val(fpu, 0));
        break;
    }

    case X86_INS_FSQRT: {
        fpu_st(fpu, 0) = std::sqrt(fpu_st_val(fpu, 0));
        break;
    }

    case X86_INS_FSIN: {
        fpu_st(fpu, 0) = std::sin(fpu_st_val(fpu, 0));
        // C2 = 0 (reduction complete)
        fpu.sw &= ~(1 << 10);
        break;
    }

    case X86_INS_FCOS: {
        fpu_st(fpu, 0) = std::cos(fpu_st_val(fpu, 0));
        fpu.sw &= ~(1 << 10);
        break;
    }

    case X86_INS_FPTAN: {
        // Replace ST(0) with tan(ST(0)), then push 1.0
        fpu_st(fpu, 0) = std::tan(fpu_st_val(fpu, 0));
        fpu_push(fpu, 1.0);
        fpu.sw &= ~(1 << 10);
        break;
    }

    case X86_INS_FPATAN: {
        // ST(1) = arctan(ST(1) / ST(0)), pop ST(0)
        double y = fpu_st_val(fpu, 1);
        double x = fpu_st_val(fpu, 0);
        fpu_pop(fpu);
        fpu_st(fpu, 0) = std::atan2(y, x);
        break;
    }

    case X86_INS_FYL2X: {
        // ST(1) = ST(1) * log2(ST(0)), pop ST(0)
        double x = fpu_st_val(fpu, 0);
        double y = fpu_st_val(fpu, 1);
        fpu_pop(fpu);
        fpu_st(fpu, 0) = y * std::log2(x);
        break;
    }

    case X86_INS_FRNDINT: {
        // Round ST(0) to integer using current rounding mode
        fpu_st(fpu, 0) = std::nearbyint(fpu_st_val(fpu, 0));
        break;
    }

    case X86_INS_F2XM1: {
        // ST(0) = 2^ST(0) - 1 (for -1 <= ST(0) <= 1)
        fpu_st(fpu, 0) = std::exp2(fpu_st_val(fpu, 0)) - 1.0;
        break;
    }

    // ================================================================
    // x87 COMPARISONS
    // ================================================================

    case X86_INS_FCOM: {
        double b;
        if (nops == 0) {
            b = fpu_st_val(fpu, 1);
        } else if (ops[0].type == X86_OP_REG) {
            b = fpu_st_val(fpu, fpu_reg_index(ops[0]));
        } else {
            b = read_fpu_mem(cpu, ops[0]);
        }
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), b);
        break;
    }

    case X86_INS_FCOMP: {
        double b;
        if (nops == 0) {
            b = fpu_st_val(fpu, 1);
        } else if (ops[0].type == X86_OP_REG) {
            b = fpu_st_val(fpu, fpu_reg_index(ops[0]));
        } else {
            b = read_fpu_mem(cpu, ops[0]);
        }
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), b);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FCOMPP: {
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), fpu_st_val(fpu, 1));
        fpu_pop(fpu);
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FUCOM: {
        int idx = (nops >= 1 && ops[0].type == X86_OP_REG) ? fpu_reg_index(ops[0]) : 1;
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), fpu_st_val(fpu, idx));
        break;
    }

    case X86_INS_FUCOMP: {
        int idx = (nops >= 1 && ops[0].type == X86_OP_REG) ? fpu_reg_index(ops[0]) : 1;
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), fpu_st_val(fpu, idx));
        fpu_pop(fpu);
        break;
    }

    case X86_INS_FUCOMPP: {
        fpu_set_compare(fpu, fpu_st_val(fpu, 0), fpu_st_val(fpu, 1));
        fpu_pop(fpu);
        fpu_pop(fpu);
        break;
    }

    // ================================================================
    // x87 CONSTANTS
    // ================================================================

    case X86_INS_FLDZ:  fpu_push(fpu, 0.0); break;
    case X86_INS_FLD1:  fpu_push(fpu, 1.0); break;
    case X86_INS_FLDPI: fpu_push(fpu, M_PI); break;
    case X86_INS_FLDL2E: fpu_push(fpu, M_LOG2E); break;
    case X86_INS_FLDLN2: fpu_push(fpu, M_LN2); break;
    case X86_INS_FLDL2T: fpu_push(fpu, std::log2(10.0)); break;
    case X86_INS_FLDLG2: fpu_push(fpu, std::log10(2.0)); break;

    // ================================================================
    // x87 CONTROL
    // ================================================================

    case X86_INS_FNSTCW: {
        // Store FPU control word to memory
        uint32_t addr = cpu.effective_address(ops[0]);
        vmem.write(addr, &fpu.cw, 2);
        break;
    }

    case X86_INS_FLDCW: {
        // Load FPU control word from memory
        uint32_t addr = cpu.effective_address(ops[0]);
        vmem.read(addr, &fpu.cw, 2);
        break;
    }

    case X86_INS_FNSTSW: {
        // Store FPU status word
        // Update SW TOP field before storing
        fpu.sw = (fpu.sw & ~(7 << 11)) | (fpu.top << 11);

        if (nops == 1 && ops[0].type == X86_OP_REG && ops[0].reg == X86_REG_AX) {
            // FNSTSW AX
            st.eax = (st.eax & 0xFFFF0000) | fpu.sw;
        } else if (nops == 1 && ops[0].type == X86_OP_MEM) {
            uint32_t addr = cpu.effective_address(ops[0]);
            vmem.write(addr, &fpu.sw, 2);
        }
        break;
    }

    case X86_INS_FSTENV: {
        // Store FPU environment (28 bytes in 32-bit protected mode)
        uint32_t addr = cpu.effective_address(ops[0]);
        // Simplified: store control word, status word, tag word
        vmem.write(addr + 0, &fpu.cw, 2);
        uint16_t zero = 0;
        vmem.write(addr + 2, &zero, 2);
        fpu.sw = (fpu.sw & ~(7 << 11)) | (fpu.top << 11);
        vmem.write(addr + 4, &fpu.sw, 2);
        vmem.write(addr + 6, &zero, 2);
        vmem.write(addr + 8, &fpu.tw, 2);
        // IP, CS, DP, DS offsets (simplified to zeros)
        uint32_t zeroes = 0;
        vmem.write(addr + 12, &zeroes, 4);
        vmem.write(addr + 16, &zeroes, 4);
        vmem.write(addr + 20, &zeroes, 4);
        vmem.write(addr + 24, &zeroes, 4);
        break;
    }

    case X86_INS_FLDENV: {
        // Load FPU environment
        uint32_t addr = cpu.effective_address(ops[0]);
        vmem.read(addr + 0, &fpu.cw, 2);
        vmem.read(addr + 4, &fpu.sw, 2);
        vmem.read(addr + 8, &fpu.tw, 2);
        fpu.top = (fpu.sw >> 11) & 7;
        break;
    }

    case X86_INS_WAIT: {
        // FWAIT/WAIT: check for unmasked FPU exceptions (nop in emulation)
        break;
    }

    case X86_INS_FNINIT: {
        // Initialize FPU to defaults
        fpu.cw = 0x037F;
        fpu.sw = 0;
        fpu.tw = 0xFFFF;  // All empty
        fpu.top = 7;
        for (int i = 0; i < 8; i++) fpu.st[i] = 0.0;
        break;
    }

    case X86_INS_FNCLEX: {
        // Clear FPU exception flags
        fpu.sw &= ~0x3F;  // Clear IE, DE, ZE, OE, UE, PE
        fpu.sw &= ~(1 << 7);  // Clear ES (exception summary)
        fpu.sw &= ~(1 << 15); // Clear B (busy)
        break;
    }

    // ================================================================
    // SSE SCALAR FLOAT (32-bit)
    // ================================================================

    case X86_INS_MOVSS: {
        if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG) {
            // XMM -> XMM: only low 32 bits, upper bits preserved
            int dst = xmm_index(ops[0]);
            int src = xmm_index(ops[1]);
            float val = xmm_read_ss(sse, src);
            xmm_write_ss(sse, dst, val);
        } else if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_MEM) {
            // Mem -> XMM: zero upper bits
            int dst = xmm_index(ops[0]);
            uint32_t addr = cpu.effective_address(ops[1]);
            float val;
            vmem.read(addr, &val, 4);
            sse.xmm[dst].lo = 0;
            sse.xmm[dst].hi = 0;
            xmm_write_ss(sse, dst, val);
        } else if (ops[0].type == X86_OP_MEM && ops[1].type == X86_OP_REG) {
            // XMM -> Mem
            int src = xmm_index(ops[1]);
            uint32_t addr = cpu.effective_address(ops[0]);
            float val = xmm_read_ss(sse, src);
            vmem.write(addr, &val, 4);
        }
        break;
    }

    case X86_INS_ADDSS: {
        int dst = xmm_index(ops[0]);
        float a = xmm_read_ss(sse, dst);
        float b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 4);
        }
        xmm_write_ss(sse, dst, a + b);
        break;
    }

    case X86_INS_SUBSS: {
        int dst = xmm_index(ops[0]);
        float a = xmm_read_ss(sse, dst);
        float b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 4);
        }
        xmm_write_ss(sse, dst, a - b);
        break;
    }

    case X86_INS_MULSS: {
        int dst = xmm_index(ops[0]);
        float a = xmm_read_ss(sse, dst);
        float b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 4);
        }
        xmm_write_ss(sse, dst, a * b);
        break;
    }

    case X86_INS_DIVSS: {
        int dst = xmm_index(ops[0]);
        float a = xmm_read_ss(sse, dst);
        float b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 4);
        }
        xmm_write_ss(sse, dst, a / b);
        break;
    }

    case X86_INS_COMISS:
    case X86_INS_UCOMISS: {
        int src1 = xmm_index(ops[0]);
        float a = xmm_read_ss(sse, src1);
        float b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 4);
        }
        set_eflags_from_fp_compare(st.eflags, static_cast<double>(a), static_cast<double>(b));
        break;
    }

    // ================================================================
    // SSE SCALAR DOUBLE (64-bit)
    // ================================================================

    case X86_INS_MOVSD: {
        // Note: MOVSD can be either SSE2 movsd or the string MOVSD.
        // Capstone distinguishes by operand type. If we have XMM operands, it's SSE.
        if (nops >= 2 && (ops[0].type == X86_OP_REG && ops[0].reg >= X86_REG_XMM0 && ops[0].reg <= X86_REG_XMM7)) {
            // SSE2 MOVSD
            if (ops[1].type == X86_OP_REG) {
                int dst = xmm_index(ops[0]);
                int src = xmm_index(ops[1]);
                double val = xmm_read_sd(sse, src);
                xmm_write_sd(sse, dst, val);
            } else if (ops[1].type == X86_OP_MEM) {
                int dst = xmm_index(ops[0]);
                uint32_t addr = cpu.effective_address(ops[1]);
                double val;
                vmem.read(addr, &val, 8);
                sse.xmm[dst].lo = 0;
                sse.xmm[dst].hi = 0;
                xmm_write_sd(sse, dst, val);
            }
        } else if (nops >= 2 && ops[0].type == X86_OP_MEM &&
                   ops[1].type == X86_OP_REG && ops[1].reg >= X86_REG_XMM0 && ops[1].reg <= X86_REG_XMM7) {
            int src = xmm_index(ops[1]);
            uint32_t addr = cpu.effective_address(ops[0]);
            double val = xmm_read_sd(sse, src);
            vmem.write(addr, &val, 8);
        }
        // If neither is XMM, this was already handled as string MOVSD in x86_insns.cpp
        break;
    }

    case X86_INS_ADDSD: {
        int dst = xmm_index(ops[0]);
        double a = xmm_read_sd(sse, dst);
        double b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 8);
        }
        xmm_write_sd(sse, dst, a + b);
        break;
    }

    case X86_INS_SUBSD: {
        int dst = xmm_index(ops[0]);
        double a = xmm_read_sd(sse, dst);
        double b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 8);
        }
        xmm_write_sd(sse, dst, a - b);
        break;
    }

    case X86_INS_MULSD: {
        int dst = xmm_index(ops[0]);
        double a = xmm_read_sd(sse, dst);
        double b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 8);
        }
        xmm_write_sd(sse, dst, a * b);
        break;
    }

    case X86_INS_DIVSD: {
        int dst = xmm_index(ops[0]);
        double a = xmm_read_sd(sse, dst);
        double b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 8);
        }
        xmm_write_sd(sse, dst, a / b);
        break;
    }

    case X86_INS_COMISD:
    case X86_INS_UCOMISD: {
        int src1 = xmm_index(ops[0]);
        double a = xmm_read_sd(sse, src1);
        double b;
        if (ops[1].type == X86_OP_REG) {
            b = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &b, 8);
        }
        set_eflags_from_fp_compare(st.eflags, a, b);
        break;
    }

    // ================================================================
    // SSE CONVERSIONS
    // ================================================================

    case X86_INS_CVTSI2SS: {
        // Convert int32 to float32
        int dst = xmm_index(ops[0]);
        int32_t src;
        if (ops[1].type == X86_OP_REG) {
            src = static_cast<int32_t>(cpu.read_operand(ops[1], 4));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 4);
        }
        xmm_write_ss(sse, dst, static_cast<float>(src));
        break;
    }

    case X86_INS_CVTSI2SD: {
        int dst = xmm_index(ops[0]);
        int32_t src;
        if (ops[1].type == X86_OP_REG) {
            src = static_cast<int32_t>(cpu.read_operand(ops[1], 4));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 4);
        }
        xmm_write_sd(sse, dst, static_cast<double>(src));
        break;
    }

    case X86_INS_CVTSS2SI: {
        // Convert float32 to int32 (rounded)
        float src;
        if (ops[1].type == X86_OP_REG) {
            src = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 4);
        }
        int32_t result = static_cast<int32_t>(std::lrintf(src));
        cpu.write_operand(ops[0], static_cast<uint32_t>(result), 4);
        break;
    }

    case X86_INS_CVTSD2SI: {
        double src;
        if (ops[1].type == X86_OP_REG) {
            src = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 8);
        }
        int32_t result = static_cast<int32_t>(std::lrint(src));
        cpu.write_operand(ops[0], static_cast<uint32_t>(result), 4);
        break;
    }

    case X86_INS_CVTTSS2SI: {
        // Convert float32 to int32 (truncated)
        float src;
        if (ops[1].type == X86_OP_REG) {
            src = xmm_read_ss(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 4);
        }
        int32_t result = static_cast<int32_t>(src);
        cpu.write_operand(ops[0], static_cast<uint32_t>(result), 4);
        break;
    }

    case X86_INS_CVTTSD2SI: {
        double src;
        if (ops[1].type == X86_OP_REG) {
            src = xmm_read_sd(sse, xmm_index(ops[1]));
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &src, 8);
        }
        int32_t result = static_cast<int32_t>(src);
        cpu.write_operand(ops[0], static_cast<uint32_t>(result), 4);
        break;
    }

    // ================================================================
    // SSE PACKED / MOVE OPERATIONS
    // ================================================================

    case X86_INS_MOVAPS:
    case X86_INS_MOVUPS: {
        // Move 128-bit aligned/unaligned packed single
        if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG) {
            int dst = xmm_index(ops[0]);
            int src = xmm_index(ops[1]);
            sse.xmm[dst] = sse.xmm[src];
        } else if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_MEM) {
            int dst = xmm_index(ops[0]);
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &sse.xmm[dst].lo, 8);
            vmem.read(addr + 8, &sse.xmm[dst].hi, 8);
        } else if (ops[0].type == X86_OP_MEM && ops[1].type == X86_OP_REG) {
            int src = xmm_index(ops[1]);
            uint32_t addr = cpu.effective_address(ops[0]);
            vmem.write(addr, &sse.xmm[src].lo, 8);
            vmem.write(addr + 8, &sse.xmm[src].hi, 8);
        }
        break;
    }

    case X86_INS_MOVDQA:
    case X86_INS_MOVDQU: {
        // Same as MOVAPS/MOVUPS but for integer data
        if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_REG) {
            int dst = xmm_index(ops[0]);
            int src = xmm_index(ops[1]);
            sse.xmm[dst] = sse.xmm[src];
        } else if (ops[0].type == X86_OP_REG && ops[1].type == X86_OP_MEM) {
            int dst = xmm_index(ops[0]);
            uint32_t addr = cpu.effective_address(ops[1]);
            vmem.read(addr, &sse.xmm[dst].lo, 8);
            vmem.read(addr + 8, &sse.xmm[dst].hi, 8);
        } else if (ops[0].type == X86_OP_MEM && ops[1].type == X86_OP_REG) {
            int src = xmm_index(ops[1]);
            uint32_t addr = cpu.effective_address(ops[0]);
            vmem.write(addr, &sse.xmm[src].lo, 8);
            vmem.write(addr + 8, &sse.xmm[src].hi, 8);
        }
        break;
    }

    // ================================================================
    // SSE INTEGER LOGIC (packed)
    // ================================================================

    case X86_INS_PAND: {
        int dst = xmm_index(ops[0]);
        if (ops[1].type == X86_OP_REG) {
            int src = xmm_index(ops[1]);
            sse.xmm[dst].lo &= sse.xmm[src].lo;
            sse.xmm[dst].hi &= sse.xmm[src].hi;
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            uint64_t lo = 0, hi = 0;
            vmem.read(addr, &lo, 8);
            vmem.read(addr + 8, &hi, 8);
            sse.xmm[dst].lo &= lo;
            sse.xmm[dst].hi &= hi;
        }
        break;
    }

    case X86_INS_POR: {
        int dst = xmm_index(ops[0]);
        if (ops[1].type == X86_OP_REG) {
            int src = xmm_index(ops[1]);
            sse.xmm[dst].lo |= sse.xmm[src].lo;
            sse.xmm[dst].hi |= sse.xmm[src].hi;
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            uint64_t lo = 0, hi = 0;
            vmem.read(addr, &lo, 8);
            vmem.read(addr + 8, &hi, 8);
            sse.xmm[dst].lo |= lo;
            sse.xmm[dst].hi |= hi;
        }
        break;
    }

    case X86_INS_PXOR: {
        int dst = xmm_index(ops[0]);
        if (ops[1].type == X86_OP_REG) {
            int src = xmm_index(ops[1]);
            sse.xmm[dst].lo ^= sse.xmm[src].lo;
            sse.xmm[dst].hi ^= sse.xmm[src].hi;
        } else {
            uint32_t addr = cpu.effective_address(ops[1]);
            uint64_t lo = 0, hi = 0;
            vmem.read(addr, &lo, 8);
            vmem.read(addr + 8, &hi, 8);
            sse.xmm[dst].lo ^= lo;
            sse.xmm[dst].hi ^= hi;
        }
        break;
    }

    // ================================================================
    // SSE MOVD / MOVQ
    // ================================================================

    case X86_INS_MOVD: {
        // MOVD: move 32-bit between GPR/mem and XMM
        if (ops[0].type == X86_OP_REG && ops[0].reg >= X86_REG_XMM0 && ops[0].reg <= X86_REG_XMM7) {
            // GPR/mem -> XMM (zero-extend to 128 bits)
            int dst = xmm_index(ops[0]);
            uint32_t val;
            if (ops[1].type == X86_OP_REG) {
                val = cpu.read_operand(ops[1], 4);
            } else {
                uint32_t addr = cpu.effective_address(ops[1]);
                vmem.read(addr, &val, 4);
            }
            sse.xmm[dst].lo = val;
            sse.xmm[dst].hi = 0;
        } else {
            // XMM -> GPR/mem (low 32 bits)
            int src = xmm_index(ops[1]);
            uint32_t val = static_cast<uint32_t>(sse.xmm[src].lo);
            if (ops[0].type == X86_OP_REG) {
                cpu.write_operand(ops[0], val, 4);
            } else {
                uint32_t addr = cpu.effective_address(ops[0]);
                vmem.write(addr, &val, 4);
            }
        }
        break;
    }

    case X86_INS_MOVQ: {
        // MOVQ: move 64-bit between XMM/mem
        if (ops[0].type == X86_OP_REG && ops[0].reg >= X86_REG_XMM0 && ops[0].reg <= X86_REG_XMM7) {
            int dst = xmm_index(ops[0]);
            if (ops[1].type == X86_OP_REG && ops[1].reg >= X86_REG_XMM0 && ops[1].reg <= X86_REG_XMM7) {
                int src = xmm_index(ops[1]);
                sse.xmm[dst].lo = sse.xmm[src].lo;
            } else if (ops[1].type == X86_OP_MEM) {
                uint32_t addr = cpu.effective_address(ops[1]);
                vmem.read(addr, &sse.xmm[dst].lo, 8);
            }
            sse.xmm[dst].hi = 0;
        } else if (ops[0].type == X86_OP_MEM) {
            int src = xmm_index(ops[1]);
            uint32_t addr = cpu.effective_address(ops[0]);
            vmem.write(addr, &sse.xmm[src].lo, 8);
        }
        break;
    }

    // ================================================================
    // DEFAULT: unhandled FPU/SSE instruction
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
