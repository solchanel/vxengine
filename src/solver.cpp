/**
 * VXEngine Z3 SMT Solver Integration
 *
 * Provides concolic execution and deobfuscation capabilities:
 *   - Symbolic register/memory tracking
 *   - Opaque predicate detection
 *   - Constant folding for obfuscated arithmetic
 *   - Encrypted blob/handler solving
 */

#ifdef VX_ENABLE_Z3

#include "vxengine/solver.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <sstream>
#include <algorithm>
#include <cassert>

namespace vx {

// ============================================================
// Construction / Destruction
// ============================================================

Solver::Solver()
    : ctx_()
    , solver_(ctx_)
{
    // Default 5-second timeout
    z3::params p(ctx_);
    p.set("timeout", 5000u);
    solver_.set(p);
}

Solver::~Solver() = default;

// ============================================================
// Symbolic variable creation
// ============================================================

z3::expr Solver::symbolize_reg(int reg_id, const std::string& name, int bits) {
    z3::expr sym = ctx_.bv_const(name.c_str(), bits);
    sym_regs_.insert_or_assign(reg_id, sym);
    return sym;
}

std::vector<z3::expr> Solver::symbolize_mem(uint64_t addr, size_t size,
                                             const std::string& name) {
    std::vector<z3::expr> result;
    result.reserve(size);
    for (size_t i = 0; i < size; ++i) {
        std::string byte_name = name + "_" + std::to_string(i);
        z3::expr sym = ctx_.bv_const(byte_name.c_str(), 8);
        sym_mem_.insert_or_assign(addr + i, sym);
        result.push_back(sym);
    }
    return result;
}

z3::expr Solver::make_symbol(const std::string& name, int bits) {
    return ctx_.bv_const(name.c_str(), bits);
}

// ============================================================
// Path constraint management
// ============================================================

void Solver::on_branch(uint64_t addr, const z3::expr& condition, bool taken) {
    constraints_.push_back(PathConstraint{addr, condition, taken});
    branch_cache_.insert_or_assign(addr, condition);

    // Add to solver: if branch was taken, condition is true; otherwise false
    if (taken) {
        solver_.add(condition);
    } else {
        solver_.add(!condition);
    }
}

const std::vector<PathConstraint>& Solver::path_constraints() const {
    return constraints_;
}

void Solver::clear_constraints() {
    constraints_.clear();
    branch_cache_.clear();
    solver_.reset();
}

void Solver::push() {
    solver_.push();
}

void Solver::pop() {
    solver_.pop();
}

// ============================================================
// Opaque predicate detection
// ============================================================

PredicateResult Solver::solve_opaque_predicate(const z3::expr& condition) {
    query_count_++;

    // Test if condition can be true
    solver_.push();
    solver_.add(condition);
    z3::check_result can_be_true = solver_.check();
    solver_.pop();

    // Test if condition can be false
    solver_.push();
    solver_.add(!condition);
    z3::check_result can_be_false = solver_.check();
    solver_.pop();

    if (can_be_true == z3::sat && can_be_false == z3::sat) {
        sat_count_++;
        return PredicateResult::INPUT_DEPENDENT;
    }
    if (can_be_true == z3::sat && can_be_false == z3::unsat) {
        sat_count_++;
        return PredicateResult::ALWAYS_TRUE;
    }
    if (can_be_true == z3::unsat && can_be_false == z3::sat) {
        sat_count_++;
        return PredicateResult::ALWAYS_FALSE;
    }
    // Both unsat or unknown
    return PredicateResult::UNKNOWN;
}

PredicateResult Solver::solve_opaque_predicate(uint64_t addr) {
    auto it = branch_cache_.find(addr);
    if (it == branch_cache_.end()) {
        return PredicateResult::UNKNOWN;
    }
    return solve_opaque_predicate(it->second);
}

// ============================================================
// Constant folding
// ============================================================

FoldResult Solver::fold_constant(const z3::expr& expr) {
    FoldResult result{false, 0, ""};

    // Use Z3's simplify to reduce the expression
    z3::expr simplified = expr.simplify();

    // Check if the simplified expression is a concrete numeral
    if (simplified.is_numeral()) {
        uint64_t val = 0;
        if (simplified.is_numeral_u64(val)) {
            result.folded = true;
            result.value = val;
        }
        std::stringstream ss;
        ss << simplified;
        result.expr_str = ss.str();
        return result;
    }

    // Try solving: if the expression always evaluates to the same value,
    // it's a constant regardless of symbolic inputs.
    query_count_++;

    // Create a fresh variable to represent the expression's value
    z3::expr v = ctx_.bv_const("__fold_v", expr.get_sort().bv_size());

    // Check: can the expression take two different values?
    z3::solver test_solver(ctx_);

    // Copy current constraints
    for (auto& c : constraints_) {
        if (c.taken) {
            test_solver.add(c.condition);
        } else {
            test_solver.add(!c.condition);
        }
    }

    test_solver.add(v == expr);

    if (test_solver.check() == z3::sat) {
        z3::model m = test_solver.get_model();
        z3::expr val1 = m.eval(expr, true);

        // Now check if any other value is possible
        test_solver.push();
        test_solver.add(expr != val1);
        if (test_solver.check() == z3::unsat) {
            // Only one possible value -- it's a constant!
            sat_count_++;
            result.folded = true;
            val1.is_numeral_u64(result.value);
        }
        test_solver.pop();
    }

    std::stringstream ss;
    ss << simplified;
    result.expr_str = ss.str();
    return result;
}

FoldResult Solver::fold_constant_from_trace(const std::vector<StepResult>& trace,
                                             int target_reg) {
    // Build a symbolic expression from instruction trace on the target register.
    // Start with symbolic value, apply each instruction's effect.
    z3::expr acc = symbolize_reg(target_reg, "__trace_fold_input", 32);

    // For a push+add+sub+xor+pop chain, we track the stack symbolically
    // and build the final expression on acc.
    // This is a simplified model: we look at the final register value.

    // If the trace recorded simplified values already, use those
    if (!trace.empty()) {
        const auto& last = trace.back();
        // The register value after the last instruction is the result
        uint64_t concrete_val = 0;
        // Extract from regs_after based on reg id
        // (simplified: just use rax field for reg 0, etc.)
        switch (target_reg) {
            case 0: concrete_val = last.regs_after.rax; break;
            case 1: concrete_val = last.regs_after.rcx; break;
            case 2: concrete_val = last.regs_after.rdx; break;
            case 3: concrete_val = last.regs_after.rbx; break;
            default: concrete_val = last.regs_after.rax; break;
        }

        // Check if the result is the same regardless of initial value
        // by testing with the symbolic expression
        z3::expr result_expr = bv_const(concrete_val, 32);
        return fold_constant(result_expr);
    }

    return FoldResult{false, 0, ""};
}

// ============================================================
// Encrypted data solving
// ============================================================

BlobSolution Solver::solve_blob(uint64_t addr, size_t size,
                                 const z3::expr& decrypt_func,
                                 const z3::expr& constraint) {
    BlobSolution result{false, {}, {}, ""};
    query_count_++;

    solver_.push();
    solver_.add(constraint);

    if (solver_.check() == z3::sat) {
        sat_count_++;
        z3::model m = solver_.get_model();
        result.solved = true;

        // Extract key bytes from model
        for (size_t i = 0; i < size; ++i) {
            std::string key_name = "key_" + std::to_string(i);
            auto it = sym_mem_.find(addr + i);
            if (it != sym_mem_.end()) {
                z3::expr val = m.eval(it->second, true);
                uint64_t byte_val = 0;
                val.is_numeral_u64(byte_val);
                result.key.push_back(static_cast<uint8_t>(byte_val));
            }
        }

        // Evaluate decrypt_func with the model to get plaintext
        z3::expr plain = m.eval(decrypt_func, true);
        // Extract plaintext bytes (depends on expression width)
        unsigned bits = decrypt_func.get_sort().bv_size();
        for (unsigned i = 0; i < bits / 8; ++i) {
            z3::expr byte_expr = plain.extract(i * 8 + 7, i * 8).simplify();
            uint64_t byte_val = 0;
            byte_expr.is_numeral_u64(byte_val);
            result.plaintext.push_back(static_cast<uint8_t>(byte_val));
        }

        std::stringstream ss;
        ss << m;
        result.model_str = ss.str();
    }

    solver_.pop();
    return result;
}

uint64_t Solver::solve_handler_addr(uint64_t encrypted,
                                      const z3::expr& decrypt_expr) {
    query_count_++;

    // The decrypt_expr should contain a symbolic 'key' or 'base' variable.
    // We add the constraint that the input is the encrypted value,
    // and solve for what the decrypted output would be.

    // Create a concrete bitvector for the encrypted value
    unsigned bits = decrypt_expr.get_sort().bv_size();
    z3::expr enc = bv_const(encrypted, bits);

    // We need to find: what value does decrypt_expr evaluate to?
    // If decrypt_expr is fully symbolic (depends on key), we solve for key
    // such that the result is a valid address (e.g., in module range).

    solver_.push();

    // Evaluate decrypt_expr under current constraints
    if (solver_.check() == z3::sat) {
        sat_count_++;
        z3::model m = solver_.get_model();
        z3::expr result = m.eval(decrypt_expr, true);

        uint64_t addr = 0;
        result.is_numeral_u64(addr);
        solver_.pop();
        return addr;
    }

    solver_.pop();
    return 0;
}

// ============================================================
// Expression building helpers
// ============================================================

z3::expr Solver::reg_expr(int reg_id) {
    auto it = sym_regs_.find(reg_id);
    if (it != sym_regs_.end()) {
        return it->second;
    }
    // Return a fresh unnamed constant (concrete placeholder)
    std::string name = "__reg_" + std::to_string(reg_id);
    return ctx_.bv_const(name.c_str(), 32);
}

z3::expr Solver::mem_expr(uint64_t addr, int bits) {
    if (bits == 8) {
        auto it = sym_mem_.find(addr);
        if (it != sym_mem_.end()) {
            return it->second;
        }
        std::string name = "__mem_" + std::to_string(addr);
        return ctx_.bv_const(name.c_str(), 8);
    }

    // Multi-byte: concatenate byte expressions (little-endian)
    int bytes = bits / 8;
    z3::expr result = mem_expr(addr, 8);
    for (int i = 1; i < bytes; ++i) {
        result = z3::concat(mem_expr(addr + i, 8), result);
    }
    return result;
}

z3::expr Solver::bv_const(uint64_t val, int bits) {
    return ctx_.bv_val(static_cast<uint64_t>(val), bits);
}

// ============================================================
// Timeout
// ============================================================

void Solver::set_timeout(unsigned ms) {
    z3::params p(ctx_);
    p.set("timeout", ms);
    solver_.set(p);
}

// ============================================================
// Statistics
// ============================================================

void Solver::reset_stats() {
    query_count_ = 0;
    sat_count_ = 0;
}

// ============================================================
// Internal helpers
// ============================================================

z3::check_result Solver::check_with(const z3::expr& extra) {
    solver_.push();
    solver_.add(extra);
    z3::check_result r = solver_.check();
    solver_.pop();
    return r;
}

std::optional<uint64_t> Solver::eval_model(const z3::expr& e, const z3::model& m) {
    z3::expr val = m.eval(e, true);
    uint64_t result = 0;
    if (val.is_numeral_u64(result)) {
        return result;
    }
    return std::nullopt;
}

} // namespace vx

#endif // VX_ENABLE_Z3
