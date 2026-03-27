#pragma once
/**
 * VXEngine Z3 SMT Solver Integration
 *
 * Concolic execution and deobfuscation:
 *   - Symbolic register and memory tracking
 *   - Path constraint recording at branches
 *   - Opaque predicate detection (always-true/false vs input-dependent)
 *   - Constant folding for obfuscated computations
 *   - Encrypted blob solving (unknown key recovery)
 *   - Handler table entry decryption
 */

#ifdef VX_ENABLE_Z3

#include "vxengine.h"
#include <z3++.h>
#include <string>
#include <vector>
#include <unordered_map>

namespace vx {

// Forward declarations
class VirtualMemory;
class ICpuBackend;

/// Result of opaque predicate analysis
enum class PredicateResult : uint8_t {
    ALWAYS_TRUE,     // Branch is always taken (opaque predicate)
    ALWAYS_FALSE,    // Branch is never taken (opaque predicate)
    INPUT_DEPENDENT, // Branch depends on symbolic input (real conditional)
    UNKNOWN,         // Solver timeout or error
};

/// A recorded path constraint from a conditional branch
struct PathConstraint {
    uint64_t addr;        // Address of the branch instruction
    z3::expr condition;   // The symbolic condition expression
    bool taken;           // Whether the branch was actually taken
};

/// Result of constant folding
struct FoldResult {
    bool folded;           // Whether folding succeeded
    uint64_t value;        // The concrete constant value
    std::string expr_str;  // Human-readable simplified expression
};

/// Result of blob solving
struct BlobSolution {
    bool solved;
    std::vector<uint8_t> key;         // Recovered key bytes
    std::vector<uint8_t> plaintext;   // Decrypted data
    std::string model_str;            // Z3 model as string
};

class Solver {
public:
    explicit Solver();
    ~Solver();

    Solver(const Solver&) = delete;
    Solver& operator=(const Solver&) = delete;

    // ===== Symbolic variable creation =====

    /// Mark a CPU register as symbolic (creates a BitVec variable)
    z3::expr symbolize_reg(int reg_id, const std::string& name, int bits = 32);

    /// Mark a memory range as symbolic (one BitVec per byte)
    std::vector<z3::expr> symbolize_mem(uint64_t addr, size_t size,
                                         const std::string& name);

    /// Create a free symbolic BitVec variable
    z3::expr make_symbol(const std::string& name, int bits);

    // ===== Path constraint management =====

    /// Record a path constraint at a conditional branch
    void on_branch(uint64_t addr, const z3::expr& condition, bool taken);

    /// Get all recorded path constraints
    const std::vector<PathConstraint>& path_constraints() const;

    /// Clear all path constraints
    void clear_constraints();

    /// Push solver state (for backtracking)
    void push();

    /// Pop solver state
    void pop();

    // ===== Opaque predicate detection =====

    /// Analyze a branch condition to determine if it's an opaque predicate.
    /// Tests satisfiability of both condition and !condition under current
    /// path constraints.
    PredicateResult solve_opaque_predicate(const z3::expr& condition);

    /// Convenience: analyze branch at address using recorded condition
    PredicateResult solve_opaque_predicate(uint64_t addr);

    // ===== Constant folding =====

    /// Attempt to simplify an obfuscated constant computation.
    /// Handles patterns like push+add+pop+sub+xor chains that produce
    /// a constant result regardless of input.
    FoldResult fold_constant(const z3::expr& expr);

    /// Fold from a sequence of instruction effects on a register
    FoldResult fold_constant_from_trace(const std::vector<StepResult>& trace,
                                        int target_reg);

    // ===== Encrypted data solving =====

    /// Solve for unknown key to decrypt an encrypted data blob.
    /// @param addr         Address of encrypted data in virtual memory
    /// @param size         Size of encrypted data
    /// @param decrypt_func Symbolic expression representing the decryption function
    /// @param constraint   Constraint the plaintext must satisfy
    BlobSolution solve_blob(uint64_t addr, size_t size,
                            const z3::expr& decrypt_func,
                            const z3::expr& constraint);

    /// Solve for the decrypted value of an encrypted handler table entry.
    /// @param encrypted    The encrypted entry value
    /// @param decrypt_expr Symbolic decryption expression (e.g., encrypted ^ key + base)
    /// @return             Solved handler address, or 0 on failure
    uint64_t solve_handler_addr(uint64_t encrypted,
                                 const z3::expr& decrypt_expr);

    // ===== Expression building helpers =====

    /// Build a Z3 expression representing a register value
    z3::expr reg_expr(int reg_id);

    /// Build a Z3 expression representing a memory read
    z3::expr mem_expr(uint64_t addr, int bits);

    /// Concrete value as Z3 bitvector
    z3::expr bv_const(uint64_t val, int bits);

    /// Get the Z3 context (for advanced usage)
    z3::context& ctx() { return ctx_; }

    // ===== Timeout =====

    /// Set solver timeout in milliseconds
    void set_timeout(unsigned ms);

    // ===== Statistics =====

    /// Number of solver queries made
    uint64_t query_count() const { return query_count_; }

    /// Number of satisfiable results
    uint64_t sat_count() const { return sat_count_; }

    /// Reset statistics
    void reset_stats();

private:
    z3::context ctx_;
    z3::solver solver_;

    /// Symbolic register map: reg_id -> z3 expression
    std::unordered_map<int, z3::expr> sym_regs_;

    /// Symbolic memory map: byte_addr -> z3 expression (8-bit)
    std::unordered_map<uint64_t, z3::expr> sym_mem_;

    /// Recorded path constraints
    std::vector<PathConstraint> constraints_;

    /// Branch condition cache: addr -> last condition
    std::unordered_map<uint64_t, z3::expr> branch_cache_;

    /// Statistics
    uint64_t query_count_ = 0;
    uint64_t sat_count_ = 0;

    /// Check satisfiability with current constraints plus extras
    z3::check_result check_with(const z3::expr& extra);

    /// Get model value for an expression (after sat check)
    std::optional<uint64_t> eval_model(const z3::expr& e, const z3::model& m);
};

} // namespace vx

#endif // VX_ENABLE_Z3
