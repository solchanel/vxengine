#pragma once
/**
 * VXEngine Instruction Tracer
 *
 * Wraps CPU stepping with full state recording:
 *   - Register snapshots before/after each instruction
 *   - Memory read/write tracking
 *   - Basic block detection
 *   - Export to text, JSON, or IDA Python script format
 *   - Z3 annotations (simplified expressions, opaque predicate notes)
 */

#include "vxengine.h"
#include <string>
#include <vector>
#include <functional>

namespace vx {

// Forward declarations
class ICpuBackend;
class VirtualMemory;
#ifdef VX_ENABLE_Z3
class Solver;
#endif

/// Trace export format
enum class TraceFormat : uint8_t {
    TEXT,       // Human-readable text
    JSON,       // JSON array
    IDA_SCRIPT, // IDA Python script (SetColor, MakeComm)
};

/// A single trace entry (alias for StepResult with guaranteed fields)
using TraceEntry = StepResult;

/// Filter callback: return true to include the entry in the trace
using TraceFilter = std::function<bool(const TraceEntry& entry)>;

class Tracer {
public:
    /// Construct a tracer attached to a CPU backend
    explicit Tracer(ICpuBackend& cpu);
    ~Tracer() = default;

    Tracer(const Tracer&) = delete;
    Tracer& operator=(const Tracer&) = delete;

#ifdef VX_ENABLE_Z3
    /// Attach a Z3 solver for annotation (opaque predicate, constant folding)
    void attach_solver(Solver* solver);
#endif

    // ===== Stepping with recording =====

    /// Single-step one instruction with full state capture.
    /// Records regs before/after, memory reads/writes.
    /// If Z3 solver attached, annotates with simplified/predicate_note.
    TraceEntry step();

    /// Step over calls: if current instruction is CALL, run_until return addr
    TraceEntry step_over();

    /// Run until a specific address, recording every step.
    /// @param addr      Target address to stop at
    /// @param max_insns Safety limit (0 = no limit)
    /// @return          Full trace of all executed instructions
    std::vector<TraceEntry> run_until(uint64_t addr, uint64_t max_insns = 100000);

    /// Trace one basic block (up to next branch/call/ret).
    /// @return Trace entries for the block
    std::vector<TraceEntry> trace_block();

    /// Run with a filter: only keep entries matching the filter
    std::vector<TraceEntry> run_filtered(uint64_t addr,
                                          TraceFilter filter,
                                          uint64_t max_insns = 100000);

    // ===== Trace buffer management =====

    /// Enable/disable automatic recording into the internal buffer
    void set_recording(bool enable);
    bool is_recording() const { return recording_; }

    /// Get the recorded trace buffer
    const std::vector<TraceEntry>& trace() const { return trace_; }

    /// Clear the trace buffer
    void clear();

    /// Get the last N entries
    std::vector<TraceEntry> last(size_t n) const;

    // ===== Export =====

    /// Export the current trace buffer to a file
    bool export_trace(const std::string& path, TraceFormat format) const;

    /// Export a specific trace to a file
    static bool export_trace(const std::vector<TraceEntry>& entries,
                             const std::string& path, TraceFormat format);

    /// Format a single entry as text
    static std::string format_entry(const TraceEntry& entry);

    /// Format a single entry as JSON object string
    static std::string format_entry_json(const TraceEntry& entry);

    // ===== Statistics =====

    /// Total instructions traced since construction (or last reset)
    uint64_t total_traced() const { return total_traced_; }

    /// Reset statistics
    void reset_stats();

private:
    ICpuBackend& cpu_;
    std::vector<TraceEntry> trace_;
    bool recording_ = true;
    uint64_t total_traced_ = 0;

#ifdef VX_ENABLE_Z3
    Solver* solver_ = nullptr;

    /// Annotate a trace entry with Z3 solver results
    void annotate(TraceEntry& entry);
#endif

    /// Record an entry (add to buffer if recording enabled)
    void record(TraceEntry& entry);

    /// Detect if instruction is a branch/call/ret (block terminator)
    static bool is_block_terminator(const std::string& disasm);
};

} // namespace vx
