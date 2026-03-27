#pragma once
/**
 * VXEngine Exception Handler — SEH/VEH Emulation
 *
 * Many VM protectors (Themida, VMProtect, custom) use exception-driven
 * execution flow where control is transferred via structured/vectored
 * exception handlers instead of normal call/jmp.
 *
 * Patterns supported:
 *   1. INT3 (0xCC) breakpoint exceptions → handler dispatches next VM opcode
 *   2. Access violation (#PF) on guard pages → handler unpacks code
 *   3. Division by zero (INT 0) → handler computes result differently
 *   4. Invalid opcode (#UD) → handler emulates custom instruction
 *   5. Single-step (#DB via TF) → handler advances VM state
 *   6. PUSH SS/POP SS → trap flag suppression with exception fallback
 *   7. Privileged instruction (#GP) → handler fakes kernel result
 *
 * Architecture:
 *   - Maintains a chain of exception handlers (SEH frames on stack)
 *   - Maintains a list of vectored exception handlers (VEH, called first)
 *   - When CPU raises an exception, dispatches through VEH → SEH chain
 *   - Builds EXCEPTION_RECORD + CONTEXT structures on the emulated stack
 *   - Transfers control to the handler function
 *   - Handles EXCEPTION_CONTINUE_EXECUTION and EXCEPTION_CONTINUE_SEARCH
 */

#include "vxengine.h"
#include "memory.h"
#include "cpu/icpu.h"
#include <vector>
#include <functional>

namespace vx {

// ============================================================
// Exception codes (Windows NTSTATUS values)
// ============================================================
enum ExceptionCode : uint32_t {
    EXCEPTION_ACCESS_VIOLATION      = 0xC0000005,
    EXCEPTION_BREAKPOINT            = 0x80000003,
    EXCEPTION_SINGLE_STEP           = 0x80000004,
    EXCEPTION_INT_DIVIDE_BY_ZERO    = 0xC0000094,
    EXCEPTION_INT_OVERFLOW          = 0xC0000095,
    EXCEPTION_PRIV_INSTRUCTION      = 0xC0000096,
    EXCEPTION_ILLEGAL_INSTRUCTION   = 0xC000001D,
    EXCEPTION_STACK_OVERFLOW        = 0xC00000FD,
    EXCEPTION_GUARD_PAGE            = 0x80000001,
    EXCEPTION_FLT_DIVIDE_BY_ZERO    = 0xC000008E,
    EXCEPTION_FLT_INVALID_OPERATION = 0xC0000090,
};

// Handler return dispositions
enum ExceptionDisposition : uint32_t {
    EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF,  // -1: resume at faulting insn
    EXCEPTION_CONTINUE_SEARCH    = 0,            //  0: try next handler
    EXCEPTION_EXECUTE_HANDLER    = 1,            //  1: execute __except block
    EXCEPTION_COLLIDED_UNWIND    = 3,
};

// ============================================================
// Windows exception structures (32-bit, laid out in emulated memory)
// ============================================================
#pragma pack(push, 1)

struct EXCEPTION_RECORD32 {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;        // 0 = continuable, 1 = non-continuable
    uint32_t ExceptionRecord;       // Ptr to chained record (usually 0)
    uint32_t ExceptionAddress;      // Address where exception occurred
    uint32_t NumberParameters;      // 0-15
    uint32_t ExceptionInformation[15];
};

// Minimal CONTEXT32 (x86) — matches Windows CONTEXT layout
struct CONTEXT32 {
    uint32_t ContextFlags;          // 0x10001F = FULL
    // Debug registers
    uint32_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    // Float save (108 bytes, simplified)
    uint8_t  FloatSave[112];
    // Segment registers
    uint32_t SegGs, SegFs, SegEs, SegDs;
    // GP registers
    uint32_t Edi, Esi, Ebx, Edx, Ecx, Eax;
    // Control registers
    uint32_t Ebp, Eip, SegCs, EFlags, Esp, SegSs;
    // Extended (SSE, 512 bytes)
    uint8_t  ExtendedRegisters[512];
};

// SEH registration record (on stack, linked list via fs:[0])
struct EXCEPTION_REGISTRATION32 {
    uint32_t prev;      // Pointer to previous handler (or 0xFFFFFFFF = end)
    uint32_t handler;   // Pointer to handler function
};

// EXCEPTION_POINTERS (passed to VEH/filters)
struct EXCEPTION_POINTERS32 {
    uint32_t ExceptionRecord;   // Ptr to EXCEPTION_RECORD
    uint32_t ContextRecord;     // Ptr to CONTEXT
};

#pragma pack(pop)

// ============================================================
// Vectored Exception Handler entry
// ============================================================
struct VEHEntry {
    uint64_t handler_addr;     // Address of handler function in emulated memory
    bool first;                // Added via AddVectoredExceptionHandler(1, ...) ?
    bool is_continue;          // VCH (vectored continue handler) vs VEH
};

// ============================================================
// Custom exception hook (C++ side, for analysis)
// ============================================================
using ExceptionHook = std::function<ExceptionDisposition(
    ExceptionCode code, uint64_t fault_addr, RegSnapshot& context)>;

// ============================================================
// Exception Handler Manager
// ============================================================
class ExceptionManager {
public:
    ExceptionManager(ICpuBackend& cpu, VirtualMemory& vmem);

    // ===== Configuration =====

    /// Enable/disable exception-driven execution support
    void set_enabled(bool enable) { enabled_ = enable; }
    bool enabled() const { return enabled_; }

    /// Enable logging of all exceptions
    void set_logging(bool enable) { log_exceptions_ = enable; }

    // ===== VEH Management (Vectored Exception Handlers) =====

    /// Register a vectored exception handler (emulated RtlAddVectoredExceptionHandler)
    /// first=true inserts at front of list
    uint64_t add_veh(uint64_t handler_addr, bool first = false);

    /// Remove a vectored exception handler
    bool remove_veh(uint64_t handler_addr);

    /// Register a vectored continue handler
    uint64_t add_vch(uint64_t handler_addr, bool first = false);

    /// Remove a vectored continue handler
    bool remove_vch(uint64_t handler_addr);

    // ===== SEH Management (Structured Exception Handling) =====

    /// Read the SEH chain from fs:[0] (walks the linked list on stack)
    std::vector<EXCEPTION_REGISTRATION32> read_seh_chain() const;

    /// Push a new SEH frame (called when code does: mov [fs:0], esp)
    void push_seh_frame(uint64_t handler_addr, uint64_t prev = 0xFFFFFFFF);

    /// Pop the top SEH frame
    void pop_seh_frame();

    // ===== Exception Dispatch =====

    /// Main entry point: raise an exception and dispatch through VEH → SEH
    /// Returns true if exception was handled (execution can continue)
    /// Returns false if unhandled (should terminate)
    bool dispatch_exception(ExceptionCode code, uint64_t fault_addr,
                           uint32_t num_params = 0,
                           const uint32_t* params = nullptr);

    /// Raise specific exception types (convenience)
    bool raise_access_violation(uint64_t addr, bool is_write);
    bool raise_breakpoint(uint64_t addr);
    bool raise_single_step(uint64_t addr);
    bool raise_divide_by_zero(uint64_t addr);
    bool raise_illegal_instruction(uint64_t addr);
    bool raise_privileged_instruction(uint64_t addr);
    bool raise_guard_page(uint64_t addr);

    // ===== C++ Exception Hooks (for analysis/interception) =====

    /// Register a C++ hook that fires BEFORE the emulated handlers
    /// Can handle the exception directly without involving emulated SEH/VEH
    HookID add_exception_hook(ExceptionCode code, ExceptionHook hook);
    HookID add_exception_hook_all(ExceptionHook hook);  // All exceptions
    void remove_exception_hook(HookID id);

    // ===== Statistics =====

    struct ExceptionStats {
        uint64_t total_exceptions = 0;
        uint64_t handled_by_veh = 0;
        uint64_t handled_by_seh = 0;
        uint64_t handled_by_hook = 0;
        uint64_t unhandled = 0;
        std::map<ExceptionCode, uint64_t> by_code;
    };

    const ExceptionStats& stats() const { return stats_; }
    void reset_stats() { stats_ = {}; }

    // ===== Exception Log =====

    struct ExceptionLogEntry {
        ExceptionCode code;
        uint64_t address;
        uint64_t handler_addr;  // Which handler caught it (0 if unhandled)
        std::string handler_type; // "veh", "seh", "hook", "unhandled"
        RegSnapshot context;
    };

    const std::vector<ExceptionLogEntry>& exception_log() const { return exception_log_; }
    void clear_log() { exception_log_.clear(); }

private:
    ICpuBackend& cpu_;
    VirtualMemory& vmem_;
    bool enabled_ = true;
    bool log_exceptions_ = false;

    // VEH/VCH lists
    std::vector<VEHEntry> veh_list_;
    std::vector<VEHEntry> vch_list_;

    // C++ hooks
    struct HookEntry {
        ExceptionCode code;
        ExceptionHook hook;
        bool all_codes;
    };
    std::map<HookID, HookEntry> hooks_;
    HookID next_hook_id_ = 1;

    // Statistics and logging
    ExceptionStats stats_;
    std::vector<ExceptionLogEntry> exception_log_;

    // ===== Internal dispatch =====

    /// Build EXCEPTION_RECORD and CONTEXT in emulated memory
    uint64_t build_exception_record(ExceptionCode code, uint64_t addr,
                                     uint32_t num_params, const uint32_t* params);
    uint64_t build_context(RegSnapshot& snap);

    /// Restore CPU state from a CONTEXT32 in emulated memory
    void restore_context(uint64_t context_addr);

    /// Dispatch through C++ hooks first
    ExceptionDisposition dispatch_hooks(ExceptionCode code, uint64_t addr,
                                         RegSnapshot& ctx);

    /// Dispatch through VEH chain
    ExceptionDisposition dispatch_veh(uint64_t exception_ptrs_addr);

    /// Dispatch through SEH chain (walks fs:[0] linked list)
    ExceptionDisposition dispatch_seh(uint64_t exception_record_addr,
                                       uint64_t context_addr);

    /// Call a single handler function in emulated code
    /// Sets up stack frame, transfers control, runs until handler returns
    ExceptionDisposition call_handler(uint64_t handler_addr,
                                       uint64_t exception_record_addr,
                                       uint64_t context_addr,
                                       bool is_veh);
};

} // namespace vx
