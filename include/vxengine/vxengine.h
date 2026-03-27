#pragma once
/**
 * VXEngine — Virtual Execution Engine for Obfuscated Binary Analysis
 *
 * A general-purpose CPU emulator with:
 *   - Shadow PTE (EPT-style split-view memory for invisible hooks)
 *   - Z3 solver integration (opaque predicate detection, constant folding)
 *   - Full Windows environment (TEB/PEB/GDT/heap)
 *   - Lua (sol2) scripting for plugins and extensibility
 *   - MCP server for AI-driven debugging
 *   - Multi-arch: x86, x64, ARM
 */

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <optional>
#include <variant>

namespace vx {

// ============================================================
// Forward declarations
// ============================================================
class VirtualMemory;
class ICpuBackend;
class PELoader;
class ELFLoader;
class WindowsEnvironment;
class APIDispatcher;
class Tracer;
class VXEngine;

#ifdef VX_ENABLE_Z3
class Solver;
#endif

// ============================================================
// Architecture enum
// ============================================================
enum class Arch : uint8_t {
    X86_32 = 0,
    X86_64 = 1,
    ARM_32 = 2,
    ARM_64 = 3,
};

// ============================================================
// Memory permissions (bitmask)
// ============================================================
enum Perm : uint8_t {
    PERM_NONE  = 0,
    PERM_READ  = 1,
    PERM_WRITE = 2,
    PERM_EXEC  = 4,
    PERM_RW    = PERM_READ | PERM_WRITE,
    PERM_RX    = PERM_READ | PERM_EXEC,
    PERM_RWX   = PERM_READ | PERM_WRITE | PERM_EXEC,
};

// ============================================================
// Memory access types for hooks/watchpoints
// ============================================================
enum class AccessType : uint8_t {
    READ      = 1,
    WRITE     = 2,
    EXEC      = 4,
    READ_WRITE = 3,
    ALL       = 7,
};

// ============================================================
// Register snapshot
// ============================================================
struct RegSnapshot {
    // x86/x64 general purpose
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rip;
    uint32_t eflags;

    // Segment registers
    uint16_t cs, ds, es, fs, gs, ss;

    // FPU
    double st[8];    // x87 FPU stack
    uint16_t fpu_cw; // FPU control word
    uint16_t fpu_sw; // FPU status word
    uint16_t fpu_tw; // FPU tag word
    int fpu_top;     // FPU stack top index

    // SSE
    struct { uint64_t lo, hi; } xmm[16];
};

// ============================================================
// Memory access record (for tracing)
// ============================================================
struct MemAccess {
    uint64_t addr;
    uint32_t size;
    uint64_t value;
    uint64_t old_value;  // for writes
    AccessType type;
};

// ============================================================
// Step/Run result
// ============================================================
enum class StopReason : uint8_t {
    STEP,           // Single step completed
    BREAKPOINT,     // Hit breakpoint
    WATCHPOINT,     // Watchpoint triggered
    ADDRESS_HIT,    // Reached target address
    MAX_INSNS,      // Instruction limit
    EXCEPTION,      // CPU exception (INT3, #GP, #PF, etc.)
    SENTINEL_HIT,   // IAT sentinel (API call)
    ERROR,          // Emulation error
    HALT,           // HLT instruction
};

struct StepResult {
    uint64_t addr;
    uint8_t  size;
    std::string disasm;
    RegSnapshot regs_before;
    RegSnapshot regs_after;
    std::vector<MemAccess> mem_reads;
    std::vector<MemAccess> mem_writes;
    StopReason reason;

    // Z3 annotations (if solver enabled)
    std::string simplified;       // Constant folding result
    std::string predicate_note;   // "opaque_true", "opaque_false", "real"
};

struct RunResult {
    StopReason reason;
    uint64_t stop_addr;
    uint64_t insn_count;
    std::vector<StepResult> trace;  // If tracing enabled
};

// ============================================================
// Hook callback types
// ============================================================
using CodeCallback = std::function<void(uint64_t addr, uint32_t size)>;
using MemCallback  = std::function<bool(uint64_t addr, uint32_t size,
                                        uint64_t value, AccessType type)>;
using HookID = uint32_t;

// ============================================================
// Loaded module info
// ============================================================
struct LoadedModule {
    std::string name;
    std::string path;
    uint64_t base;
    uint64_t size;
    uint64_t entry_point;
    uint64_t image_base;  // Preferred base from PE header

    struct Section {
        std::string name;
        uint64_t va;
        uint64_t size;
        uint64_t raw_size;
        uint8_t perms;
    };
    std::vector<Section> sections;

    struct Import {
        std::string dll;
        std::string func;
        uint64_t iat_addr;       // IAT entry address
        uint64_t sentinel_addr;  // Sentinel redirect target
    };
    std::vector<Import> imports;

    struct Export {
        std::string name;
        uint64_t addr;
        uint16_t ordinal;
    };
    std::vector<Export> exports;
};

// ============================================================
// Page Table Entry (shadow PTE)
// ============================================================
struct PageEntry {
    uint64_t addr;           // Page-aligned virtual address
    uint32_t size = 0x1000;  // Always 4KB
    uint8_t  perms;          // R/W/X permissions

    std::vector<uint8_t> data;       // Current content (exec_view if split)
    std::vector<uint8_t> read_view;  // Alternate read data (for split pages)
    std::vector<uint8_t> original;   // Pristine copy

    bool split = false;      // Is this a split-view page?
    bool cow = false;         // Copy-on-write?
    bool accessed = false;
    bool dirty = false;

    // Fake attributes for VirtualQuery bypass
    uint32_t fake_protect = 0;  // 0 = use real
    uint32_t fake_type = 0;     // 0 = use real
};

// ============================================================
// GDT/LDT entries for segment register support
// ============================================================
struct GDTEntry {
    uint32_t base;
    uint32_t limit;
    uint8_t  access;
    uint8_t  flags;
};

// ============================================================
// Constants
// ============================================================
constexpr uint64_t PAGE_SIZE = 0x1000;
constexpr uint64_t PAGE_MASK = ~(PAGE_SIZE - 1);
constexpr uint64_t SENTINEL_BASE = 0xFEED0000;

} // namespace vx
