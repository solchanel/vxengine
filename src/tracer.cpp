/**
 * VXEngine Instruction Tracer
 *
 * Records full CPU state at each instruction step:
 *   - Register snapshots before/after
 *   - Memory reads/writes
 *   - Disassembly text
 *   - Optional Z3 annotations
 */

#include "vxengine/tracer.h"
#include "vxengine/cpu/icpu.h"
#include "vxengine/memory.h"
#ifdef VX_ENABLE_Z3
#include "vxengine/solver.h"
#endif

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace vx {

// ============================================================
// Construction
// ============================================================

Tracer::Tracer(ICpuBackend& cpu)
    : cpu_(cpu)
{
}

#ifdef VX_ENABLE_Z3
void Tracer::attach_solver(Solver* solver) {
    solver_ = solver;
}
#endif

// ============================================================
// Stepping with recording
// ============================================================

TraceEntry Tracer::step() {
    TraceEntry entry = cpu_.step();
    total_traced_++;

#ifdef VX_ENABLE_Z3
    if (solver_) {
        annotate(entry);
    }
#endif

    record(entry);
    return entry;
}

TraceEntry Tracer::step_over() {
    TraceEntry entry = cpu_.step_over();
    total_traced_++;

#ifdef VX_ENABLE_Z3
    if (solver_) {
        annotate(entry);
    }
#endif

    record(entry);
    return entry;
}

std::vector<TraceEntry> Tracer::run_until(uint64_t addr, uint64_t max_insns) {
    std::vector<TraceEntry> result;

    uint64_t count = 0;
    while (cpu_.pc() != addr) {
        if (max_insns > 0 && count >= max_insns) {
            break;
        }

        TraceEntry entry = step();
        result.push_back(std::move(entry));
        count++;

        // Check for stop conditions
        if (result.back().reason == StopReason::EXCEPTION ||
            result.back().reason == StopReason::ERROR ||
            result.back().reason == StopReason::HALT) {
            break;
        }
    }

    return result;
}

std::vector<TraceEntry> Tracer::trace_block() {
    std::vector<TraceEntry> result;

    while (true) {
        // Check if current instruction is a block terminator before stepping
        std::string dis = cpu_.disasm_at_pc();

        TraceEntry entry = step();
        result.push_back(std::move(entry));

        if (is_block_terminator(dis)) {
            break;
        }

        // Also break on stop conditions
        if (result.back().reason == StopReason::BREAKPOINT ||
            result.back().reason == StopReason::SENTINEL_HIT ||
            result.back().reason == StopReason::EXCEPTION ||
            result.back().reason == StopReason::ERROR ||
            result.back().reason == StopReason::HALT) {
            break;
        }
    }

    return result;
}

std::vector<TraceEntry> Tracer::run_filtered(uint64_t addr,
                                              TraceFilter filter,
                                              uint64_t max_insns) {
    std::vector<TraceEntry> result;
    uint64_t count = 0;

    while (cpu_.pc() != addr) {
        if (max_insns > 0 && count >= max_insns) {
            break;
        }

        TraceEntry entry = step();
        count++;

        if (filter(entry)) {
            result.push_back(std::move(entry));
        }

        if (entry.reason == StopReason::EXCEPTION ||
            entry.reason == StopReason::ERROR ||
            entry.reason == StopReason::HALT) {
            break;
        }
    }

    return result;
}

// ============================================================
// Trace buffer management
// ============================================================

void Tracer::set_recording(bool enable) {
    recording_ = enable;
}

void Tracer::clear() {
    trace_.clear();
}

std::vector<TraceEntry> Tracer::last(size_t n) const {
    if (n >= trace_.size()) {
        return trace_;
    }
    return std::vector<TraceEntry>(trace_.end() - n, trace_.end());
}

// ============================================================
// Export
// ============================================================

bool Tracer::export_trace(const std::string& path, TraceFormat format) const {
    return export_trace(trace_, path, format);
}

bool Tracer::export_trace(const std::vector<TraceEntry>& entries,
                           const std::string& path, TraceFormat format) {
    std::ofstream out(path);
    if (!out.is_open()) {
        return false;
    }

    switch (format) {
    case TraceFormat::TEXT: {
        out << "# VXEngine Trace (" << entries.size() << " instructions)\n";
        out << "# ADDR       | SIZE | DISASSEMBLY                      "
               "| ANNOTATIONS\n";
        out << std::string(80, '-') << "\n";
        for (const auto& e : entries) {
            out << format_entry(e) << "\n";
        }
        break;
    }

    case TraceFormat::JSON: {
        out << "[\n";
        for (size_t i = 0; i < entries.size(); ++i) {
            out << "  " << format_entry_json(entries[i]);
            if (i + 1 < entries.size()) out << ",";
            out << "\n";
        }
        out << "]\n";
        break;
    }

    case TraceFormat::IDA_SCRIPT: {
        out << "# VXEngine trace -> IDA Python script\n";
        out << "# Auto-generated. Run in IDA's Python console.\n";
        out << "import idaapi, idc\n\n";

        for (const auto& e : entries) {
            // Color traced instructions
            out << "idaapi.set_item_color(0x" << std::hex << e.addr
                << ", 0xC7FFFF)  # light yellow\n";

            // Add comments for annotations
            if (!e.simplified.empty()) {
                out << "idc.set_cmt(0x" << std::hex << e.addr
                    << ", \"" << e.simplified << "\", 0)\n";
            }
            if (!e.predicate_note.empty()) {
                out << "idc.set_cmt(0x" << std::hex << e.addr
                    << ", \"" << e.predicate_note << "\", 1)\n";
            }
        }
        break;
    }
    } // switch

    return true;
}

std::string Tracer::format_entry(const TraceEntry& entry) {
    std::ostringstream ss;
    ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << entry.addr
       << " | " << std::dec << std::setw(2) << (int)entry.size
       << "   | " << std::left << std::setw(35) << entry.disasm;

    // Memory accesses
    if (!entry.mem_reads.empty()) {
        ss << " R[";
        for (size_t i = 0; i < entry.mem_reads.size(); ++i) {
            if (i > 0) ss << ",";
            ss << "0x" << std::hex << entry.mem_reads[i].addr
               << "=" << entry.mem_reads[i].value;
        }
        ss << "]";
    }
    if (!entry.mem_writes.empty()) {
        ss << " W[";
        for (size_t i = 0; i < entry.mem_writes.size(); ++i) {
            if (i > 0) ss << ",";
            ss << "0x" << std::hex << entry.mem_writes[i].addr
               << "=" << entry.mem_writes[i].value;
        }
        ss << "]";
    }

    // Z3 annotations
    if (!entry.simplified.empty()) {
        ss << " [fold:" << entry.simplified << "]";
    }
    if (!entry.predicate_note.empty()) {
        ss << " [" << entry.predicate_note << "]";
    }

    return ss.str();
}

std::string Tracer::format_entry_json(const TraceEntry& entry) {
    std::ostringstream ss;
    ss << "{\"addr\":\"0x" << std::hex << entry.addr << "\""
       << ",\"size\":" << std::dec << (int)entry.size
       << ",\"disasm\":\"" << entry.disasm << "\""
       << ",\"reason\":" << (int)entry.reason;

    // Register changes (show EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP)
    ss << ",\"regs_before\":{";
    ss << "\"eax\":\"0x" << std::hex << (uint32_t)entry.regs_before.rax << "\""
       << ",\"ecx\":\"0x" << (uint32_t)entry.regs_before.rcx << "\""
       << ",\"edx\":\"0x" << (uint32_t)entry.regs_before.rdx << "\""
       << ",\"ebx\":\"0x" << (uint32_t)entry.regs_before.rbx << "\""
       << ",\"esp\":\"0x" << (uint32_t)entry.regs_before.rsp << "\""
       << ",\"ebp\":\"0x" << (uint32_t)entry.regs_before.rbp << "\""
       << ",\"esi\":\"0x" << (uint32_t)entry.regs_before.rsi << "\""
       << ",\"edi\":\"0x" << (uint32_t)entry.regs_before.rdi << "\""
       << ",\"eip\":\"0x" << (uint32_t)entry.regs_before.rip << "\""
       << "}";

    ss << ",\"regs_after\":{";
    ss << "\"eax\":\"0x" << std::hex << (uint32_t)entry.regs_after.rax << "\""
       << ",\"ecx\":\"0x" << (uint32_t)entry.regs_after.rcx << "\""
       << ",\"edx\":\"0x" << (uint32_t)entry.regs_after.rdx << "\""
       << ",\"ebx\":\"0x" << (uint32_t)entry.regs_after.rbx << "\""
       << ",\"esp\":\"0x" << (uint32_t)entry.regs_after.rsp << "\""
       << ",\"ebp\":\"0x" << (uint32_t)entry.regs_after.rbp << "\""
       << ",\"esi\":\"0x" << (uint32_t)entry.regs_after.rsi << "\""
       << ",\"edi\":\"0x" << (uint32_t)entry.regs_after.rdi << "\""
       << ",\"eip\":\"0x" << (uint32_t)entry.regs_after.rip << "\""
       << "}";

    // Memory accesses
    if (!entry.mem_reads.empty()) {
        ss << ",\"mem_reads\":[";
        for (size_t i = 0; i < entry.mem_reads.size(); ++i) {
            if (i > 0) ss << ",";
            ss << "{\"addr\":\"0x" << std::hex << entry.mem_reads[i].addr
               << "\",\"size\":" << std::dec << entry.mem_reads[i].size
               << ",\"value\":\"0x" << std::hex << entry.mem_reads[i].value << "\"}";
        }
        ss << "]";
    }
    if (!entry.mem_writes.empty()) {
        ss << ",\"mem_writes\":[";
        for (size_t i = 0; i < entry.mem_writes.size(); ++i) {
            if (i > 0) ss << ",";
            ss << "{\"addr\":\"0x" << std::hex << entry.mem_writes[i].addr
               << "\",\"size\":" << std::dec << entry.mem_writes[i].size
               << ",\"value\":\"0x" << std::hex << entry.mem_writes[i].value
               << "\",\"old\":\"0x" << entry.mem_writes[i].old_value << "\"}";
        }
        ss << "]";
    }

    // Z3 annotations
    if (!entry.simplified.empty()) {
        ss << ",\"simplified\":\"" << entry.simplified << "\"";
    }
    if (!entry.predicate_note.empty()) {
        ss << ",\"predicate\":\"" << entry.predicate_note << "\"";
    }

    ss << "}";
    return ss.str();
}

// ============================================================
// Statistics
// ============================================================

void Tracer::reset_stats() {
    total_traced_ = 0;
}

// ============================================================
// Internal helpers
// ============================================================

void Tracer::record(TraceEntry& entry) {
    if (recording_) {
        trace_.push_back(entry);
    }
}

bool Tracer::is_block_terminator(const std::string& disasm) {
    if (disasm.empty()) return true;

    // Extract the mnemonic (first whitespace-delimited token)
    std::string mnemonic;
    for (char c : disasm) {
        if (std::isspace(static_cast<unsigned char>(c))) break;
        mnemonic += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    // Unconditional jumps
    if (mnemonic == "jmp" || mnemonic == "ret" || mnemonic == "retn" ||
        mnemonic == "retf" || mnemonic == "iret" || mnemonic == "iretd") {
        return true;
    }

    // Conditional jumps
    if (mnemonic.size() >= 2 && mnemonic[0] == 'j') {
        return true;  // ja, jb, je, jne, jg, jl, jge, jle, etc.
    }

    // Calls (they start a new block in the callee)
    if (mnemonic == "call") {
        return true;
    }

    // Loop instructions
    if (mnemonic == "loop" || mnemonic == "loope" || mnemonic == "loopne" ||
        mnemonic == "loopz" || mnemonic == "loopnz") {
        return true;
    }

    // INT instructions
    if (mnemonic == "int" || mnemonic == "int3" || mnemonic == "into") {
        return true;
    }

    // HLT
    if (mnemonic == "hlt") {
        return true;
    }

    return false;
}

#ifdef VX_ENABLE_Z3
void Tracer::annotate(TraceEntry& entry) {
    if (!solver_) return;

    // Check if this is a conditional branch and analyze predicate
    std::string mnemonic;
    for (char c : entry.disasm) {
        if (std::isspace(static_cast<unsigned char>(c))) break;
        mnemonic += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    bool is_cond_branch = (mnemonic.size() >= 2 && mnemonic[0] == 'j' &&
                           mnemonic != "jmp");

    if (is_cond_branch) {
        PredicateResult pr = solver_->solve_opaque_predicate(entry.addr);
        switch (pr) {
            case PredicateResult::ALWAYS_TRUE:
                entry.predicate_note = "opaque_true";
                break;
            case PredicateResult::ALWAYS_FALSE:
                entry.predicate_note = "opaque_false";
                break;
            case PredicateResult::INPUT_DEPENDENT:
                entry.predicate_note = "real";
                break;
            case PredicateResult::UNKNOWN:
                entry.predicate_note = "unknown";
                break;
        }
    }
}
#endif

} // namespace vx
