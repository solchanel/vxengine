#pragma once
/**
 * VXEngine Auto-Unpacker
 *
 * Detects Original Entry Point (OEP) of packed binaries and dumps
 * the unpacked code as a valid PE file. Uses memory watchpoints to
 * track section writes and heuristics to identify when execution
 * transfers to the unpacked code.
 *
 * OEP detection heuristics:
 *   1. Section write tracking: monitors which sections receive writes
 *   2. Cross-section jump: execution enters a previously-written section
 *   3. UPX tail pattern: POPAD + JMP far
 *   4. Decryption loop + far jump
 */

#include "vxengine/vxengine.h"
#include "vxengine/memory.h"
#include "vxengine/pe_loader.h"
#include "vxengine/cpu/icpu.h"

#include <string>
#include <vector>
#include <set>
#include <map>
#include <cstdint>

namespace vx {

class Unpacker {
public:
    Unpacker(ICpuBackend& cpu, VirtualMemory& vmem, PELoader& loader);

    struct Result {
        bool success = false;
        uint64_t oep = 0;
        std::vector<uint8_t> dumped_pe;
        std::string error;
    };

    /// Install watchpoints on all PE sections to track writes.
    /// Call after loading the packed binary.
    void arm(const LoadedModule& mod);

    /// Called each step during execution.
    /// Returns true when a potential OEP is detected.
    bool check(uint64_t pc);

    /// Get the detected OEP (valid only after check() returns true).
    uint64_t detected_oep() const { return detected_oep_; }

    /// Dump the current memory state as a PE file.
    /// Reads sections from VirtualMemory, rebuilds headers, reconstructs imports.
    Result dump(const std::string& output_path, const LoadedModule& mod);

    /// Whether the unpacker is armed and monitoring.
    bool is_armed() const { return armed_; }

private:
    ICpuBackend& cpu_;
    VirtualMemory& vmem_;
    PELoader& loader_;

    bool armed_ = false;
    uint64_t detected_oep_ = 0;

    // Section tracking
    struct SectionInfo {
        uint64_t va;
        uint64_t size;
        std::string name;
        bool was_written = false;
        bool is_entry_section = false;  // Contains the PE entry point
    };
    std::vector<SectionInfo> sections_;

    // Track which section the PC was in last step
    uint64_t last_pc_ = 0;
    int last_section_idx_ = -1;

    // Watchpoint IDs for cleanup
    std::vector<uint64_t> watchpoint_ids_;

    // Find which section contains an address (-1 if none)
    int find_section(uint64_t addr) const;

    // Reconstruct imports by scanning for sentinel addresses
    std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>
        reconstruct_imports(const LoadedModule& mod);

    // Build a valid PE from memory contents
    std::vector<uint8_t> rebuild_pe(const LoadedModule& mod, uint64_t oep,
        const std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>& imports);
};

} // namespace vx
