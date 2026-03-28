/**
 * VXEngine Auto-Unpacker Implementation
 *
 * Monitors section writes during execution and detects when the program
 * transfers control to unpacked code. Dumps the result as a valid PE.
 */

#include "unpacker.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace vx {

// ============================================================
// PE structure constants for rebuilding
// ============================================================

static constexpr uint32_t PE_FILE_ALIGNMENT = 0x200;
static constexpr uint32_t PE_SECTION_ALIGNMENT = 0x1000;

static uint32_t align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================
// Construction
// ============================================================

Unpacker::Unpacker(ICpuBackend& cpu, VirtualMemory& vmem, PELoader& loader)
    : cpu_(cpu), vmem_(vmem), loader_(loader)
{
}

// ============================================================
// Arming — install watchpoints on sections
// ============================================================

void Unpacker::arm(const LoadedModule& mod) {
    sections_.clear();
    watchpoint_ids_.clear();
    detected_oep_ = 0;
    armed_ = false;

    if (mod.sections.empty()) {
        std::cerr << "[vx] Unpacker: No sections found in module\n";
        return;
    }

    // Build section info
    for (const auto& sec : mod.sections) {
        SectionInfo si;
        si.va = sec.va;
        si.size = sec.size > 0 ? sec.size : sec.raw_size;
        si.name = sec.name;
        si.was_written = false;
        si.is_entry_section = (mod.entry_point >= si.va &&
                               mod.entry_point < si.va + si.size);
        sections_.push_back(si);
    }

    // Install write watchpoints on each section
    for (size_t i = 0; i < sections_.size(); ++i) {
        auto& sec = sections_[i];
        size_t idx = i;

        auto wid = vmem_.add_watchpoint(sec.va, sec.size,
            [this, idx](uint64_t addr, uint32_t size, uint64_t value,
                        AccessType type) -> bool {
                if (type == AccessType::WRITE && idx < sections_.size()) {
                    sections_[idx].was_written = true;
                }
                return true; // Continue execution
            }, AccessType::WRITE);

        watchpoint_ids_.push_back(wid);
    }

    last_pc_ = cpu_.pc();
    last_section_idx_ = find_section(last_pc_);
    armed_ = true;

    std::cerr << "[vx] Unpacker armed: monitoring " << sections_.size()
              << " sections for OEP detection\n";
}

// ============================================================
// OEP detection — called each step
// ============================================================

bool Unpacker::check(uint64_t pc) {
    if (!armed_) return false;

    int current_section = find_section(pc);

    // Heuristic 1: Execution enters a section that was written to,
    // from a different section (cross-section jump to unpacked code)
    if (current_section >= 0 && current_section != last_section_idx_) {
        auto& sec = sections_[current_section];
        if (sec.was_written && !sec.is_entry_section) {
            detected_oep_ = pc;
            armed_ = false;
            std::cerr << "[vx] OEP detected at 0x" << std::hex << pc
                      << " (cross-section jump to written section '"
                      << sec.name << "')\n" << std::dec;
            return true;
        }
    }

    // Heuristic 2: Execution enters a written section that IS the entry
    // section, but from a non-entry section (packer finished, jumping back)
    if (current_section >= 0 && last_section_idx_ >= 0 &&
        current_section != last_section_idx_) {
        auto& cur = sections_[current_section];
        auto& prev = sections_[last_section_idx_];
        if (cur.is_entry_section && cur.was_written && prev.was_written) {
            detected_oep_ = pc;
            armed_ = false;
            std::cerr << "[vx] OEP detected at 0x" << std::hex << pc
                      << " (return to entry section after unpacking)\n" << std::dec;
            return true;
        }
    }

    last_pc_ = pc;
    last_section_idx_ = current_section;
    return false;
}

// ============================================================
// Section lookup
// ============================================================

int Unpacker::find_section(uint64_t addr) const {
    for (size_t i = 0; i < sections_.size(); ++i) {
        if (addr >= sections_[i].va &&
            addr < sections_[i].va + sections_[i].size) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

// ============================================================
// Import reconstruction
// ============================================================

std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>
Unpacker::reconstruct_imports(const LoadedModule& mod) {
    std::map<std::string, std::vector<std::pair<std::string, uint64_t>>> imports;

    const auto& sentinel_map = loader_.sentinel_map();
    if (sentinel_map.empty()) return imports;

    // Scan all sections for DWORD values that fall in the sentinel range
    for (const auto& sec : sections_) {
        for (uint64_t addr = sec.va; addr + 4 <= sec.va + sec.size; addr += 4) {
            uint32_t val = vmem_.read32(addr);
            auto it = sentinel_map.find(val);
            if (it != sentinel_map.end()) {
                const std::string& dll = it->second.first;
                const std::string& func = it->second.second;
                imports[dll].push_back({func, addr});
            }
        }
    }

    return imports;
}

// ============================================================
// PE rebuilding
// ============================================================

std::vector<uint8_t> Unpacker::rebuild_pe(const LoadedModule& mod, uint64_t oep,
    const std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>& imports)
{
    // Calculate sizes
    uint32_t num_sections = static_cast<uint32_t>(mod.sections.size());
    uint32_t headers_size = align_up(
        0x40 +    // DOS header
        0x18 +    // PE signature + COFF header
        0xE0 +    // Optional header (PE32)
        num_sections * 0x28,  // Section headers
        PE_FILE_ALIGNMENT);

    // Calculate total file size
    uint32_t file_size = headers_size;
    for (const auto& sec : mod.sections) {
        uint32_t vsize = sec.size > 0 ? static_cast<uint32_t>(sec.size)
                                      : static_cast<uint32_t>(sec.raw_size);
        uint32_t raw_size = align_up(vsize, PE_FILE_ALIGNMENT);
        file_size += raw_size;
    }

    std::vector<uint8_t> pe(file_size, 0);

    // DOS header
    pe[0] = 'M'; pe[1] = 'Z';
    // e_lfanew at offset 0x3C
    uint32_t pe_offset = 0x40;
    std::memcpy(&pe[0x3C], &pe_offset, 4);

    // PE signature
    pe[pe_offset] = 'P'; pe[pe_offset + 1] = 'E';

    // COFF header (offset pe_offset + 4)
    uint32_t coff = pe_offset + 4;
    uint16_t machine = 0x014C; // IMAGE_FILE_MACHINE_I386
    std::memcpy(&pe[coff + 0], &machine, 2);
    uint16_t nsections = static_cast<uint16_t>(num_sections);
    std::memcpy(&pe[coff + 2], &nsections, 2);
    uint16_t opt_size = 0xE0;
    std::memcpy(&pe[coff + 16], &opt_size, 2);
    uint16_t characteristics = 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE
    std::memcpy(&pe[coff + 18], &characteristics, 2);

    // Optional header (PE32)
    uint32_t opt = coff + 20;
    uint16_t magic = 0x010B; // PE32
    std::memcpy(&pe[opt + 0], &magic, 2);

    // Entry point RVA
    uint32_t ep_rva = static_cast<uint32_t>(oep - mod.base);
    std::memcpy(&pe[opt + 16], &ep_rva, 4);

    // ImageBase
    uint32_t image_base = static_cast<uint32_t>(mod.base);
    std::memcpy(&pe[opt + 28], &image_base, 4);

    // Section alignment
    uint32_t sec_align = PE_SECTION_ALIGNMENT;
    std::memcpy(&pe[opt + 32], &sec_align, 4);

    // File alignment
    uint32_t file_align = PE_FILE_ALIGNMENT;
    std::memcpy(&pe[opt + 36], &file_align, 4);

    // SizeOfImage
    uint32_t last_va = 0;
    for (const auto& sec : mod.sections) {
        uint32_t sec_rva = static_cast<uint32_t>(sec.va - mod.base);
        uint32_t vsize = sec.size > 0 ? static_cast<uint32_t>(sec.size)
                                      : static_cast<uint32_t>(sec.raw_size);
        uint32_t end = sec_rva + align_up(vsize, PE_SECTION_ALIGNMENT);
        if (end > last_va) last_va = end;
    }
    std::memcpy(&pe[opt + 56], &last_va, 4);

    // SizeOfHeaders
    std::memcpy(&pe[opt + 60], &headers_size, 4);

    // NumberOfRvaAndSizes
    uint32_t num_dirs = 16;
    std::memcpy(&pe[opt + 116], &num_dirs, 4);

    // Section headers
    uint32_t sec_hdr = opt + 0xE0;
    uint32_t raw_offset = headers_size;

    for (size_t i = 0; i < mod.sections.size(); ++i) {
        const auto& sec = mod.sections[i];
        uint32_t hdr = sec_hdr + static_cast<uint32_t>(i) * 0x28;

        // Name (8 bytes)
        size_t name_len = std::min(sec.name.size(), size_t(8));
        std::memcpy(&pe[hdr], sec.name.c_str(), name_len);

        // VirtualSize
        uint32_t vsize = sec.size > 0 ? static_cast<uint32_t>(sec.size)
                                      : static_cast<uint32_t>(sec.raw_size);
        std::memcpy(&pe[hdr + 8], &vsize, 4);

        // VirtualAddress (RVA)
        uint32_t rva = static_cast<uint32_t>(sec.va - mod.base);
        std::memcpy(&pe[hdr + 12], &rva, 4);

        // SizeOfRawData
        uint32_t raw_size = align_up(vsize, PE_FILE_ALIGNMENT);
        std::memcpy(&pe[hdr + 16], &raw_size, 4);

        // PointerToRawData
        std::memcpy(&pe[hdr + 20], &raw_offset, 4);

        // Characteristics
        uint32_t chars = 0xE0000060; // CODE | INITIALIZED_DATA | MEM_READ | MEM_WRITE | MEM_EXECUTE
        std::memcpy(&pe[hdr + 36], &chars, 4);

        // Copy section data from virtual memory
        uint32_t copy_size = std::min(vsize, raw_size);
        if (raw_offset + copy_size <= pe.size()) {
            vmem_.read(sec.va, &pe[raw_offset], copy_size);
        }

        raw_offset += raw_size;
    }

    return pe;
}

// ============================================================
// Dump
// ============================================================

Unpacker::Result Unpacker::dump(const std::string& output_path, const LoadedModule& mod) {
    Result result;

    uint64_t oep = detected_oep_;
    if (oep == 0) {
        result.error = "No OEP detected yet";
        return result;
    }

    // Reconstruct imports
    auto imports = reconstruct_imports(mod);
    std::cerr << "[vx] Reconstructed imports from " << imports.size() << " DLLs\n";
    for (const auto& [dll, funcs] : imports) {
        std::cerr << "  " << dll << ": " << funcs.size() << " functions\n";
    }

    // Rebuild PE
    result.dumped_pe = rebuild_pe(mod, oep, imports);
    result.oep = oep;

    // Write to file
    std::ofstream ofs(output_path, std::ios::binary);
    if (!ofs) {
        result.error = "Failed to open output file: " + output_path;
        return result;
    }

    ofs.write(reinterpret_cast<const char*>(result.dumped_pe.data()),
              result.dumped_pe.size());
    ofs.close();

    result.success = true;
    std::cerr << "[vx] Dumped " << result.dumped_pe.size() << " bytes to "
              << output_path << " (OEP=0x" << std::hex << oep << std::dec << ")\n";

    return result;
}

} // namespace vx
