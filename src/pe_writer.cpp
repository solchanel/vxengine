/**
 * VXEngine PE Writer Implementation
 *
 * Builds valid PE files from memory-resident images, with import
 * table reconstruction from sentinel addresses.
 */

#include "pe_writer.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <algorithm>

namespace vx {

// ============================================================
// Constants
// ============================================================

static constexpr uint32_t FILE_ALIGNMENT = 0x200;
static constexpr uint32_t SECTION_ALIGNMENT = 0x1000;

uint32_t PEWriter::align_up(uint32_t value, uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// ============================================================
// Sentinel reference scanning
// ============================================================

std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>
PEWriter::scan_sentinel_refs(VirtualMemory& vmem,
                             const LoadedModule& mod,
                             const PELoader::SentinelMap& sentinels)
{
    std::map<std::string, std::vector<std::pair<std::string, uint64_t>>> imports;

    if (sentinels.empty()) return imports;

    // Determine sentinel range for quick filtering
    uint64_t sentinel_min = sentinels.begin()->first;
    uint64_t sentinel_max = sentinels.rbegin()->first;

    // Scan all sections for DWORD values in sentinel range
    for (const auto& sec : mod.sections) {
        uint64_t va = sec.va;
        uint32_t size = sec.size > 0 ? static_cast<uint32_t>(sec.size)
                                     : static_cast<uint32_t>(sec.raw_size);

        for (uint64_t addr = va; addr + 4 <= va + size; addr += 1) {
            uint32_t val = vmem.read32(addr);
            if (val >= sentinel_min && val <= sentinel_max) {
                auto it = sentinels.find(val);
                if (it != sentinels.end()) {
                    const std::string& dll = it->second.first;
                    const std::string& func = it->second.second;
                    imports[dll].push_back({func, addr});
                }
            }
        }
    }

    // Deduplicate
    for (auto& [dll, funcs] : imports) {
        std::sort(funcs.begin(), funcs.end());
        funcs.erase(std::unique(funcs.begin(), funcs.end()), funcs.end());
    }

    return imports;
}

// ============================================================
// Write PE to disk
// ============================================================

bool PEWriter::write(const std::string& output_path,
                     VirtualMemory& vmem,
                     const LoadedModule& mod,
                     uint64_t oep,
                     const PELoader::SentinelMap& sentinels)
{
    if (mod.sections.empty()) {
        std::cerr << "[vx] PEWriter: No sections in module\n";
        return false;
    }

    uint32_t image_base = static_cast<uint32_t>(mod.base);
    uint32_t entry_rva = oep > 0
        ? static_cast<uint32_t>(oep - mod.base)
        : static_cast<uint32_t>(mod.entry_point - mod.base);

    uint32_t num_sections = static_cast<uint32_t>(mod.sections.size());

    // Calculate headers size
    uint32_t headers_size = align_up(
        0x40 + 0x18 + 0xE0 + num_sections * 0x28,
        FILE_ALIGNMENT);

    // First pass: calculate raw offsets and total file size
    struct SecLayout {
        uint32_t rva;
        uint32_t vsize;
        uint32_t raw_offset;
        uint32_t raw_size;
        std::string name;
    };
    std::vector<SecLayout> layouts;

    uint32_t raw_offset = headers_size;
    for (const auto& sec : mod.sections) {
        SecLayout sl;
        sl.rva = static_cast<uint32_t>(sec.va - mod.base);
        sl.vsize = sec.size > 0 ? static_cast<uint32_t>(sec.size)
                                : static_cast<uint32_t>(sec.raw_size);
        sl.raw_size = align_up(sl.vsize, FILE_ALIGNMENT);
        sl.raw_offset = raw_offset;
        sl.name = sec.name;
        layouts.push_back(sl);
        raw_offset += sl.raw_size;
    }

    uint32_t file_size = raw_offset;

    // Build PE
    std::vector<uint8_t> pe(file_size, 0);

    // DOS header
    pe[0] = 'M'; pe[1] = 'Z';
    uint32_t pe_sig_offset = 0x40;
    std::memcpy(&pe[0x3C], &pe_sig_offset, 4);

    // PE signature
    pe[0x40] = 'P'; pe[0x41] = 'E';

    // COFF header
    uint32_t coff = 0x44;
    uint16_t machine = 0x014C;
    std::memcpy(&pe[coff], &machine, 2);
    uint16_t nsec = static_cast<uint16_t>(num_sections);
    std::memcpy(&pe[coff + 2], &nsec, 2);
    uint16_t opt_hdr_size = 0xE0;
    std::memcpy(&pe[coff + 16], &opt_hdr_size, 2);
    uint16_t chars = 0x0103; // RELOCS_STRIPPED | EXECUTABLE | 32BIT
    std::memcpy(&pe[coff + 18], &chars, 2);

    // Optional header
    uint32_t opt = coff + 20;
    uint16_t magic = 0x010B;
    std::memcpy(&pe[opt], &magic, 2);
    pe[opt + 2] = 14; // MajorLinkerVersion
    std::memcpy(&pe[opt + 16], &entry_rva, 4);
    std::memcpy(&pe[opt + 28], &image_base, 4);
    uint32_t sec_align = SECTION_ALIGNMENT;
    std::memcpy(&pe[opt + 32], &sec_align, 4);
    uint32_t file_align = FILE_ALIGNMENT;
    std::memcpy(&pe[opt + 36], &file_align, 4);

    // OS version
    uint16_t os_major = 6, os_minor = 0;
    std::memcpy(&pe[opt + 40], &os_major, 2);
    std::memcpy(&pe[opt + 42], &os_minor, 2);

    // Subsystem version
    std::memcpy(&pe[opt + 48], &os_major, 2);
    std::memcpy(&pe[opt + 50], &os_minor, 2);

    // SizeOfImage
    uint32_t size_of_image = 0;
    for (const auto& sl : layouts) {
        uint32_t end = sl.rva + align_up(sl.vsize, SECTION_ALIGNMENT);
        if (end > size_of_image) size_of_image = end;
    }
    std::memcpy(&pe[opt + 56], &size_of_image, 4);

    // SizeOfHeaders
    std::memcpy(&pe[opt + 60], &headers_size, 4);

    // Subsystem: GUI=2, Console=3
    uint16_t subsystem = 3;
    std::memcpy(&pe[opt + 68], &subsystem, 2);

    // DllCharacteristics
    uint16_t dll_chars = 0x8160; // NX_COMPAT | DYNAMIC_BASE | TERMINAL_SERVER_AWARE
    std::memcpy(&pe[opt + 70], &dll_chars, 2);

    // Stack/Heap sizes
    uint32_t stack_reserve = 0x100000, stack_commit = 0x1000;
    uint32_t heap_reserve = 0x100000, heap_commit = 0x1000;
    std::memcpy(&pe[opt + 72], &stack_reserve, 4);
    std::memcpy(&pe[opt + 76], &stack_commit, 4);
    std::memcpy(&pe[opt + 80], &heap_reserve, 4);
    std::memcpy(&pe[opt + 84], &heap_commit, 4);

    // NumberOfRvaAndSizes
    uint32_t num_dirs = 16;
    std::memcpy(&pe[opt + 116], &num_dirs, 4);

    // Section headers + data
    uint32_t sec_hdr_base = opt + 0xE0;
    for (size_t i = 0; i < layouts.size(); ++i) {
        const auto& sl = layouts[i];
        uint32_t hdr = sec_hdr_base + static_cast<uint32_t>(i) * 0x28;

        // Name
        size_t name_len = std::min(sl.name.size(), size_t(8));
        std::memcpy(&pe[hdr], sl.name.c_str(), name_len);

        // VirtualSize
        std::memcpy(&pe[hdr + 8], &sl.vsize, 4);

        // VirtualAddress
        std::memcpy(&pe[hdr + 12], &sl.rva, 4);

        // SizeOfRawData
        std::memcpy(&pe[hdr + 16], &sl.raw_size, 4);

        // PointerToRawData
        std::memcpy(&pe[hdr + 20], &sl.raw_offset, 4);

        // Characteristics: RWX
        uint32_t sec_chars = 0xE0000060;
        std::memcpy(&pe[hdr + 36], &sec_chars, 4);

        // Copy section data from virtual memory
        uint64_t va = image_base + sl.rva;
        uint32_t copy_len = std::min(sl.vsize, sl.raw_size);
        if (sl.raw_offset + copy_len <= pe.size()) {
            vmem.read(va, &pe[sl.raw_offset], copy_len);
        }
    }

    // Scan for sentinel references and log them
    auto imports = scan_sentinel_refs(vmem, mod, sentinels);
    if (!imports.empty()) {
        std::cerr << "[vx] PEWriter: Found sentinel references in "
                  << imports.size() << " DLLs:\n";
        for (const auto& [dll, funcs] : imports) {
            std::cerr << "  " << dll << ": " << funcs.size() << " imports\n";
        }
        // Note: full import directory reconstruction is complex.
        // For now, we log the imports and leave sentinel refs in place.
        // The user can use IDA/x64dbg to manually fix up the IAT.
    }

    // Write to file
    std::ofstream ofs(output_path, std::ios::binary);
    if (!ofs) {
        std::cerr << "[vx] PEWriter: Failed to open " << output_path << "\n";
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(pe.data()), pe.size());
    ofs.close();

    std::cerr << "[vx] PEWriter: Wrote " << pe.size() << " bytes to "
              << output_path << " (EP RVA=0x" << std::hex << entry_rva
              << ", base=0x" << image_base << std::dec << ")\n";

    return true;
}

} // namespace vx
