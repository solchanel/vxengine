/**
 * VXEngine ELF32 Loader — Implementation
 *
 * Minimal ELF loader for ARM Linux and x86 Linux binaries.
 * This file contains:
 *   - ELF header validation (magic, EI_CLASS=32, EM_ARM/EM_386)
 *   - PT_LOAD segment mapping with correct permissions
 *   - Section header parsing for section info
 *   - Dynamic section parsing for imports (DT_NEEDED, DT_SYMTAB, DT_STRTAB)
 *   - Entry point extraction and LoadedModule construction
 */

#include "vxengine/elf_loader.h"
#include <fstream>
#include <algorithm>
#include <stdexcept>

namespace vx {

// ============================================================
// Constructor
// ============================================================

ELFLoader::ELFLoader(VirtualMemory& vmem)
    : vmem_(vmem)
{
}

// ============================================================
// Utility helpers
// ============================================================

uint8_t ELFLoader::phdr_perms(uint32_t flags) {
    uint8_t perms = PERM_NONE;
    if (flags & PF_R) perms |= PERM_READ;
    if (flags & PF_W) perms |= PERM_WRITE;
    if (flags & PF_X) perms |= PERM_EXEC;
    return perms;
}

std::string ELFLoader::read_string_at(const uint8_t* strtab, size_t strtab_size, uint32_t offset) {
    if (offset >= strtab_size) return "";
    const char* str = reinterpret_cast<const char*>(strtab + offset);
    size_t max_len = strtab_size - offset;
    size_t len = strnlen(str, max_len);
    return std::string(str, len);
}

// ============================================================
// Header validation
// ============================================================

bool ELFLoader::validate_header(const uint8_t* data, size_t size) const {
    if (size < sizeof(Elf32_Ehdr)) return false;

    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);

    // Check ELF magic
    if (ehdr->e_ident[0] != ELFMAG0 || ehdr->e_ident[1] != ELFMAG1 ||
        ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3) {
        return false;
    }

    // Must be 32-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) return false;

    // Must be little-endian (ARM LE or x86)
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) return false;

    // Must be executable or shared object
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) return false;

    // Must be ARM or x86
    if (ehdr->e_machine != EM_ARM && ehdr->e_machine != EM_386) return false;

    // Validate program header table
    if (ehdr->e_phoff == 0 || ehdr->e_phnum == 0) return false;
    if (ehdr->e_phoff + static_cast<size_t>(ehdr->e_phnum) * ehdr->e_phentsize > size) {
        return false;
    }

    return true;
}

// ============================================================
// Map PT_LOAD segments
// ============================================================

bool ELFLoader::map_segments(const uint8_t* data, size_t size,
                              uint64_t base, const Elf32_Ehdr& ehdr,
                              LoadedModule& mod) {
    const uint8_t* ph_base = data + ehdr.e_phoff;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const auto* phdr = reinterpret_cast<const Elf32_Phdr*>(
            ph_base + i * ehdr.e_phentsize);

        if (phdr->p_type != PT_LOAD) continue;

        // Compute page-aligned addresses
        uint64_t seg_vaddr = base + phdr->p_vaddr;
        uint64_t seg_start = seg_vaddr & PAGE_MASK;
        uint64_t seg_end   = (seg_vaddr + phdr->p_memsz + PAGE_SIZE - 1) & PAGE_MASK;
        uint64_t map_size  = seg_end - seg_start;

        uint8_t perms = phdr_perms(phdr->p_flags);

        // Map the region
        if (!vmem_.map(seg_start, map_size, perms)) {
            // Region may already be mapped (overlapping segments)
            // Try to just update permissions
            vmem_.protect(seg_start, map_size, perms);
        }

        // Copy file data into the segment
        if (phdr->p_filesz > 0) {
            if (phdr->p_offset + phdr->p_filesz > size) return false;
            vmem_.write(seg_vaddr, data + phdr->p_offset, phdr->p_filesz);
        }

        // Zero-fill BSS portion (memsz > filesz)
        if (phdr->p_memsz > phdr->p_filesz) {
            uint64_t bss_start = seg_vaddr + phdr->p_filesz;
            uint64_t bss_size  = phdr->p_memsz - phdr->p_filesz;
            vmem_.memset(bss_start, 0, static_cast<size_t>(bss_size));
        }

        // Update module size to encompass all segments
        uint64_t seg_top = seg_vaddr + phdr->p_memsz;
        if (seg_top > mod.base + mod.size) {
            mod.size = seg_top - mod.base;
        }
    }

    return true;
}

// ============================================================
// Parse section headers for section info
// ============================================================

bool ELFLoader::parse_sections(const uint8_t* data, size_t size,
                                uint64_t base, const Elf32_Ehdr& ehdr,
                                LoadedModule& mod) {
    if (ehdr.e_shoff == 0 || ehdr.e_shnum == 0) return true;  // No sections is OK

    if (ehdr.e_shoff + static_cast<size_t>(ehdr.e_shnum) * ehdr.e_shentsize > size) {
        return false;
    }

    const uint8_t* sh_base = data + ehdr.e_shoff;

    // Get section name string table
    const uint8_t* shstrtab = nullptr;
    size_t shstrtab_size = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const auto* shstr_hdr = reinterpret_cast<const Elf32_Shdr*>(
            sh_base + ehdr.e_shstrndx * ehdr.e_shentsize);
        if (shstr_hdr->sh_offset + shstr_hdr->sh_size <= size) {
            shstrtab = data + shstr_hdr->sh_offset;
            shstrtab_size = shstr_hdr->sh_size;
        }
    }

    for (uint16_t i = 0; i < ehdr.e_shnum; i++) {
        const auto* shdr = reinterpret_cast<const Elf32_Shdr*>(
            sh_base + i * ehdr.e_shentsize);

        if (shdr->sh_type == SHT_NULL) continue;
        if (!(shdr->sh_flags & SHF_ALLOC)) continue;  // Only map allocated sections

        LoadedModule::Section sec;
        if (shstrtab) {
            sec.name = read_string_at(shstrtab, shstrtab_size, shdr->sh_name);
        }
        sec.va       = base + shdr->sh_addr;
        sec.size     = shdr->sh_size;
        sec.raw_size = (shdr->sh_type == SHT_NOBITS) ? 0 : shdr->sh_size;

        // Compute permissions from section flags
        uint8_t perms = PERM_NONE;
        if (shdr->sh_flags & SHF_ALLOC)     perms |= PERM_READ;
        if (shdr->sh_flags & SHF_WRITE)     perms |= PERM_WRITE;
        if (shdr->sh_flags & SHF_EXECINSTR) perms |= PERM_EXEC;
        sec.perms = perms;

        mod.sections.push_back(std::move(sec));
    }

    return true;
}

// ============================================================
// Parse dynamic section for imports
// ============================================================

bool ELFLoader::parse_dynamic(const uint8_t* data, size_t size,
                               uint64_t base, const Elf32_Ehdr& ehdr,
                               LoadedModule& mod) {
    const uint8_t* ph_base = data + ehdr.e_phoff;

    // Find PT_DYNAMIC segment
    const Elf32_Phdr* dyn_phdr = nullptr;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const auto* phdr = reinterpret_cast<const Elf32_Phdr*>(
            ph_base + i * ehdr.e_phentsize);
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_phdr = phdr;
            break;
        }
    }

    if (!dyn_phdr) return true;  // No dynamic section is OK (static binary)

    if (dyn_phdr->p_offset + dyn_phdr->p_filesz > size) return false;

    const uint8_t* dyn_data = data + dyn_phdr->p_offset;
    size_t dyn_count = dyn_phdr->p_filesz / sizeof(Elf32_Dyn);

    // First pass: collect DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_NEEDED
    uint32_t strtab_vaddr = 0;
    uint32_t strtab_size  = 0;
    uint32_t symtab_vaddr = 0;
    std::vector<uint32_t> needed_offsets;

    for (size_t i = 0; i < dyn_count; i++) {
        const auto* dyn = reinterpret_cast<const Elf32_Dyn*>(dyn_data + i * sizeof(Elf32_Dyn));
        if (dyn->d_tag == DT_NULL) break;

        switch (dyn->d_tag) {
            case DT_STRTAB:
                strtab_vaddr = dyn->d_val;
                break;
            case DT_STRSZ:
                strtab_size = dyn->d_val;
                break;
            case DT_SYMTAB:
                symtab_vaddr = dyn->d_val;
                break;
            case DT_NEEDED:
                needed_offsets.push_back(dyn->d_val);
                break;
            default:
                break;
        }
    }

    // Resolve DT_STRTAB to file offset
    // For ET_EXEC, the strtab_vaddr is an absolute address
    // For ET_DYN, it's relative to base
    // We need to find which PT_LOAD contains this address and compute the file offset
    auto vaddr_to_offset = [&](uint32_t vaddr) -> size_t {
        for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
            const auto* phdr = reinterpret_cast<const Elf32_Phdr*>(
                ph_base + i * ehdr.e_phentsize);
            if (phdr->p_type != PT_LOAD) continue;
            if (vaddr >= phdr->p_vaddr && vaddr < phdr->p_vaddr + phdr->p_filesz) {
                return phdr->p_offset + (vaddr - phdr->p_vaddr);
            }
        }
        return SIZE_MAX;
    };

    // Resolve DT_NEEDED names
    if (strtab_vaddr != 0 && strtab_size > 0) {
        size_t strtab_foff = vaddr_to_offset(strtab_vaddr);
        if (strtab_foff != SIZE_MAX && strtab_foff + strtab_size <= size) {
            const uint8_t* strtab = data + strtab_foff;

            needed_libs_.clear();
            for (uint32_t offset : needed_offsets) {
                std::string name = read_string_at(strtab, strtab_size, offset);
                if (!name.empty()) {
                    needed_libs_.push_back(name);

                    // Add as imports with empty function names (library-level dependency)
                    LoadedModule::Import imp;
                    imp.dll = name;
                    imp.func = "";
                    imp.iat_addr = 0;
                    imp.sentinel_addr = 0;
                    mod.imports.push_back(std::move(imp));
                }
            }
        }
    }

    // Parse symbol table for imports (undefined symbols)
    if (symtab_vaddr != 0 && strtab_vaddr != 0) {
        size_t symtab_foff = vaddr_to_offset(symtab_vaddr);
        size_t strtab_foff = vaddr_to_offset(strtab_vaddr);

        if (symtab_foff != SIZE_MAX && strtab_foff != SIZE_MAX &&
            strtab_foff + strtab_size <= size) {

            const uint8_t* strtab = data + strtab_foff;

            // The symbol table size isn't directly in the dynamic section;
            // we iterate until we hit the string table or end of file.
            // A common heuristic: symtab ends where strtab begins.
            size_t symtab_end = strtab_foff;
            if (symtab_foff < symtab_end) {
                size_t sym_count = (symtab_end - symtab_foff) / sizeof(Elf32_Sym);
                // Cap at reasonable limit
                sym_count = std::min(sym_count, static_cast<size_t>(10000));

                for (size_t i = 0; i < sym_count; i++) {
                    if (symtab_foff + (i + 1) * sizeof(Elf32_Sym) > size) break;

                    const auto* sym = reinterpret_cast<const Elf32_Sym*>(
                        data + symtab_foff + i * sizeof(Elf32_Sym));

                    // Skip null symbol
                    if (sym->st_name == 0) continue;

                    // Check if undefined (import)
                    if (sym->st_shndx == 0) {
                        std::string name = read_string_at(strtab, strtab_size, sym->st_name);
                        if (!name.empty()) {
                            LoadedModule::Import imp;
                            imp.dll = "";  // Unknown library
                            imp.func = name;
                            imp.iat_addr = 0;
                            imp.sentinel_addr = 0;
                            mod.imports.push_back(std::move(imp));
                        }
                    }
                }
            }
        }
    }

    return true;
}

// ============================================================
// Main load from buffer
// ============================================================

std::optional<LoadedModule> ELFLoader::load(const uint8_t* data, size_t size,
                                             uint64_t base) {
    if (!validate_header(data, size)) return std::nullopt;

    const auto* ehdr = reinterpret_cast<const Elf32_Ehdr*>(data);

    // Determine load base
    // For ET_EXEC: use addresses as-is (base offset typically 0)
    // For ET_DYN (PIE): if no base specified, use a default
    if (base == 0 && ehdr->e_type == ET_DYN) {
        base = 0x10000;  // Default base for PIE binaries
    }
    // For ET_EXEC, base offset is typically 0 (addresses are absolute)
    if (ehdr->e_type == ET_EXEC) {
        base = 0;  // Addresses in the ELF are already absolute
    }

    // Find the lowest vaddr across all PT_LOAD segments (for module base)
    uint32_t min_vaddr = 0xFFFFFFFF;
    const uint8_t* ph_base = data + ehdr->e_phoff;
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        const auto* phdr = reinterpret_cast<const Elf32_Phdr*>(
            ph_base + i * ehdr->e_phentsize);
        if (phdr->p_type == PT_LOAD && phdr->p_vaddr < min_vaddr) {
            min_vaddr = phdr->p_vaddr;
        }
    }
    if (min_vaddr == 0xFFFFFFFF) return std::nullopt;

    // Build the LoadedModule
    LoadedModule mod;
    mod.base        = base + min_vaddr;
    mod.image_base  = min_vaddr;
    mod.size        = 0;
    mod.entry_point = base + ehdr->e_entry;

    // Map PT_LOAD segments
    if (!map_segments(data, size, base, *ehdr, mod)) return std::nullopt;

    // Parse section headers
    parse_sections(data, size, base, *ehdr, mod);

    // Parse dynamic section for imports
    parse_dynamic(data, size, base, *ehdr, mod);

    return mod;
}

// ============================================================
// Load from file
// ============================================================

std::optional<LoadedModule> ELFLoader::load_file(const std::string& path,
                                                  uint64_t base) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    std::streamsize file_size = file.tellg();
    if (file_size <= 0) return std::nullopt;
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> data(static_cast<size_t>(file_size));
    if (!file.read(reinterpret_cast<char*>(data.data()), file_size)) {
        return std::nullopt;
    }

    auto result = load(data.data(), data.size(), base);
    if (result) {
        // Extract filename from path
        size_t sep = path.find_last_of("/\\");
        result->name = (sep != std::string::npos) ? path.substr(sep + 1) : path;
        result->path = path;
    }
    return result;
}

} // namespace vx
