/**
 * VXEngine PE32/PE64 Loader Implementation
 *
 * Full PE loading pipeline:
 *   1. Parse DOS + PE headers, validate signatures
 *   2. Map sections to virtual memory at correct RVAs
 *   3. Apply base relocations if loaded at non-preferred base
 *   4. Process imports: sentinel-patch IAT entries
 *   5. Process exports: build name->address map
 *   6. Process TLS: allocate data, register callbacks
 */

#include "../include/vxengine/pe_loader.h"
#include <fstream>
#include <algorithm>
#include <cstring>

namespace vx {

// ============================================================
// Construction
// ============================================================

PELoader::PELoader(VirtualMemory& vmem)
    : vmem_(vmem)
{
}

// ============================================================
// Utility helpers
// ============================================================

uint8_t PELoader::section_perms(uint32_t ch) {
    uint8_t p = PERM_NONE;
    if (ch & IMAGE_SCN_MEM_READ)    p |= PERM_READ;
    if (ch & IMAGE_SCN_MEM_WRITE)   p |= PERM_WRITE;
    if (ch & IMAGE_SCN_MEM_EXECUTE) p |= PERM_EXEC;
    // Default: at least readable
    if (p == PERM_NONE) p = PERM_READ;
    return p;
}

std::string PELoader::section_name(const IMAGE_SECTION_HEADER& sec) {
    // Section name is up to 8 bytes, not necessarily null-terminated
    char buf[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    std::memcpy(buf, sec.Name, IMAGE_SIZEOF_SHORT_NAME);
    return std::string(buf);
}

// ============================================================
// Header validation
// ============================================================

bool PELoader::parse_headers(const uint8_t* data, size_t size, bool& is64) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return false;

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    if (pe_offset + sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) > size)
        return false;

    auto* sig = reinterpret_cast<const uint32_t*>(data + pe_offset);
    if (*sig != IMAGE_NT_SIGNATURE) return false;

    auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(data + pe_offset + 4);

    // Determine 32-bit vs 64-bit from optional header magic
    size_t opt_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    if (opt_offset + 2 > size) return false;

    uint16_t magic = *reinterpret_cast<const uint16_t*>(data + opt_offset);
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        is64 = true;
        if (opt_offset + sizeof(IMAGE_OPTIONAL_HEADER64) > size) return false;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        is64 = false;
        if (opt_offset + sizeof(IMAGE_OPTIONAL_HEADER32) > size) return false;
    } else {
        return false;
    }

    // Validate machine type
    if (is64 && file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    if (!is64 && file_hdr->Machine != IMAGE_FILE_MACHINE_I386) return false;

    return true;
}

// ============================================================
// Section mapping
// ============================================================

bool PELoader::map_sections(const uint8_t* data, size_t size,
                            uint64_t base, LoadedModule& mod)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    auto* file_hdr = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        data + pe_offset + 4);

    uint32_t opt_size = file_hdr->SizeOfOptionalHeader;
    size_t sec_offset = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER) + opt_size;
    uint16_t num_sections = file_hdr->NumberOfSections;

    if (sec_offset + num_sections * sizeof(IMAGE_SECTION_HEADER) > size)
        return false;

    auto* sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        data + sec_offset);

    // Determine header size to map
    uint32_t headers_size = 0;
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);
    auto* opt32 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
    auto* opt64 = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);

    bool is64 = (opt32->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    headers_size = is64 ? opt64->SizeOfHeaders : opt32->SizeOfHeaders;

    // Map PE headers
    uint64_t hdr_map_size = (headers_size + PAGE_SIZE - 1) & PAGE_MASK;
    if (hdr_map_size == 0) hdr_map_size = PAGE_SIZE;
    vmem_.map(base, hdr_map_size, PERM_READ);

    size_t copy_size = std::min(static_cast<size_t>(headers_size), size);
    vmem_.write(base, data, copy_size);

    // Map each section
    for (uint16_t i = 0; i < num_sections; ++i) {
        const auto& sec = sections[i];

        uint64_t sec_va = base + sec.VirtualAddress;
        uint64_t sec_vsize = sec.VirtualSize;
        if (sec_vsize == 0) sec_vsize = sec.SizeOfRawData;

        // Page-align the virtual size
        uint64_t aligned_size = (sec_vsize + PAGE_SIZE - 1) & PAGE_MASK;
        if (aligned_size == 0) aligned_size = PAGE_SIZE;

        uint8_t perms = section_perms(sec.Characteristics);
        vmem_.map(sec_va, aligned_size, perms);

        // Copy raw data
        if (sec.SizeOfRawData > 0 && sec.PointerToRawData < size) {
            size_t raw_copy = std::min(
                static_cast<size_t>(sec.SizeOfRawData),
                size - static_cast<size_t>(sec.PointerToRawData));
            raw_copy = std::min(raw_copy, static_cast<size_t>(sec_vsize));
            vmem_.write(sec_va, data + sec.PointerToRawData, raw_copy);
        }

        // Record section info
        LoadedModule::Section sec_info;
        sec_info.name = section_name(sec);
        sec_info.va = sec_va;
        sec_info.size = sec_vsize;
        sec_info.raw_size = sec.SizeOfRawData;
        sec_info.perms = perms;
        mod.sections.push_back(std::move(sec_info));
    }

    return true;
}

// ============================================================
// Base relocations
// ============================================================

bool PELoader::apply_relocations(const uint8_t* data, size_t size,
                                 uint64_t base, uint64_t preferred_base,
                                 bool is64)
{
    if (base == preferred_base) return true; // No relocation needed

    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);

    IMAGE_DATA_DIRECTORY reloc_dir;
    if (is64) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
            return true;
        reloc_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    } else {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
            return true;
        reloc_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    }

    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0)
        return true; // No relocations

    int64_t delta = static_cast<int64_t>(base) - static_cast<int64_t>(preferred_base);

    // Walk relocation blocks from virtual memory (already mapped)
    uint64_t reloc_va = base + reloc_dir.VirtualAddress;
    uint32_t remaining = reloc_dir.Size;

    while (remaining >= sizeof(IMAGE_BASE_RELOCATION)) {
        IMAGE_BASE_RELOCATION block;
        if (!vmem_.read(reloc_va, &block, sizeof(block))) break;

        if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
        if (block.SizeOfBlock > remaining) break;

        uint32_t num_entries = (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
        uint64_t entry_va = reloc_va + sizeof(IMAGE_BASE_RELOCATION);

        for (uint32_t i = 0; i < num_entries; ++i) {
            uint16_t entry = 0;
            vmem_.read(entry_va + i * 2, &entry, 2);

            uint16_t type = entry >> 12;
            uint16_t offset = entry & 0x0FFF;
            uint64_t patch_addr = base + block.VirtualAddress + offset;

            switch (type) {
            case IMAGE_REL_BASED_ABSOLUTE:
                // Padding, skip
                break;
            case IMAGE_REL_BASED_HIGHLOW: {
                uint32_t val = vmem_.read32(patch_addr);
                val = static_cast<uint32_t>(val + delta);
                vmem_.write32(patch_addr, val);
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                uint64_t val = vmem_.read64(patch_addr);
                val = static_cast<uint64_t>(static_cast<int64_t>(val) + delta);
                vmem_.write64(patch_addr, val);
                break;
            }
            default:
                // Unknown relocation type, skip
                break;
            }
        }

        reloc_va += block.SizeOfBlock;
        remaining -= block.SizeOfBlock;
    }

    return true;
}

// ============================================================
// Import processing (sentinel patching)
// ============================================================

bool PELoader::process_imports(const uint8_t* data, size_t size,
                               uint64_t base, bool is64,
                               LoadedModule& mod)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);

    IMAGE_DATA_DIRECTORY import_dir;
    if (is64) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
            return true;
        import_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    } else {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
            return true;
        import_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    }

    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0)
        return true;

    uint64_t desc_va = base + import_dir.VirtualAddress;

    // Walk import descriptors
    while (true) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!vmem_.read(desc_va, &desc, sizeof(desc))) break;

        // Null terminator
        if (desc.Name == 0 && desc.FirstThunk == 0) break;

        // Read DLL name
        std::string dll_name = vmem_.read_string(base + desc.Name, 256);
        // Normalize to lowercase
        std::string dll_lower = dll_name;
        for (auto& c : dll_lower) c = static_cast<char>(::tolower(c));

        // Walk thunks (use OriginalFirstThunk if available, else FirstThunk)
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk
                                                    : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;

        uint64_t int_va = base + int_rva;
        uint64_t iat_va = base + iat_rva;

        uint32_t thunk_size = is64 ? 8 : 4;
        // Ordinal flag: bit 31 for PE32, bit 63 for PE64
        uint64_t ordinal_flag = is64 ? (1ULL << 63) : (1ULL << 31);

        for (uint32_t idx = 0; ; ++idx) {
            uint64_t thunk_val = 0;
            if (is64) {
                thunk_val = vmem_.read64(int_va + idx * thunk_size);
            } else {
                thunk_val = vmem_.read32(int_va + idx * thunk_size);
            }

            if (thunk_val == 0) break; // End of thunk array

            std::string func_name;
            if (thunk_val & ordinal_flag) {
                // Import by ordinal
                uint16_t ordinal = static_cast<uint16_t>(thunk_val & 0xFFFF);
                func_name = "#" + std::to_string(ordinal);
            } else {
                // Import by name
                uint64_t hint_rva = thunk_val & (is64 ? 0x7FFFFFFFFFFFFFFFULL : 0x7FFFFFFFULL);
                // Skip the 2-byte Hint field to get the name
                func_name = vmem_.read_string(base + hint_rva + 2, 256);
            }

            // Assign sentinel address
            uint64_t sentinel = next_sentinel_++;
            sentinel_map_[sentinel] = {dll_lower, func_name};

            // Write sentinel to IAT entry
            uint64_t iat_entry_va = iat_va + idx * thunk_size;
            if (is64) {
                vmem_.write64(iat_entry_va, sentinel);
            } else {
                vmem_.write32(iat_entry_va, static_cast<uint32_t>(sentinel));
            }

            // Map sentinel address page if not already mapped (with RX so CPU can "jump" there)
            uint64_t sentinel_page = sentinel & PAGE_MASK;
            if (!vmem_.is_mapped(sentinel_page)) {
                vmem_.map(sentinel_page, PAGE_SIZE, PERM_RX);
            }

            // Record import
            LoadedModule::Import imp;
            imp.dll = dll_lower;
            imp.func = func_name;
            imp.iat_addr = iat_entry_va;
            imp.sentinel_addr = sentinel;
            mod.imports.push_back(std::move(imp));
        }

        desc_va += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return true;
}

// ============================================================
// Export processing
// ============================================================

bool PELoader::process_exports(const uint8_t* data, size_t size,
                               uint64_t base, LoadedModule& mod)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);

    // Determine if PE32 or PE64
    uint16_t magic = 0;
    vmem_.read(base + opt_off, &magic, 2);

    IMAGE_DATA_DIRECTORY export_dir;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            return true;
        export_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    } else {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
            return true;
        export_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    }

    if (export_dir.VirtualAddress == 0 || export_dir.Size == 0)
        return true;

    uint64_t exp_va = base + export_dir.VirtualAddress;

    IMAGE_EXPORT_DIRECTORY exp_hdr;
    if (!vmem_.read(exp_va, &exp_hdr, sizeof(exp_hdr))) return false;

    uint64_t func_table  = base + exp_hdr.AddressOfFunctions;
    uint64_t name_table  = base + exp_hdr.AddressOfNames;
    uint64_t ord_table   = base + exp_hdr.AddressOfNameOrdinals;

    // Process named exports
    for (uint32_t i = 0; i < exp_hdr.NumberOfNames; ++i) {
        uint32_t name_rva = vmem_.read32(name_table + i * 4);
        std::string name = vmem_.read_string(base + name_rva, 256);

        uint16_t ordinal_index = 0;
        vmem_.read(ord_table + i * 2, &ordinal_index, 2);

        if (ordinal_index >= exp_hdr.NumberOfFunctions) continue;

        uint32_t func_rva = vmem_.read32(func_table + ordinal_index * 4);

        // Check for forwarder (RVA points inside export directory)
        bool is_forwarder = (func_rva >= export_dir.VirtualAddress &&
                             func_rva < export_dir.VirtualAddress + export_dir.Size);

        LoadedModule::Export exp;
        exp.name = name;
        exp.addr = is_forwarder ? 0 : (base + func_rva);
        exp.ordinal = static_cast<uint16_t>(ordinal_index + exp_hdr.Base);
        mod.exports.push_back(std::move(exp));
    }

    // Process exports by ordinal only (no name)
    for (uint32_t i = 0; i < exp_hdr.NumberOfFunctions; ++i) {
        // Skip if this ordinal already has a named entry
        bool has_name = false;
        for (uint32_t j = 0; j < exp_hdr.NumberOfNames; ++j) {
            uint16_t ord_idx = 0;
            vmem_.read(ord_table + j * 2, &ord_idx, 2);
            if (ord_idx == i) { has_name = true; break; }
        }
        if (has_name) continue;

        uint32_t func_rva = vmem_.read32(func_table + i * 4);
        if (func_rva == 0) continue;

        bool is_forwarder = (func_rva >= export_dir.VirtualAddress &&
                             func_rva < export_dir.VirtualAddress + export_dir.Size);

        LoadedModule::Export exp;
        exp.name = "#" + std::to_string(i + exp_hdr.Base);
        exp.addr = is_forwarder ? 0 : (base + func_rva);
        exp.ordinal = static_cast<uint16_t>(i + exp_hdr.Base);
        mod.exports.push_back(std::move(exp));
    }

    return true;
}

// ============================================================
// TLS processing
// ============================================================

bool PELoader::process_tls(const uint8_t* data, size_t size,
                           uint64_t base, bool is64)
{
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);

    IMAGE_DATA_DIRECTORY tls_dir;
    if (is64) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
            return true;
        tls_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    } else {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
        if (opt->NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_TLS)
            return true;
        tls_dir = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    }

    if (tls_dir.VirtualAddress == 0 || tls_dir.Size == 0)
        return true;

    uint64_t tls_va = base + tls_dir.VirtualAddress;

    if (is64) {
        IMAGE_TLS_DIRECTORY64 tls;
        if (!vmem_.read(tls_va, &tls, sizeof(tls))) return false;

        // Allocate TLS data
        if (tls.EndAddressOfRawData > tls.StartAddressOfRawData) {
            uint64_t tls_data_size = tls.EndAddressOfRawData - tls.StartAddressOfRawData;
            // TLS data is already mapped as part of the section, just note it
        }

        // TLS index
        if (tls.AddressOfIndex != 0) {
            vmem_.write64(tls.AddressOfIndex, 0); // TLS index = 0
        }

        // TLS callbacks
        if (tls.AddressOfCallBacks != 0) {
            uint64_t cb_va = tls.AddressOfCallBacks;
            while (true) {
                uint64_t cb_addr = vmem_.read64(cb_va);
                if (cb_addr == 0) break;
                tls_callbacks_.push_back(cb_addr);
                cb_va += 8;
            }
        }
    } else {
        IMAGE_TLS_DIRECTORY32 tls;
        if (!vmem_.read(tls_va, &tls, sizeof(tls))) return false;

        // TLS index
        if (tls.AddressOfIndex != 0) {
            vmem_.write32(tls.AddressOfIndex, 0);
        }

        // TLS callbacks
        if (tls.AddressOfCallBacks != 0) {
            uint64_t cb_va = tls.AddressOfCallBacks;
            while (true) {
                uint32_t cb_addr = vmem_.read32(cb_va);
                if (cb_addr == 0) break;
                tls_callbacks_.push_back(cb_addr);
                cb_va += 4;
            }
        }
    }

    return true;
}

// ============================================================
// Main load entry point
// ============================================================

std::optional<LoadedModule> PELoader::load(const uint8_t* data, size_t size,
                                           uint64_t base)
{
    if (!data || size < sizeof(IMAGE_DOS_HEADER)) return std::nullopt;

    bool is64 = false;
    if (!parse_headers(data, size, is64)) return std::nullopt;

    // Extract info from headers
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    uint32_t pe_offset = static_cast<uint32_t>(dos->e_lfanew);
    size_t opt_off = pe_offset + 4 + sizeof(IMAGE_FILE_HEADER);

    uint64_t preferred_base = 0;
    uint64_t size_of_image = 0;
    uint64_t entry_rva = 0;

    if (is64) {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + opt_off);
        preferred_base = opt->ImageBase;
        size_of_image = opt->SizeOfImage;
        entry_rva = opt->AddressOfEntryPoint;
    } else {
        auto* opt = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + opt_off);
        preferred_base = opt->ImageBase;
        size_of_image = opt->SizeOfImage;
        entry_rva = opt->AddressOfEntryPoint;
    }

    // Use preferred base if no override specified
    if (base == 0) base = preferred_base;

    LoadedModule mod;
    mod.base = base;
    mod.size = size_of_image;
    mod.image_base = preferred_base;
    mod.entry_point = base + entry_rva;

    // Step 1: Map sections
    if (!map_sections(data, size, base, mod)) return std::nullopt;

    // Step 2: Apply relocations
    if (!apply_relocations(data, size, base, preferred_base, is64))
        return std::nullopt;

    // Step 3: Process imports (sentinel patching)
    if (!process_imports(data, size, base, is64, mod)) return std::nullopt;

    // Step 4: Process exports
    if (!process_exports(data, size, base, mod)) return std::nullopt;

    // Step 5: Process TLS
    if (!process_tls(data, size, base, is64)) return std::nullopt;

    return mod;
}

// ============================================================
// File-based loading
// ============================================================

std::optional<LoadedModule> PELoader::load_file(const std::string& path,
                                                uint64_t base)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return std::nullopt;

    auto fsize = file.tellg();
    if (fsize <= 0) return std::nullopt;

    std::vector<uint8_t> buf(static_cast<size_t>(fsize));
    file.seekg(0, std::ios::beg);
    file.read(reinterpret_cast<char*>(buf.data()), fsize);

    auto mod = load(buf.data(), buf.size(), base);
    if (mod) {
        // Extract filename from path
        std::string name = path;
        auto sep = name.find_last_of("/\\");
        if (sep != std::string::npos) name = name.substr(sep + 1);
        mod->name = name;
        mod->path = path;
    }
    return mod;
}

} // namespace vx
