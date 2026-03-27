#pragma once
/**
 * VXEngine ELF32 Loader
 *
 * Minimal ELF loader for ARM Linux and x86 Linux binaries.
 * Parses and maps ELF files into virtual memory:
 *   - ELF header validation (magic, class, machine)
 *   - Program header (PT_LOAD segment) mapping with correct permissions
 *   - Entry point extraction
 *   - Dynamic section parsing for imports (DT_NEEDED, DT_SYMTAB, DT_STRTAB)
 *   - Section header parsing for section info
 *   - Both ET_EXEC (static) and ET_DYN (PIE/shared object) support
 */

#include "vxengine.h"
#include "memory.h"
#include <cstring>

namespace vx {

// ============================================================
// ELF32 structure definitions (standalone, no elf.h dependency)
// ============================================================

#pragma pack(push, 1)

constexpr int EI_NIDENT = 16;

struct Elf32_Ehdr {
    uint8_t  e_ident[EI_NIDENT];  // Magic, class, data, version, OS/ABI, padding
    uint16_t e_type;               // ET_EXEC, ET_DYN, etc.
    uint16_t e_machine;            // EM_ARM, EM_386, etc.
    uint32_t e_version;
    uint32_t e_entry;              // Entry point virtual address
    uint32_t e_phoff;              // Program header table offset
    uint32_t e_shoff;              // Section header table offset
    uint32_t e_flags;
    uint16_t e_ehsize;             // ELF header size
    uint16_t e_phentsize;          // Program header entry size
    uint16_t e_phnum;              // Number of program headers
    uint16_t e_shentsize;          // Section header entry size
    uint16_t e_shnum;              // Number of section headers
    uint16_t e_shstrndx;           // Section name string table index
};

struct Elf32_Phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

struct Elf32_Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
};

struct Elf32_Dyn {
    int32_t  d_tag;
    uint32_t d_val;
};

struct Elf32_Sym {
    uint32_t st_name;
    uint32_t st_value;
    uint32_t st_size;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
};

#pragma pack(pop)

// ELF magic
constexpr uint8_t ELFMAG0 = 0x7F;
constexpr uint8_t ELFMAG1 = 'E';
constexpr uint8_t ELFMAG2 = 'L';
constexpr uint8_t ELFMAG3 = 'F';

// ELF ident offsets
constexpr int EI_CLASS   = 4;
constexpr int EI_DATA    = 5;
constexpr int EI_VERSION = 6;

// ELF class values
constexpr uint8_t ELFCLASS32 = 1;
constexpr uint8_t ELFCLASS64 = 2;

// ELF data encoding
constexpr uint8_t ELFDATA2LSB = 1;  // Little-endian
constexpr uint8_t ELFDATA2MSB = 2;  // Big-endian

// ELF types
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t ET_DYN  = 3;

// Machine types
constexpr uint16_t EM_386   = 3;
constexpr uint16_t EM_ARM   = 40;

// Program header types
constexpr uint32_t PT_NULL    = 0;
constexpr uint32_t PT_LOAD    = 1;
constexpr uint32_t PT_DYNAMIC = 2;
constexpr uint32_t PT_INTERP  = 3;
constexpr uint32_t PT_NOTE    = 4;

// Program header flags
constexpr uint32_t PF_X = 1;
constexpr uint32_t PF_W = 2;
constexpr uint32_t PF_R = 4;

// Dynamic section tags
constexpr int32_t DT_NULL    = 0;
constexpr int32_t DT_NEEDED  = 1;
constexpr int32_t DT_HASH    = 4;
constexpr int32_t DT_STRTAB  = 5;
constexpr int32_t DT_SYMTAB  = 6;
constexpr int32_t DT_STRSZ   = 10;
constexpr int32_t DT_INIT    = 12;
constexpr int32_t DT_FINI    = 13;
constexpr int32_t DT_REL     = 17;
constexpr int32_t DT_RELSZ   = 18;
constexpr int32_t DT_JMPREL  = 23;
constexpr int32_t DT_PLTRELSZ = 2;

// Section header types
constexpr uint32_t SHT_NULL    = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_SYMTAB = 2;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint32_t SHT_NOBITS = 8;
constexpr uint32_t SHT_DYNSYM = 11;

// Section header flags
constexpr uint32_t SHF_WRITE     = 0x1;
constexpr uint32_t SHF_ALLOC     = 0x2;
constexpr uint32_t SHF_EXECINSTR = 0x4;

// ============================================================
// ELF Loader class
// ============================================================

class ELFLoader {
public:
    explicit ELFLoader(VirtualMemory& vmem);
    ~ELFLoader() = default;

    ELFLoader(const ELFLoader&) = delete;
    ELFLoader& operator=(const ELFLoader&) = delete;

    /// Load an ELF file from a raw byte buffer.
    /// @param data     Raw ELF file bytes
    /// @param size     Size of the data buffer
    /// @param base     Load base address (0 = use addresses from ELF, or 0x10000 for ET_DYN)
    /// @return         LoadedModule on success, empty optional on failure
    std::optional<LoadedModule> load(const uint8_t* data, size_t size,
                                     uint64_t base = 0);

    /// Load an ELF file from disk.
    std::optional<LoadedModule> load_file(const std::string& path,
                                          uint64_t base = 0);

    /// Get the list of needed shared libraries (DT_NEEDED entries)
    const std::vector<std::string>& needed_libs() const { return needed_libs_; }

private:
    VirtualMemory& vmem_;
    std::vector<std::string> needed_libs_;

    // Internal helpers
    bool validate_header(const uint8_t* data, size_t size) const;
    bool map_segments(const uint8_t* data, size_t size,
                      uint64_t base, const Elf32_Ehdr& ehdr, LoadedModule& mod);
    bool parse_sections(const uint8_t* data, size_t size,
                        uint64_t base, const Elf32_Ehdr& ehdr, LoadedModule& mod);
    bool parse_dynamic(const uint8_t* data, size_t size,
                       uint64_t base, const Elf32_Ehdr& ehdr, LoadedModule& mod);

    // Utility
    static uint8_t phdr_perms(uint32_t flags);
    static std::string read_string_at(const uint8_t* strtab, size_t strtab_size, uint32_t offset);
};

} // namespace vx
