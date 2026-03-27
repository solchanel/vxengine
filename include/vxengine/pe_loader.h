#pragma once
/**
 * VXEngine PE32/PE64 Loader
 *
 * Parses and maps PE files into virtual memory:
 *   - DOS header, PE signature, COFF/optional headers
 *   - Section mapping with correct RVA alignment
 *   - Base relocations (when loaded at non-preferred base)
 *   - Import directory processing with IAT sentinel patching
 *   - Export directory parsing (name -> address map)
 *   - TLS directory support (data + callbacks)
 *   - Both PE32 (32-bit) and PE32+ (64-bit)
 */

#include "vxengine.h"
#include "memory.h"
#include <cstring>

namespace vx {

// ============================================================
// PE structure definitions (standalone, no windows.h dependency)
// ============================================================

#pragma pack(push, 1)

struct IMAGE_DOS_HEADER {
    uint16_t e_magic;       // "MZ"
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;      // Offset to PE header
};

struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

struct IMAGE_OPTIONAL_HEADER32 {
    uint16_t Magic;                     // 0x10B = PE32
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;                     // 0x20B = PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_NT_HEADERS32 {
    uint32_t Signature;                 // "PE\0\0"
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

constexpr int IMAGE_SIZEOF_SHORT_NAME = 8;

struct IMAGE_SECTION_HEADER {
    char     Name[IMAGE_SIZEOF_SHORT_NAME];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk;    // RVA to INT (Import Name Table)
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;                  // RVA to DLL name
    uint32_t FirstThunk;            // RVA to IAT (Import Address Table)
};

struct IMAGE_IMPORT_BY_NAME {
    uint16_t Hint;
    char     Name[1];               // Variable-length
};

struct IMAGE_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};

struct IMAGE_BASE_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
    // Followed by variable-length array of uint16_t entries
};

struct IMAGE_TLS_DIRECTORY32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;
    uint32_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

struct IMAGE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData;
    uint64_t EndAddressOfRawData;
    uint64_t AddressOfIndex;
    uint64_t AddressOfCallBacks;
    uint32_t SizeOfZeroFill;
    uint32_t Characteristics;
};

#pragma pack(pop)

// PE constants
constexpr uint16_t IMAGE_DOS_SIGNATURE       = 0x5A4D;     // "MZ"
constexpr uint32_t IMAGE_NT_SIGNATURE        = 0x00004550;  // "PE\0\0"
constexpr uint16_t IMAGE_FILE_MACHINE_I386   = 0x014C;
constexpr uint16_t IMAGE_FILE_MACHINE_AMD64  = 0x8664;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B;
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B;

// Data directory indices
constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT    = 0;
constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT    = 1;
constexpr int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr int IMAGE_DIRECTORY_ENTRY_TLS       = 9;

// Section characteristics
constexpr uint32_t IMAGE_SCN_CNT_CODE         = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED  = 0x00000040;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE      = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ         = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE        = 0x80000000;

// Relocation types
constexpr uint16_t IMAGE_REL_BASED_ABSOLUTE   = 0;
constexpr uint16_t IMAGE_REL_BASED_HIGHLOW    = 3;
constexpr uint16_t IMAGE_REL_BASED_DIR64      = 10;

// ============================================================
// PE Loader class
// ============================================================

class PELoader {
public:
    explicit PELoader(VirtualMemory& vmem);
    ~PELoader() = default;

    PELoader(const PELoader&) = delete;
    PELoader& operator=(const PELoader&) = delete;

    /// Load a PE file from a raw byte buffer.
    /// @param data     Raw PE file bytes
    /// @param size     Size of the data buffer
    /// @param base     Load base address (0 = use preferred from PE header)
    /// @return         LoadedModule on success, empty optional on failure
    std::optional<LoadedModule> load(const uint8_t* data, size_t size,
                                     uint64_t base = 0);

    /// Load a PE file from disk.
    std::optional<LoadedModule> load_file(const std::string& path,
                                          uint64_t base = 0);

    /// Get the current sentinel counter (for external sentinel allocation)
    uint64_t next_sentinel() const { return next_sentinel_; }

    /// Advance the sentinel counter and return the new value
    uint64_t alloc_sentinel() { return next_sentinel_++; }

    /// Get import sentinel map: sentinel_addr -> (dll_name, func_name)
    using SentinelMap = std::map<uint64_t, std::pair<std::string, std::string>>;
    const SentinelMap& sentinel_map() const { return sentinel_map_; }

    /// Get TLS callback addresses
    const std::vector<uint64_t>& tls_callbacks() const { return tls_callbacks_; }

private:
    VirtualMemory& vmem_;
    uint64_t next_sentinel_ = SENTINEL_BASE;
    SentinelMap sentinel_map_;
    std::vector<uint64_t> tls_callbacks_;

    // Internal helpers
    bool parse_headers(const uint8_t* data, size_t size, bool& is64);
    bool map_sections(const uint8_t* data, size_t size,
                      uint64_t base, LoadedModule& mod);
    bool apply_relocations(const uint8_t* data, size_t size,
                           uint64_t base, uint64_t preferred_base, bool is64);
    bool process_imports(const uint8_t* data, size_t size,
                         uint64_t base, bool is64, LoadedModule& mod);
    bool process_exports(const uint8_t* data, size_t size,
                         uint64_t base, LoadedModule& mod);
    bool process_tls(const uint8_t* data, size_t size,
                     uint64_t base, bool is64);

    // Utility
    static uint8_t section_perms(uint32_t characteristics);
    static std::string section_name(const IMAGE_SECTION_HEADER& sec);
};

} // namespace vx
