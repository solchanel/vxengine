#pragma once
/**
 * VXEngine Windows Environment Setup
 *
 * Creates a realistic Windows process environment for emulation:
 *   - PEB (Process Environment Block) with Ldr, ProcessParameters
 *   - TEB (Thread Environment Block) with Self pointer, PEB, TLS slots
 *   - GDT with proper segment descriptors (CS, DS, SS, FS, GS)
 *   - Stack allocation (1MB)
 *   - Simple bump-allocator heap
 *   - Module list (PEB_LDR_DATA with InLoadOrderModuleList)
 */

#include "vxengine.h"
#include "memory.h"
#include "cpu/icpu.h"
#include "cpu/x86/x86_cpu.h"
#include <cstring>

namespace vx {

// ============================================================
// Windows structure layouts (standalone, no windows.h)
// ============================================================

#pragma pack(push, 1)

// Doubly-linked list (Windows LIST_ENTRY)
struct LIST_ENTRY32 {
    uint32_t Flink;
    uint32_t Blink;
};

// Unicode string
struct UNICODE_STRING32 {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Buffer;
};

// LDR_DATA_TABLE_ENTRY (simplified, x86)
struct LDR_DATA_TABLE_ENTRY32 {
    LIST_ENTRY32 InLoadOrderLinks;          // +0x00
    LIST_ENTRY32 InMemoryOrderLinks;        // +0x08
    LIST_ENTRY32 InInitializationOrderLinks; // +0x10
    uint32_t DllBase;                       // +0x18
    uint32_t EntryPoint;                    // +0x1C
    uint32_t SizeOfImage;                   // +0x20
    UNICODE_STRING32 FullDllName;           // +0x24
    UNICODE_STRING32 BaseDllName;           // +0x2C
    uint32_t Flags;                         // +0x34
    uint16_t LoadCount;                     // +0x38
    uint16_t TlsIndex;                      // +0x3A
    // ... more fields omitted
};

// PEB_LDR_DATA (simplified, x86)
struct PEB_LDR_DATA32 {
    uint32_t Length;                         // +0x00
    uint8_t  Initialized;                   // +0x04
    uint8_t  pad1[3];
    uint32_t SsHandle;                      // +0x08
    LIST_ENTRY32 InLoadOrderModuleList;     // +0x0C
    LIST_ENTRY32 InMemoryOrderModuleList;   // +0x14
    LIST_ENTRY32 InInitializationOrderModuleList; // +0x1C
};

// RTL_USER_PROCESS_PARAMETERS (simplified, x86)
struct RTL_USER_PROCESS_PARAMETERS32 {
    uint32_t MaximumLength;                 // +0x00
    uint32_t Length;                        // +0x04
    uint32_t Flags;                         // +0x08
    uint32_t DebugFlags;                    // +0x0C
    uint32_t ConsoleHandle;                 // +0x10
    uint32_t ConsoleFlags;                  // +0x14
    uint32_t StdInputHandle;               // +0x18
    uint32_t StdOutputHandle;              // +0x1C
    uint32_t StdErrorHandle;               // +0x20
    UNICODE_STRING32 CurrentDirectory_DosPath; // +0x24
    uint32_t CurrentDirectory_Handle;       // +0x2C
    UNICODE_STRING32 DllPath;              // +0x30
    UNICODE_STRING32 ImagePathName;        // +0x38
    UNICODE_STRING32 CommandLine;          // +0x40
    uint32_t Environment;                  // +0x48
};

// PEB (simplified, x86 - offsets must match real Windows)
struct PEB32 {
    uint8_t  InheritedAddressSpace;         // +0x00
    uint8_t  ReadImageFileExecOptions;      // +0x01
    uint8_t  BeingDebugged;                 // +0x02
    uint8_t  BitField;                      // +0x03
    uint32_t Mutant;                        // +0x04
    uint32_t ImageBaseAddress;              // +0x08
    uint32_t Ldr;                           // +0x0C (PEB_LDR_DATA*)
    uint32_t ProcessParameters;             // +0x10
    uint32_t SubSystemData;                 // +0x14
    uint32_t ProcessHeap;                   // +0x18
    uint32_t FastPebLock;                   // +0x1C
    uint32_t AtlThunkSListPtr;             // +0x20
    uint32_t IFEOKey;                      // +0x24
    uint32_t CrossProcessFlags;            // +0x28
    uint32_t UserSharedInfoPtr;            // +0x2C
    uint32_t SystemReserved;               // +0x30
    uint32_t AtlThunkSListPtr32;           // +0x34
    uint32_t ApiSetMap;                    // +0x38
    uint32_t TlsExpansionCounter;          // +0x3C
    uint32_t TlsBitmap;                    // +0x40
    uint32_t TlsBitmapBits[2];             // +0x44
    uint32_t ReadOnlySharedMemoryBase;     // +0x4C
    uint32_t SharedData;                   // +0x50
    uint32_t ReadOnlyStaticServerData;     // +0x54
    uint32_t AnsiCodePageData;             // +0x58
    uint32_t OemCodePageData;              // +0x5C
    uint32_t UnicodeCaseTableData;         // +0x60
    uint32_t NumberOfProcessors;           // +0x64
    uint32_t NtGlobalFlag;                 // +0x68
    uint8_t  pad_6c[4];                    // alignment
    uint64_t CriticalSectionTimeout;       // +0x70
    uint32_t HeapSegmentReserve;           // +0x78
    uint32_t HeapSegmentCommit;            // +0x7C
    uint32_t HeapDeCommitTotalFreeThreshold; // +0x80
    uint32_t HeapDeCommitFreeBlockThreshold; // +0x84
    uint32_t NumberOfHeaps;                // +0x88
    uint32_t MaximumNumberOfHeaps;         // +0x8C
    uint32_t ProcessHeaps;                 // +0x90
};

// TEB (simplified, x86 - offsets must match real Windows)
struct TEB32 {
    uint32_t ExceptionList;                 // +0x00 (fs:[0x00]) NT_TIB
    uint32_t StackBase;                     // +0x04 (fs:[0x04])
    uint32_t StackLimit;                    // +0x08 (fs:[0x08])
    uint32_t SubSystemTib;                  // +0x0C
    uint32_t FiberData;                     // +0x10
    uint32_t ArbitraryUserPointer;          // +0x14
    uint32_t Self;                          // +0x18 (fs:[0x18]) -> TEB itself
    uint32_t EnvironmentPointer;            // +0x1C
    uint32_t ClientId_UniqueProcess;        // +0x20 (fs:[0x20])
    uint32_t ClientId_UniqueThread;         // +0x24 (fs:[0x24])
    uint32_t ActiveRpcHandle;               // +0x28
    uint32_t ThreadLocalStoragePointer;     // +0x2C (fs:[0x2C])
    uint32_t ProcessEnvironmentBlock;       // +0x30 (fs:[0x30]) -> PEB
    uint32_t LastErrorValue;                // +0x34 (fs:[0x34])
    uint32_t CountOfOwnedCriticalSections;  // +0x38
    uint32_t CsrClientThread;              // +0x3C
    uint32_t Win32ThreadInfo;              // +0x40
    uint32_t User32Reserved[26];           // +0x44
    uint32_t UserReserved[5];              // +0xAC
    uint32_t WOW32Reserved;                // +0xC0
    uint32_t CurrentLocale;                // +0xC4
    uint32_t FpSoftwareStatusRegister;     // +0xC8
    // ... large gap to TLS slots at +0xE10
};

#pragma pack(pop)

// ============================================================
// Layout constants
// ============================================================

constexpr uint32_t PEB_ADDRESS              = 0x7FFD0000;
constexpr uint32_t PEB_LDR_ADDRESS          = 0x7FFD0400;
constexpr uint32_t PROCESS_PARAMS_ADDRESS   = 0x7FFD0800;
constexpr uint32_t TEB_ADDRESS              = 0x7FFD3000;
constexpr uint32_t TLS_SLOTS_ADDRESS        = 0x7FFD3E10; // TEB + 0xE10
constexpr uint32_t TLS_SLOT_COUNT           = 64;
constexpr uint32_t MODULE_LIST_ADDRESS      = 0x7FFD1000; // LDR_DATA_TABLE_ENTRYs
constexpr uint32_t STRING_POOL_ADDRESS      = 0x7FFD2000; // Unicode strings

constexpr uint32_t STACK_BASE               = 0x7FF00000;
constexpr uint32_t STACK_SIZE               = 0x00100000; // 1MB
constexpr uint32_t STACK_TOP                = STACK_BASE + STACK_SIZE;
constexpr uint32_t INITIAL_ESP              = 0x7FFFC000;
constexpr uint32_t INITIAL_EBP              = INITIAL_ESP + 0x200;

constexpr uint32_t HEAP_BASE                = 0x20000000;
constexpr uint32_t HEAP_MAX_SIZE            = 0x10000000; // 256MB max

constexpr uint32_t GDT_ENTRY_COUNT          = 8;

// ============================================================
// Simple bump-allocator heap
// ============================================================

class EmulatedHeap {
public:
    explicit EmulatedHeap(VirtualMemory& vmem,
                          uint32_t base = HEAP_BASE,
                          uint32_t max_size = HEAP_MAX_SIZE);

    /// Allocate memory, returns virtual address (0 on failure)
    uint32_t alloc(uint32_t size);

    /// Free memory (tracked but not reclaimed in bump allocator)
    void free(uint32_t addr);

    /// Realloc: allocate new block, copy data, free old
    uint32_t realloc(uint32_t addr, uint32_t new_size);

    /// Get the base address
    uint32_t base() const { return base_; }

    /// Get current allocation pointer
    uint32_t current() const { return current_; }

private:
    VirtualMemory& vmem_;
    uint32_t base_;
    uint32_t max_size_;
    uint32_t current_;
    uint32_t mapped_end_;

    // Track allocations for realloc/free
    std::map<uint32_t, uint32_t> allocs_; // addr -> size

    /// Ensure pages are mapped up to the given address
    void ensure_mapped(uint32_t end_addr);
};

// ============================================================
// Windows Environment class
// ============================================================

class WindowsEnvironment {
public:
    WindowsEnvironment(VirtualMemory& vmem, X86Backend& cpu);
    ~WindowsEnvironment() = default;

    WindowsEnvironment(const WindowsEnvironment&) = delete;
    WindowsEnvironment& operator=(const WindowsEnvironment&) = delete;

    /// Initialize the full Windows environment.
    /// Call this after PE loading.
    /// @param image_base   Base address of loaded PE image
    /// @param entry_point  Entry point address
    /// @param image_name   Name of the loaded module (e.g., "target.exe")
    void initialize(uint32_t image_base, uint32_t image_size,
                    uint32_t entry_point, const std::string& image_name);

    /// Add a module to the PEB loader module list
    void add_module(const std::string& name, uint32_t base,
                    uint32_t size, uint32_t entry);

    /// Get the heap allocator
    EmulatedHeap& heap() { return heap_; }

    /// Get key addresses
    uint32_t peb_address() const { return PEB_ADDRESS; }
    uint32_t teb_address() const { return TEB_ADDRESS; }
    uint32_t stack_top() const { return STACK_TOP; }
    uint32_t initial_esp() const { return INITIAL_ESP; }

private:
    VirtualMemory& vmem_;
    X86Backend& cpu_;
    EmulatedHeap heap_;
    uint32_t next_module_entry_ = MODULE_LIST_ADDRESS;
    uint32_t string_pool_ptr_ = STRING_POOL_ADDRESS;

    // Internal setup routines
    void setup_gdt();
    void setup_stack();
    void setup_peb(uint32_t image_base, uint32_t entry_point);
    void setup_teb();
    void setup_process_params(const std::string& image_name);
    void setup_ldr(uint32_t image_base, uint32_t image_size,
                   uint32_t entry_point, const std::string& image_name);

    /// Write a UTF-16LE string to the string pool, return its VA
    uint32_t write_unicode_string(const std::string& str);

    /// Write a UNICODE_STRING structure
    void write_unicode_struct(uint32_t addr, const std::string& str);
};

} // namespace vx
