/**
 * VXEngine Windows Environment Implementation
 *
 * Sets up a realistic Windows x86 process environment:
 *   - GDT with 8 segment descriptors
 *   - 1MB stack
 *   - PEB at 0x7FFD0000 with Ldr, ProcessHeap, ProcessParameters
 *   - TEB at 0x7FFD3000 with Self pointer (fs:[0x18]), PEB, TLS slots
 *   - Bump-allocator heap starting at 0x20000000
 *   - Module list (InLoadOrderModuleList linked list)
 */

#include "../include/vxengine/win_env.h"
#include <algorithm>
#include <cstring>

namespace vx {

// ============================================================
// EmulatedHeap
// ============================================================

EmulatedHeap::EmulatedHeap(VirtualMemory& vmem, uint32_t base, uint32_t max_size)
    : vmem_(vmem)
    , base_(base)
    , max_size_(max_size)
    , current_(base)
    , mapped_end_(base)
{
}

void EmulatedHeap::ensure_mapped(uint32_t end_addr) {
    while (mapped_end_ < end_addr) {
        uint64_t page = mapped_end_ & PAGE_MASK;
        if (!vmem_.is_mapped(page)) {
            vmem_.map(page, PAGE_SIZE, PERM_RW);
        }
        mapped_end_ = static_cast<uint32_t>(page + PAGE_SIZE);
    }
}

uint32_t EmulatedHeap::alloc(uint32_t size) {
    if (size == 0) size = 1;

    // Align to 16 bytes
    size = (size + 15) & ~15u;

    if (current_ + size < current_) return 0; // Overflow
    if (current_ + size > base_ + max_size_) return 0; // Exceeded max

    uint32_t addr = current_;
    current_ += size;

    // Ensure memory is mapped
    ensure_mapped(current_);

    // Zero-initialize
    vmem_.memset(addr, 0, size);

    // Track allocation
    allocs_[addr] = size;

    return addr;
}

void EmulatedHeap::free(uint32_t addr) {
    allocs_.erase(addr);
    // Bump allocator: memory is not actually reclaimed
}

uint32_t EmulatedHeap::realloc(uint32_t addr, uint32_t new_size) {
    if (addr == 0) return alloc(new_size);
    if (new_size == 0) { free(addr); return 0; }

    auto it = allocs_.find(addr);
    uint32_t old_size = 0;
    if (it != allocs_.end()) {
        old_size = it->second;
    }

    uint32_t new_addr = alloc(new_size);
    if (new_addr == 0) return 0;

    // Copy old data
    if (old_size > 0) {
        uint32_t copy_size = std::min(old_size, new_size);
        vmem_.memcpy(new_addr, addr, copy_size);
    }

    free(addr);
    return new_addr;
}

// ============================================================
// WindowsEnvironment construction
// ============================================================

WindowsEnvironment::WindowsEnvironment(VirtualMemory& vmem, X86Backend& cpu)
    : vmem_(vmem)
    , cpu_(cpu)
    , heap_(vmem)
{
}

// ============================================================
// Full initialization
// ============================================================

void WindowsEnvironment::initialize(uint32_t image_base, uint32_t image_size,
                                    uint32_t entry_point,
                                    const std::string& image_name)
{
    // Order matters: GDT first (sets up FS segment), then stack, then TEB/PEB
    setup_gdt();
    setup_stack();
    setup_peb(image_base, entry_point);
    setup_teb();
    setup_process_params(image_name);
    setup_ldr(image_base, image_size, entry_point, image_name);

    // Set initial register state
    cpu_.set_pc(entry_point);
    cpu_.set_sp(INITIAL_ESP);
    cpu_.set_reg(X86_EBP, INITIAL_EBP);

    // Set segment registers
    cpu_.set_reg(X86_CS, 0x0008); // GDT entry 1
    cpu_.set_reg(X86_DS, 0x0010); // GDT entry 2
    cpu_.set_reg(X86_ES, 0x0010); // Same as DS
    cpu_.set_reg(X86_SS, 0x0018); // GDT entry 3
    cpu_.set_reg(X86_FS, 0x0020); // GDT entry 4 (TEB)
    cpu_.set_reg(X86_GS, 0x0028); // GDT entry 5
}

// ============================================================
// GDT setup
// ============================================================

void WindowsEnvironment::setup_gdt() {
    GDTEntry gdt[GDT_ENTRY_COUNT] = {};

    // Entry 0: Null descriptor (required)
    gdt[0] = {0, 0, 0, 0};

    // Entry 1 (selector 0x08): Code segment (ring 3)
    //   base=0, limit=0xFFFFF, access=0xFB (present, DPL=3, code, readable)
    //   flags=0xCF (granularity=4KB, 32-bit)
    gdt[1] = {0x00000000, 0xFFFFF, 0xFB, 0xCF};

    // Entry 2 (selector 0x10): Data segment (ring 3)
    //   base=0, limit=0xFFFFF, access=0xF3 (present, DPL=3, data, writable)
    gdt[2] = {0x00000000, 0xFFFFF, 0xF3, 0xCF};

    // Entry 3 (selector 0x18): Stack segment (ring 3, same as data)
    gdt[3] = {0x00000000, 0xFFFFF, 0xF3, 0xCF};

    // Entry 4 (selector 0x20): FS segment (base = TEB address)
    //   access=0xF3 (present, DPL=3, data, writable)
    //   flags=0xCF (granularity=4KB, 32-bit)
    gdt[4] = {TEB_ADDRESS, 0xFFF, 0xF3, 0x40};

    // Entry 5 (selector 0x28): GS segment (base = 0)
    gdt[5] = {0x00000000, 0xFFFFF, 0xF3, 0xCF};

    // Entries 6-7: Spare (zeroed)
    gdt[6] = {0, 0, 0, 0};
    gdt[7] = {0, 0, 0, 0};

    cpu_.setup_gdt(gdt, GDT_ENTRY_COUNT);
}

// ============================================================
// Stack setup
// ============================================================

void WindowsEnvironment::setup_stack() {
    // Map 1MB stack
    vmem_.map(STACK_BASE, STACK_SIZE, PERM_RW);

    // Zero-fill stack
    vmem_.memset(STACK_BASE, 0, STACK_SIZE);

    // Write a fake return address at the top of stack (sentinel for "exit")
    // When main() returns, it will pop this and jump to it
    vmem_.write32(INITIAL_ESP, 0xDEAD0000);

    // Map the dead-return page so the CPU can detect it
    if (!vmem_.is_mapped(0xDEAD0000)) {
        vmem_.map(0xDEAD0000, PAGE_SIZE, PERM_RX);
    }
}

// ============================================================
// PEB setup
// ============================================================

void WindowsEnvironment::setup_peb(uint32_t image_base, uint32_t entry_point) {
    // Map PEB region (multiple pages for PEB + LDR + params + strings + modules)
    uint64_t region_base = PEB_ADDRESS & PAGE_MASK;
    uint64_t region_size = (STRING_POOL_ADDRESS + 0x2000) - region_base;
    region_size = (region_size + PAGE_SIZE - 1) & PAGE_MASK;
    vmem_.map(region_base, region_size, PERM_RW);

    // Zero the whole region
    vmem_.memset(region_base, 0, static_cast<size_t>(region_size));

    // Build PEB
    PEB32 peb = {};
    peb.InheritedAddressSpace = 0;
    peb.ReadImageFileExecOptions = 0;
    peb.BeingDebugged = 0;          // Not being debugged
    peb.ImageBaseAddress = image_base;
    peb.Ldr = PEB_LDR_ADDRESS;
    peb.ProcessParameters = PROCESS_PARAMS_ADDRESS;
    peb.ProcessHeap = heap_.base();
    peb.NtGlobalFlag = 0;           // No debug flags
    peb.NumberOfProcessors = 1;

    vmem_.write(PEB_ADDRESS, &peb, sizeof(peb));
}

// ============================================================
// TEB setup
// ============================================================

void WindowsEnvironment::setup_teb() {
    // TEB is already mapped as part of the PEB region (0x7FFD3000)
    // But ensure the TLS slots page is mapped too
    uint64_t tls_page = TLS_SLOTS_ADDRESS & PAGE_MASK;
    if (!vmem_.is_mapped(tls_page)) {
        vmem_.map(tls_page, PAGE_SIZE, PERM_RW);
    }

    TEB32 teb = {};
    teb.ExceptionList = 0xFFFFFFFF;     // End of SEH chain
    teb.StackBase = STACK_TOP;          // Top of stack (highest address)
    teb.StackLimit = STACK_BASE;        // Bottom of stack (lowest address)
    teb.Self = TEB_ADDRESS;             // fs:[0x18] -> TEB itself
    teb.ProcessEnvironmentBlock = PEB_ADDRESS;  // fs:[0x30] -> PEB
    teb.ClientId_UniqueProcess = 0x1000;  // Fake PID
    teb.ClientId_UniqueThread = 0x1004;   // Fake TID
    teb.LastErrorValue = 0;
    teb.ThreadLocalStoragePointer = TLS_SLOTS_ADDRESS;
    teb.CurrentLocale = 0x0409;         // en-US

    vmem_.write(TEB_ADDRESS, &teb, sizeof(teb));

    // Zero-fill TLS slots
    vmem_.memset(TLS_SLOTS_ADDRESS, 0, TLS_SLOT_COUNT * 4);
}

// ============================================================
// Process parameters
// ============================================================

void WindowsEnvironment::setup_process_params(const std::string& image_name) {
    // Build a simple image path like "C:\target.exe"
    std::string image_path = "C:\\" + image_name;
    std::string cmd_line = "\"" + image_path + "\"";
    std::string current_dir = "C:\\";

    RTL_USER_PROCESS_PARAMETERS32 params = {};
    params.MaximumLength = sizeof(RTL_USER_PROCESS_PARAMETERS32);
    params.Length = sizeof(RTL_USER_PROCESS_PARAMETERS32);
    params.Flags = 0x4001; // RTL_USER_PROC_PARAMS_NORMALIZED
    params.ConsoleHandle = 0;
    params.StdInputHandle = 0xFFFFFFF6;   // STD_INPUT_HANDLE
    params.StdOutputHandle = 0xFFFFFFF5;  // STD_OUTPUT_HANDLE
    params.StdErrorHandle = 0xFFFFFFF4;   // STD_ERROR_HANDLE

    vmem_.write(PROCESS_PARAMS_ADDRESS, &params, sizeof(params));

    // Write the UNICODE_STRING fields
    write_unicode_struct(PROCESS_PARAMS_ADDRESS + 0x24, current_dir);  // CurrentDirectory
    write_unicode_struct(PROCESS_PARAMS_ADDRESS + 0x38, image_path);   // ImagePathName
    write_unicode_struct(PROCESS_PARAMS_ADDRESS + 0x40, cmd_line);     // CommandLine
}

// ============================================================
// Loader data (PEB_LDR_DATA + module list)
// ============================================================

void WindowsEnvironment::setup_ldr(uint32_t image_base, uint32_t image_size,
                                   uint32_t entry_point,
                                   const std::string& image_name)
{
    // Initialize PEB_LDR_DATA with empty circular lists pointing to themselves
    PEB_LDR_DATA32 ldr = {};
    ldr.Length = sizeof(PEB_LDR_DATA32);
    ldr.Initialized = 1;

    // Initially, all three lists are circular (Flink=Blink=&list_head)
    uint32_t load_order_head   = PEB_LDR_ADDRESS + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList);
    uint32_t memory_order_head = PEB_LDR_ADDRESS + offsetof(PEB_LDR_DATA32, InMemoryOrderModuleList);
    uint32_t init_order_head   = PEB_LDR_ADDRESS + offsetof(PEB_LDR_DATA32, InInitializationOrderModuleList);

    ldr.InLoadOrderModuleList.Flink = load_order_head;
    ldr.InLoadOrderModuleList.Blink = load_order_head;
    ldr.InMemoryOrderModuleList.Flink = memory_order_head;
    ldr.InMemoryOrderModuleList.Blink = memory_order_head;
    ldr.InInitializationOrderModuleList.Flink = init_order_head;
    ldr.InInitializationOrderModuleList.Blink = init_order_head;

    vmem_.write(PEB_LDR_ADDRESS, &ldr, sizeof(ldr));

    // Add the main executable module
    add_module(image_name, image_base, image_size, entry_point);

    // Add fake ntdll.dll and kernel32.dll entries (no actual code, just list presence)
    add_module("ntdll.dll",     0x77000000, 0x00180000, 0x77000000);
    add_module("kernel32.dll",  0x76000000, 0x00110000, 0x76000000);
}

// ============================================================
// Add a module to the PEB loader list
// ============================================================

void WindowsEnvironment::add_module(const std::string& name,
                                    uint32_t base, uint32_t size,
                                    uint32_t entry)
{
    // Build LDR_DATA_TABLE_ENTRY
    uint32_t entry_addr = next_module_entry_;
    next_module_entry_ += sizeof(LDR_DATA_TABLE_ENTRY32) + 0x10; // +padding

    // Ensure the module entry area is mapped
    uint64_t entry_page = entry_addr & PAGE_MASK;
    if (!vmem_.is_mapped(entry_page)) {
        vmem_.map(entry_page, PAGE_SIZE, PERM_RW);
    }

    // Write unicode strings for module name
    std::string full_path = "C:\\Windows\\System32\\" + name;
    uint32_t full_name_va = write_unicode_string(full_path);
    uint32_t base_name_va = write_unicode_string(name);

    LDR_DATA_TABLE_ENTRY32 ldr_entry = {};
    ldr_entry.DllBase = base;
    ldr_entry.EntryPoint = entry;
    ldr_entry.SizeOfImage = size;

    // FullDllName
    ldr_entry.FullDllName.Length = static_cast<uint16_t>(full_path.size() * 2);
    ldr_entry.FullDllName.MaximumLength = static_cast<uint16_t>(full_path.size() * 2 + 2);
    ldr_entry.FullDllName.Buffer = full_name_va;

    // BaseDllName
    ldr_entry.BaseDllName.Length = static_cast<uint16_t>(name.size() * 2);
    ldr_entry.BaseDllName.MaximumLength = static_cast<uint16_t>(name.size() * 2 + 2);
    ldr_entry.BaseDllName.Buffer = base_name_va;

    ldr_entry.Flags = 0x00004004; // LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED
    ldr_entry.LoadCount = 1;

    // Insert into InLoadOrderModuleList (at tail)
    uint32_t load_order_head = PEB_LDR_ADDRESS +
        offsetof(PEB_LDR_DATA32, InLoadOrderModuleList);
    uint32_t entry_load_link = entry_addr +
        offsetof(LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

    // Read current tail
    uint32_t old_blink = vmem_.read32(load_order_head + 4); // list_head.Blink

    // New entry: Flink -> head, Blink -> old_tail
    ldr_entry.InLoadOrderLinks.Flink = load_order_head;
    ldr_entry.InLoadOrderLinks.Blink = old_blink;

    // Write the entry
    vmem_.write(entry_addr, &ldr_entry, sizeof(ldr_entry));

    // Patch old tail's Flink to point to new entry
    vmem_.write32(old_blink, entry_load_link);  // old_tail.Flink = new_entry

    // Patch list head's Blink to point to new entry
    vmem_.write32(load_order_head + 4, entry_load_link); // head.Blink = new_entry

    // Also link InMemoryOrderLinks (offset +0x08 in the entry)
    uint32_t memory_order_head = PEB_LDR_ADDRESS +
        offsetof(PEB_LDR_DATA32, InMemoryOrderModuleList);
    uint32_t entry_mem_link = entry_addr +
        offsetof(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

    uint32_t old_mem_blink = vmem_.read32(memory_order_head + 4);
    vmem_.write32(entry_addr + offsetof(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks),
                  memory_order_head);     // Flink
    vmem_.write32(entry_addr + offsetof(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks) + 4,
                  old_mem_blink);         // Blink
    vmem_.write32(old_mem_blink, entry_mem_link);
    vmem_.write32(memory_order_head + 4, entry_mem_link);

    // Also link InInitializationOrderLinks
    uint32_t init_order_head = PEB_LDR_ADDRESS +
        offsetof(PEB_LDR_DATA32, InInitializationOrderModuleList);
    uint32_t entry_init_link = entry_addr +
        offsetof(LDR_DATA_TABLE_ENTRY32, InInitializationOrderLinks);

    uint32_t old_init_blink = vmem_.read32(init_order_head + 4);
    vmem_.write32(entry_addr + offsetof(LDR_DATA_TABLE_ENTRY32, InInitializationOrderLinks),
                  init_order_head);       // Flink
    vmem_.write32(entry_addr + offsetof(LDR_DATA_TABLE_ENTRY32, InInitializationOrderLinks) + 4,
                  old_init_blink);        // Blink
    vmem_.write32(old_init_blink, entry_init_link);
    vmem_.write32(init_order_head + 4, entry_init_link);
}

// ============================================================
// Unicode string helpers
// ============================================================

uint32_t WindowsEnvironment::write_unicode_string(const std::string& str) {
    uint32_t va = string_pool_ptr_;

    // Ensure mapped
    uint64_t page = va & PAGE_MASK;
    uint64_t end_page = ((va + str.size() * 2 + 2) + PAGE_SIZE - 1) & PAGE_MASK;
    for (uint64_t p = page; p < end_page; p += PAGE_SIZE) {
        if (!vmem_.is_mapped(p)) {
            vmem_.map(p, PAGE_SIZE, PERM_RW);
        }
    }

    // Write UTF-16LE (simple ASCII -> UTF-16)
    for (size_t i = 0; i < str.size(); ++i) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
        vmem_.write(va + i * 2, &wc, 2);
    }
    // Null terminator
    uint16_t null_term = 0;
    vmem_.write(va + str.size() * 2, &null_term, 2);

    string_pool_ptr_ += static_cast<uint32_t>((str.size() + 1) * 2);
    // Align to 4 bytes
    string_pool_ptr_ = (string_pool_ptr_ + 3) & ~3u;

    return va;
}

void WindowsEnvironment::write_unicode_struct(uint32_t addr, const std::string& str) {
    uint32_t buf_va = write_unicode_string(str);

    UNICODE_STRING32 us;
    us.Length = static_cast<uint16_t>(str.size() * 2);
    us.MaximumLength = static_cast<uint16_t>(str.size() * 2 + 2);
    us.Buffer = buf_va;

    vmem_.write(addr, &us, sizeof(us));
}

} // namespace vx
