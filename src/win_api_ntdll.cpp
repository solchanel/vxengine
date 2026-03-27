/**
 * VXEngine NT Native API, Syscall Interception, and Device I/O
 *
 * Implements:
 *   - 40+ ntdll.dll native API handlers
 *   - SyscallInterceptor with Windows 10 syscall number mappings
 *   - DeviceIOInterceptor with IOCTL dispatch and built-in handlers
 *   - Anti-debug bypasses (NtQueryInformationProcess, NtSetInformationThread)
 *   - Ldr* module loading stubs
 *   - Rtl* runtime library functions
 *
 * All handlers use the same register_native() pattern as win_api.cpp.
 */

#include "../include/vxengine/win_api.h"
#include "../include/vxengine/win_api_ntdll.h"
#include <algorithm>
#include <cstring>
#include <cctype>

namespace vx {

// ============================================================
// Helpers (shared with win_api_extended.cpp via duplication — could be factored)
// ============================================================

static std::string ntdll_read_wide_string(VirtualMemory& vmem, uint64_t addr, size_t max = 2048) {
    std::string result;
    for (size_t i = 0; i < max; i++) {
        uint16_t wc = static_cast<uint16_t>(vmem.read32(addr + i * 2) & 0xFFFF);
        if (wc == 0) break;
        result.push_back(static_cast<char>(wc & 0xFF));
    }
    return result;
}

static void ntdll_write_wide_string(VirtualMemory& vmem, uint64_t addr, const std::string& str) {
    for (size_t i = 0; i < str.size(); i++) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
        vmem.write(addr + i * 2, &wc, 2);
    }
    uint16_t null = 0;
    vmem.write(addr + str.size() * 2, &null, 2);
}

// Stdcall return helper
static void ntdll_stdcall_ret(X86Backend& cpu, VirtualMemory& vmem,
                              uint32_t retval, uint32_t arg_bytes) {
    cpu.set_reg(X86_EAX, retval);
    uint32_t esp = static_cast<uint32_t>(cpu.sp());
    uint32_t ret = vmem.read32(esp);
    cpu.set_sp(esp + 4 + arg_bytes);
    cpu.set_pc(ret);
}

// Convert Windows protection constant to vx::Perm
static uint8_t win_prot_to_perm(uint32_t protect) {
    if (protect & PAGE_EXECUTE_READWRITE) return PERM_RWX;
    if (protect & PAGE_EXECUTE_READ)      return PERM_RX;
    if (protect & PAGE_READWRITE)         return PERM_RW;
    if (protect & PAGE_READONLY)          return PERM_READ;
    if (protect & PAGE_EXECUTE)           return PERM_EXEC;
    return PERM_RW;
}

// Fake constants
constexpr uint32_t FAKE_PID_NT       = 0x1000;
constexpr uint32_t FAKE_TID_NT       = 0x1004;
constexpr uint32_t FAKE_PROCESS_H    = 0xFFFFFFFF;
constexpr uint32_t FAKE_THREAD_H     = 0xFFFFFFFE;

// VEH handler tracking
static uint32_t veh_first_handler_ = 0;
static uint32_t veh_last_handler_ = 0;

// ============================================================
// SyscallInterceptor implementation
// ============================================================

void SyscallInterceptor::register_syscall(uint32_t number, const std::string& name,
                                           NativeAPIHandler handler) {
    syscall_table_[number] = {number, name, std::move(handler), false};
}

bool SyscallInterceptor::handle_syscall(uint32_t number, X86Backend& cpu,
                                         VirtualMemory& vmem, EmulatedHeap& heap) {
    auto it = syscall_table_.find(number);
    if (it == syscall_table_.end()) return false;

    if (logging_enabled_) {
        // Log syscall number + first 4 args from stack/registers
        std::vector<uint32_t> args;
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        for (int i = 0; i < 4; i++) {
            args.push_back(vmem.read32(esp + 4 + i * 4));
        }
        syscall_log_.emplace_back(number, std::move(args));
    }

    it->second.handler(cpu, vmem, heap);
    return true;
}

void SyscallInterceptor::register_win10_syscalls(APIDispatcher& disp) {
    // Windows 10 22H2 x86 syscall numbers
    // These map directly to the Nt* handlers registered below.

    // We register stub handlers that delegate to the named API handlers.
    // The syscall entry reads args from the stack (EDX points to user stack
    // in int 0x2e / sysenter convention).

    // NtAllocateVirtualMemory = 0x0018
    register_syscall(0x0018, "NtAllocateVirtualMemory",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Args: ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, AllocType, Protect
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t base_ptr   = vmem.read32(esp + 8);
            uint32_t size_ptr   = vmem.read32(esp + 16);
            uint32_t type       = vmem.read32(esp + 20);
            uint32_t protect    = vmem.read32(esp + 24);

            uint32_t base = (base_ptr != 0) ? vmem.read32(base_ptr) : 0;
            uint32_t size = (size_ptr != 0) ? vmem.read32(size_ptr) : 0;

            uint8_t perms = win_prot_to_perm(protect);
            uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
            if (aligned == 0) aligned = PAGE_SIZE;

            if (base == 0) {
                static uint32_t nt_va_ptr = 0x32000000;
                base = nt_va_ptr;
                nt_va_ptr += static_cast<uint32_t>(aligned);
            }
            vmem.map(base, aligned, perms);
            vmem.memset(base, 0, static_cast<size_t>(aligned));

            if (base_ptr != 0) vmem.write32(base_ptr, base);
            if (size_ptr != 0) vmem.write32(size_ptr, static_cast<uint32_t>(aligned));

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 24);
            return 24;
        });

    // NtClose = 0x000F
    register_syscall(0x000F, "NtClose",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // NtCreateFile = 0x0055
    register_syscall(0x0055, "NtCreateFile",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 4);
            if (handle_ptr != 0) vmem.write32(handle_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 44); // 11 args
            return 44;
        });

    // NtQueryInformationProcess = 0x0019
    register_syscall(0x0019, "NtQueryInformationProcess",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t info_class = vmem.read32(esp + 8);
            uint32_t buf        = vmem.read32(esp + 12);
            uint32_t buf_len    = vmem.read32(esp + 16);
            uint32_t ret_len    = vmem.read32(esp + 20);

            if (info_class == ProcessDebugPort && buf_len >= 4) {
                vmem.write32(buf, 0); // No debug port — anti-debug bypass
                if (ret_len != 0) vmem.write32(ret_len, 4);
            } else if (info_class == ProcessDebugFlags && buf_len >= 4) {
                vmem.write32(buf, 1); // PROCESS_DEBUG_FLAGS: 1 = no debugger
                if (ret_len != 0) vmem.write32(ret_len, 4);
            } else if (info_class == ProcessDebugObjectHandle) {
                ntdll_stdcall_ret(cpu, vmem, STATUS_PORT_NOT_CONNECTED, 20);
                return 20;
            } else if (info_class == ProcessBasicInformation && buf_len >= 24) {
                // PROCESS_BASIC_INFORMATION: 24 bytes
                vmem.memset(buf, 0, 24);
                vmem.write32(buf + 4, PEB_ADDRESS); // PebBaseAddress
                vmem.write32(buf + 16, FAKE_PID_NT);// UniqueProcessId
                if (ret_len != 0) vmem.write32(ret_len, 24);
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // NtQueryVirtualMemory = 0x0023
    register_syscall(0x0023, "NtQueryVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t addr     = vmem.read32(esp + 8);
            uint32_t info_cls = vmem.read32(esp + 12);
            uint32_t buf      = vmem.read32(esp + 16);
            uint32_t buf_len  = vmem.read32(esp + 20);
            uint32_t ret_len  = vmem.read32(esp + 24);

            if (info_cls == 0 && buf_len >= 28) { // MemoryBasicInformation
                MEMORY_BASIC_INFORMATION32 mbi = {};
                uint32_t page_addr = addr & static_cast<uint32_t>(PAGE_MASK);

                uint32_t fake_prot = 0, fake_type = 0;
                if (vmem.get_fake_attrs(addr, fake_prot, fake_type)) {
                    mbi.BaseAddress = page_addr;
                    mbi.AllocationBase = page_addr;
                    mbi.AllocationProtect = fake_prot;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_COMMIT;
                    mbi.Protect = fake_prot;
                    mbi.Type = fake_type;
                } else if (vmem.is_mapped(addr)) {
                    mbi.BaseAddress = page_addr;
                    mbi.AllocationBase = page_addr;
                    mbi.AllocationProtect = PAGE_READWRITE;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_COMMIT;
                    mbi.Protect = PAGE_READWRITE;
                    mbi.Type = 0x20000;
                } else {
                    mbi.BaseAddress = page_addr;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_FREE;
                    mbi.Protect = PAGE_NOACCESS;
                }
                vmem.write(buf, &mbi, sizeof(mbi));
                if (ret_len != 0) vmem.write32(ret_len, sizeof(mbi));
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 24);
            return 24;
        });

    // NtProtectVirtualMemory = 0x0050
    register_syscall(0x0050, "NtProtectVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t base_ptr    = vmem.read32(esp + 8);
            uint32_t size_ptr    = vmem.read32(esp + 12);
            uint32_t new_prot    = vmem.read32(esp + 16);
            uint32_t old_prot_p  = vmem.read32(esp + 20);

            if (old_prot_p != 0) vmem.write32(old_prot_p, PAGE_READWRITE);

            uint32_t base = (base_ptr != 0) ? vmem.read32(base_ptr) : 0;
            uint32_t size = (size_ptr != 0) ? vmem.read32(size_ptr) : 0;

            uint8_t perms = win_prot_to_perm(new_prot);
            uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
            if (base != 0 && aligned > 0) vmem.protect(base, aligned, perms);

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // NtFreeVirtualMemory = 0x001E
    register_syscall(0x001E, "NtFreeVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t base_ptr = vmem.read32(esp + 8);
            uint32_t size_ptr = vmem.read32(esp + 12);
            uint32_t type     = vmem.read32(esp + 16);

            if ((type & MEM_RELEASE) && base_ptr != 0) {
                uint32_t base = vmem.read32(base_ptr);
                // Best-effort unmap
                vmem.unmap(base, PAGE_SIZE);
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });
}

// ============================================================
// DeviceIOInterceptor implementation
// ============================================================

void DeviceIOInterceptor::register_ioctl(uint32_t code, const std::string& device,
                                          IOCTLHandlerFn handler) {
    ioctl_handlers_[code] = {code, device, std::move(handler)};
}

uint32_t DeviceIOInterceptor::handle_device_io_control(
    VirtualMemory& vmem,
    uint32_t ioctl_code,
    uint64_t in_buf, uint32_t in_size,
    uint64_t out_buf, uint32_t out_size,
    uint64_t bytes_returned_ptr)
{
    auto it = ioctl_handlers_.find(ioctl_code);
    if (it == ioctl_handlers_.end()) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    uint32_t result = it->second.handler(vmem, in_buf, in_size, out_buf, out_size);

    if (bytes_returned_ptr != 0 && result == STATUS_SUCCESS) {
        vmem.write32(static_cast<uint32_t>(bytes_returned_ptr), out_size);
    }

    return result;
}

void DeviceIOInterceptor::register_builtins() {
    // IOCTL_DISK_GET_DRIVE_GEOMETRY = CTL_CODE(7, 0, 0, 0) = 0x00070000
    register_ioctl(0x00070000, "\\\\.\\PhysicalDrive0",
        [](VirtualMemory& vmem, uint64_t in_buf, uint32_t in_size,
           uint64_t out_buf, uint32_t out_size) -> uint32_t {
            // DISK_GEOMETRY: 24 bytes
            if (out_size < 24 || out_buf == 0) return STATUS_BUFFER_TOO_SMALL;
            vmem.memset(static_cast<uint32_t>(out_buf), 0, 24);
            // Fake: 1000 cylinders, type=FixedMedia(12), 255 tracks/cyl, 63 sectors/track, 512 bytes/sector
            vmem.write32(static_cast<uint32_t>(out_buf), 1000);  // Cylinders.LowPart
            vmem.write32(static_cast<uint32_t>(out_buf + 4), 0); // Cylinders.HighPart
            vmem.write32(static_cast<uint32_t>(out_buf + 8), 12);// MediaType = FixedMedia
            vmem.write32(static_cast<uint32_t>(out_buf + 12), 255); // TracksPerCylinder
            vmem.write32(static_cast<uint32_t>(out_buf + 16), 63);  // SectorsPerTrack
            vmem.write32(static_cast<uint32_t>(out_buf + 20), 512); // BytesPerSector
            return STATUS_SUCCESS;
        });

    // Null device — accept everything
    register_ioctl(0xFFFFFFFF, "\\\\.\\NUL",
        [](VirtualMemory&, uint64_t, uint32_t, uint64_t, uint32_t) -> uint32_t {
            return STATUS_SUCCESS;
        });
}

// ============================================================
// register_ntdll_apis — main entry point
// ============================================================

void register_ntdll_apis(APIDispatcher& disp) {

    // Static interceptors (persist across calls)
    static SyscallInterceptor syscall_interceptor;
    static DeviceIOInterceptor device_io_interceptor;
    device_io_interceptor.register_builtins();

    // ================================================================
    // NT API — Process/Thread Information
    // ================================================================

    // ---- NtQueryInformationProcess(ProcessHandle, InfoClass, Buffer, BufLen, ReturnLength) ----
    disp.register_native("NtQueryInformationProcess",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t info_class = vmem.read32(esp + 8);
            uint32_t buf        = vmem.read32(esp + 12);
            uint32_t buf_len    = vmem.read32(esp + 16);
            uint32_t ret_len    = vmem.read32(esp + 20);

            uint32_t status = STATUS_SUCCESS;

            if (info_class == ProcessDebugPort && buf_len >= 4) {
                vmem.write32(buf, 0); // Anti-debug: no debug port
                if (ret_len != 0) vmem.write32(ret_len, 4);
            } else if (info_class == ProcessDebugFlags && buf_len >= 4) {
                vmem.write32(buf, 1); // Anti-debug: flags indicate no debugger
                if (ret_len != 0) vmem.write32(ret_len, 4);
            } else if (info_class == ProcessDebugObjectHandle) {
                status = STATUS_PORT_NOT_CONNECTED; // Anti-debug: no debug object
            } else if (info_class == ProcessBasicInformation && buf_len >= 24) {
                vmem.memset(buf, 0, 24);
                vmem.write32(buf + 4, PEB_ADDRESS);
                vmem.write32(buf + 16, FAKE_PID_NT);
                if (ret_len != 0) vmem.write32(ret_len, 24);
            } else {
                if (buf != 0 && buf_len > 0) vmem.memset(buf, 0, buf_len);
                if (ret_len != 0) vmem.write32(ret_len, buf_len);
            }

            ntdll_stdcall_ret(cpu, vmem, status, 20);
            return 20;
        });

    // ---- NtQueryInformationThread(ThreadHandle, InfoClass, Buffer, BufLen, ReturnLength) ----
    disp.register_native("NtQueryInformationThread",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t buf     = vmem.read32(esp + 12);
            uint32_t buf_len = vmem.read32(esp + 16);
            if (buf != 0 && buf_len > 0) vmem.memset(buf, 0, buf_len);
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // ---- NtSetInformationThread(ThreadHandle, InfoClass, Buffer, BufLen) ----
    disp.register_native("NtSetInformationThread",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t info_class = vmem.read32(esp + 8);
            // ThreadHideFromDebugger = 0x11: silently ignore for anti-debug bypass
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- NtQuerySystemInformation(SystemInfoClass, Buffer, BufLen, ReturnLength) ----
    disp.register_native("NtQuerySystemInformation",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t info_class = vmem.read32(esp + 4);
            uint32_t buf        = vmem.read32(esp + 8);
            uint32_t buf_len    = vmem.read32(esp + 12);
            uint32_t ret_len    = vmem.read32(esp + 16);

            if (info_class == SystemBasicInformation && buf_len >= 44) {
                vmem.memset(buf, 0, 44);
                vmem.write32(buf + 0, 0);          // Reserved
                vmem.write32(buf + 4, 0x1000);     // TimerResolution
                vmem.write32(buf + 8, 0x1000);     // PageSize
                vmem.write32(buf + 12, 0x100000);  // NumberOfPhysicalPages
                vmem.write32(buf + 16, 0x100);     // LowestPhysicalPageNumber
                vmem.write32(buf + 20, 0x100000);  // HighestPhysicalPageNumber
                vmem.write32(buf + 24, 0x1000);    // AllocationGranularity
                vmem.write32(buf + 28, 0x00010000);// MinimumUserModeAddress
                vmem.write32(buf + 32, 0x7FFEFFFF);// MaximumUserModeAddress
                vmem.write32(buf + 36, 0x0F);      // ActiveProcessorsAffinityMask
                vmem.write32(buf + 40, 4);         // NumberOfProcessors
                if (ret_len != 0) vmem.write32(ret_len, 44);
            } else {
                if (buf != 0 && buf_len > 0) vmem.memset(buf, 0, std::min(buf_len, 1024u));
                if (ret_len != 0) vmem.write32(ret_len, 0);
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- NtQueryVirtualMemory(ProcessHandle, BaseAddress, InfoClass, Buffer, BufLen, RetLen) ----
    disp.register_native("NtQueryVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t addr     = vmem.read32(esp + 8);
            uint32_t info_cls = vmem.read32(esp + 12);
            uint32_t buf      = vmem.read32(esp + 16);
            uint32_t buf_len  = vmem.read32(esp + 20);
            uint32_t ret_len  = vmem.read32(esp + 24);

            if (info_cls == 0 && buf_len >= sizeof(MEMORY_BASIC_INFORMATION32)) {
                MEMORY_BASIC_INFORMATION32 mbi = {};
                uint32_t page_addr = addr & static_cast<uint32_t>(PAGE_MASK);

                uint32_t fake_prot = 0, fake_type = 0;
                if (vmem.get_fake_attrs(addr, fake_prot, fake_type)) {
                    mbi.BaseAddress = page_addr;
                    mbi.AllocationBase = page_addr;
                    mbi.AllocationProtect = fake_prot;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_COMMIT;
                    mbi.Protect = fake_prot;
                    mbi.Type = fake_type;
                } else if (vmem.is_mapped(addr)) {
                    mbi.BaseAddress = page_addr;
                    mbi.AllocationBase = page_addr;
                    mbi.AllocationProtect = PAGE_READWRITE;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_COMMIT;
                    mbi.Protect = PAGE_READWRITE;
                    mbi.Type = 0x20000;
                } else {
                    mbi.BaseAddress = page_addr;
                    mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
                    mbi.State = MEM_FREE;
                    mbi.Protect = PAGE_NOACCESS;
                }
                vmem.write(buf, &mbi, sizeof(mbi));
                if (ret_len != 0) vmem.write32(ret_len, sizeof(mbi));
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 24);
            return 24;
        });

    // ================================================================
    // NT API — Memory
    // ================================================================

    // ---- NtAllocateVirtualMemory(ProcessH, *BaseAddr, ZeroBits, *RegionSize, AllocType, Protect) ----
    disp.register_native("NtAllocateVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t base_ptr = vmem.read32(esp + 8);
            uint32_t size_ptr = vmem.read32(esp + 16);
            uint32_t type     = vmem.read32(esp + 20);
            uint32_t protect  = vmem.read32(esp + 24);

            uint32_t base = (base_ptr != 0) ? vmem.read32(base_ptr) : 0;
            uint32_t size = (size_ptr != 0) ? vmem.read32(size_ptr) : 0;

            uint8_t perms = win_prot_to_perm(protect);
            uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
            if (aligned == 0) aligned = PAGE_SIZE;

            if (base == 0) {
                static uint32_t nt_alloc = 0x33000000;
                base = nt_alloc;
                nt_alloc += static_cast<uint32_t>(aligned);
            }
            vmem.map(base, aligned, perms);
            vmem.memset(base, 0, static_cast<size_t>(aligned));

            if (base_ptr != 0) vmem.write32(base_ptr, base);
            if (size_ptr != 0) vmem.write32(size_ptr, static_cast<uint32_t>(aligned));

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 24);
            return 24;
        });

    // ---- NtFreeVirtualMemory ----
    disp.register_native("NtFreeVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- NtProtectVirtualMemory ----
    disp.register_native("NtProtectVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t old_prot_p = vmem.read32(esp + 20);
            if (old_prot_p != 0) vmem.write32(old_prot_p, PAGE_READWRITE);
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // ---- NtReadVirtualMemory(ProcessH, BaseAddr, Buffer, Size, *BytesRead) ----
    disp.register_native("NtReadVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t src  = vmem.read32(esp + 8);
            uint32_t dst  = vmem.read32(esp + 12);
            uint32_t size = vmem.read32(esp + 16);
            uint32_t read_ptr = vmem.read32(esp + 20);

            if (dst != 0 && src != 0 && size > 0) {
                vmem.memcpy(dst, src, size);
            }
            if (read_ptr != 0) vmem.write32(read_ptr, size);

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // ---- NtWriteVirtualMemory(ProcessH, BaseAddr, Buffer, Size, *BytesWritten) ----
    disp.register_native("NtWriteVirtualMemory",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t dst  = vmem.read32(esp + 8);
            uint32_t src  = vmem.read32(esp + 12);
            uint32_t size = vmem.read32(esp + 16);
            uint32_t written_ptr = vmem.read32(esp + 20);

            if (dst != 0 && src != 0 && size > 0) {
                vmem.memcpy(dst, src, size);
            }
            if (written_ptr != 0) vmem.write32(written_ptr, size);

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // ================================================================
    // NT API — Object/Handle
    // ================================================================

    // ---- NtOpenProcess(ProcessHandle*, DesiredAccess, ObjectAttributes*, ClientId*) ----
    disp.register_native("NtOpenProcess",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 4);
            if (handle_ptr != 0) vmem.write32(handle_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- NtClose(Handle) ----
    disp.register_native("NtClose",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- NtQueryObject(Handle, ObjectInfoClass, Buffer, BufLen, RetLen) ----
    disp.register_native("NtQueryObject",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t buf     = vmem.read32(esp + 12);
            uint32_t buf_len = vmem.read32(esp + 16);
            if (buf != 0 && buf_len > 0) vmem.memset(buf, 0, std::min(buf_len, 256u));
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 20);
            return 20;
        });

    // ---- NtDuplicateObject(SrcProcess, SrcHandle, TgtProcess, TgtHandle*, Access, Attrs, Options) ----
    disp.register_native("NtDuplicateObject",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t tgt_ptr = vmem.read32(esp + 16);
            if (tgt_ptr != 0) vmem.write32(tgt_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 28);
            return 28;
        });

    // ================================================================
    // NT API — File I/O
    // ================================================================

    // ---- NtCreateFile ----
    disp.register_native("NtCreateFile",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 4);
            if (handle_ptr != 0) vmem.write32(handle_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 44);
            return 44;
        });

    // ---- NtOpenFile(FileHandle*, Access, ObjectAttrs*, IoStatusBlock*, ShareAccess, OpenOptions) ----
    disp.register_native("NtOpenFile",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 4);
            if (handle_ptr != 0) vmem.write32(handle_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 24);
            return 24;
        });

    // ---- NtReadFile(FileH, Event, ApcRoutine, ApcCtx, IoStatus, Buffer, Length, ByteOffset, Key) ----
    disp.register_native("NtReadFile",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t io_status = vmem.read32(esp + 20);
            if (io_status != 0) {
                vmem.write32(io_status, STATUS_SUCCESS);
                vmem.write32(io_status + 4, 0); // 0 bytes read
            }
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 36);
            return 36;
        });

    // ---- NtWriteFile ----
    disp.register_native("NtWriteFile",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t io_status = vmem.read32(esp + 20);
            uint32_t length    = vmem.read32(esp + 28);
            if (io_status != 0) {
                vmem.write32(io_status, STATUS_SUCCESS);
                vmem.write32(io_status + 4, length);
            }
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 36);
            return 36;
        });

    // ---- NtDeviceIoControlFile(FileH, Event, ApcRoutine, ApcCtx, IoStatus,
    //                            IoControlCode, InBuf, InBufLen, OutBuf, OutBufLen) ----
    disp.register_native("NtDeviceIoControlFile",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t io_status = vmem.read32(esp + 20);
            uint32_t ioctl     = vmem.read32(esp + 24);
            uint32_t in_buf    = vmem.read32(esp + 28);
            uint32_t in_size   = vmem.read32(esp + 32);
            uint32_t out_buf   = vmem.read32(esp + 36);
            uint32_t out_size  = vmem.read32(esp + 40);

            uint32_t status = device_io_interceptor.handle_device_io_control(
                vmem, ioctl, in_buf, in_size, out_buf, out_size,
                io_status ? io_status + 4 : 0);

            if (io_status != 0) vmem.write32(io_status, status);
            ntdll_stdcall_ret(cpu, vmem, status, 40);
            return 40;
        });

    // ---- DeviceIoControl (kernel32 wrapper) ----
    disp.register_native("DeviceIoControl",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // DeviceIoControl(hDevice, dwIoControlCode, lpInBuf, nInBufSize,
            //                 lpOutBuf, nOutBufSize, lpBytesReturned, lpOverlapped)
            uint32_t ioctl   = vmem.read32(esp + 8);
            uint32_t in_buf  = vmem.read32(esp + 12);
            uint32_t in_size = vmem.read32(esp + 16);
            uint32_t out_buf = vmem.read32(esp + 20);
            uint32_t out_size= vmem.read32(esp + 24);
            uint32_t ret_ptr = vmem.read32(esp + 28);

            uint32_t status = device_io_interceptor.handle_device_io_control(
                vmem, ioctl, in_buf, in_size, out_buf, out_size, ret_ptr);

            uint32_t success = (status == STATUS_SUCCESS) ? 1u : 0u;
            ntdll_stdcall_ret(cpu, vmem, success, 32);
            return 32;
        });

    // ================================================================
    // NT API — Thread
    // ================================================================

    // ---- NtCreateThreadEx — stub ----
    disp.register_native("NtCreateThreadEx",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 4);
            if (handle_ptr != 0) vmem.write32(handle_ptr, disp.alloc_handle());
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 44);
            return 44;
        });

    // ---- NtDelayExecution(Alertable, *DelayInterval) ----
    disp.register_native("NtDelayExecution",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            // Just continue — no actual delay in emulation
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 8);
            return 8;
        });

    // ---- NtYieldExecution() ----
    disp.register_native("NtYieldExecution",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 0);
            return 0;
        });

    // ---- NtQueryPerformanceCounter(PerformanceCounter*, PerformanceFrequency*) ----
    disp.register_native("NtQueryPerformanceCounter",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t counter_ptr = vmem.read32(esp + 4);
            uint32_t freq_ptr    = vmem.read32(esp + 8);

            static uint64_t nt_perf = 2000000;
            nt_perf += 1000;

            if (counter_ptr != 0) {
                vmem.write32(counter_ptr, static_cast<uint32_t>(nt_perf & 0xFFFFFFFF));
                vmem.write32(counter_ptr + 4, static_cast<uint32_t>(nt_perf >> 32));
            }
            if (freq_ptr != 0) {
                uint64_t freq = 10000000;
                vmem.write32(freq_ptr, static_cast<uint32_t>(freq & 0xFFFFFFFF));
                vmem.write32(freq_ptr + 4, static_cast<uint32_t>(freq >> 32));
            }

            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 8);
            return 8;
        });

    // ---- NtGetContextThread / NtSetContextThread — stubs ----
    disp.register_native("NtGetContextThread",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ctx_ptr = vmem.read32(esp + 8);
            // Fill with current register state (simplified: zero out)
            if (ctx_ptr != 0) vmem.memset(ctx_ptr, 0, 716); // sizeof(CONTEXT)
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 8);
            return 8;
        });

    disp.register_native("NtSetContextThread",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            // Ignore — don't let malware modify thread context
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 8);
            return 8;
        });

    // ================================================================
    // Rtl* — Runtime Library
    // ================================================================

    // ---- RtlInitUnicodeString(DestinationString, SourceString) ----
    disp.register_native("RtlInitUnicodeString",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t dest = vmem.read32(esp + 4);
            uint32_t src  = vmem.read32(esp + 8);

            if (dest != 0 && src != 0) {
                // UNICODE_STRING: Length(2), MaximumLength(2), Buffer(4)
                uint32_t len = 0;
                for (uint32_t i = 0; i < 4096; i++) {
                    uint16_t wc = static_cast<uint16_t>(vmem.read32(src + i * 2) & 0xFFFF);
                    if (wc == 0) { len = i; break; }
                }
                uint16_t byte_len = static_cast<uint16_t>(len * 2);
                vmem.write(dest, &byte_len, 2);                    // Length
                uint16_t max_len = byte_len + 2;
                vmem.write(dest + 2, &max_len, 2);                // MaximumLength
                vmem.write32(dest + 4, src);                       // Buffer
            } else if (dest != 0) {
                vmem.memset(dest, 0, 8);
            }

            // void return
            ntdll_stdcall_ret(cpu, vmem, 0, 8);
            return 8;
        });

    // ---- RtlFreeUnicodeString(UnicodeString) ----
    disp.register_native("RtlFreeUnicodeString",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t str = vmem.read32(esp + 4);
            if (str != 0) vmem.memset(str, 0, 8);
            ntdll_stdcall_ret(cpu, vmem, 0, 4);
            return 4;
        });

    // ---- RtlGetVersion(lpVersionInformation) ----
    disp.register_native("RtlGetVersion",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t info_ptr = vmem.read32(esp + 4);
            // RTL_OSVERSIONINFOW (284 bytes) — same fields as OSVERSIONINFOEXW
            if (info_ptr != 0) {
                vmem.write32(info_ptr + 4, 10);    // Major (Windows 10)
                vmem.write32(info_ptr + 8, 0);     // Minor
                vmem.write32(info_ptr + 12, 19045);// Build
                vmem.write32(info_ptr + 16, 2);    // Platform = VER_PLATFORM_WIN32_NT
            }
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- RtlNtStatusToDosError(Status) ----
    disp.register_native("RtlNtStatusToDosError",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t status = vmem.read32(esp + 4);
            // Simplified mapping
            uint32_t dos_error = 0;
            switch (status) {
                case STATUS_SUCCESS:              dos_error = 0; break;
                case STATUS_INVALID_HANDLE:       dos_error = 6; break;
                case STATUS_INVALID_PARAMETER:    dos_error = 87; break;
                case STATUS_ACCESS_DENIED:        dos_error = 5; break;
                case STATUS_BUFFER_TOO_SMALL:     dos_error = 122; break;
                case STATUS_INFO_LENGTH_MISMATCH: dos_error = 24; break;
                default:                          dos_error = 317; break; // ERROR_MR_MID_NOT_FOUND
            }
            ntdll_stdcall_ret(cpu, vmem, dos_error, 4);
            return 4;
        });

    // ================================================================
    // Ldr* — Module Loader
    // ================================================================

    // ---- LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle*) ----
    disp.register_native("LdrLoadDll",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 16);
            static uint32_t ldr_fake_base = 0x78000000;
            if (handle_ptr != 0) {
                vmem.write32(handle_ptr, ldr_fake_base);
                ldr_fake_base += 0x00100000;
            }
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- LdrGetProcedureAddress(ModuleHandle, FunctionName, Ordinal, FunctionAddress*) ----
    disp.register_native("LdrGetProcedureAddress",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t func_ptr = vmem.read32(esp + 16);
            if (func_ptr != 0) vmem.write32(func_ptr, 0); // Not found
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ---- LdrGetDllHandle(DllPath, Unused, DllName, DllHandle*) ----
    disp.register_native("LdrGetDllHandle",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t handle_ptr = vmem.read32(esp + 16);
            if (handle_ptr != 0) vmem.write32(handle_ptr, vmem.read32(PEB_ADDRESS + 0x08));
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 16);
            return 16;
        });

    // ================================================================
    // Rtl* — Exception Handling
    // ================================================================

    // ---- RtlAddVectoredExceptionHandler(First, Handler) ----
    disp.register_native("RtlAddVectoredExceptionHandler",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t first   = vmem.read32(esp + 4);
            uint32_t handler = vmem.read32(esp + 8);
            // Store handler and return a fake "cookie"
            static uint32_t veh_cookie = 0xBEEF0000;
            if (first) {
                veh_first_handler_ = handler;
            } else {
                veh_last_handler_ = handler;
            }
            uint32_t cookie = veh_cookie++;
            cpu.set_reg(X86_EAX, cookie);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 8);
            cpu.set_pc(ret);
            return 8;
        });

    // ---- RtlRemoveVectoredExceptionHandler(Handle) ----
    disp.register_native("RtlRemoveVectoredExceptionHandler",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            cpu.set_reg(X86_EAX, 1u); // Success
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4);
            cpu.set_pc(ret);
            return 4;
        });

    // ================================================================
    // Rtl* — Heap
    // ================================================================

    // ---- RtlAllocateHeap(HeapHandle, Flags, Size) ----
    disp.register_native("RtlAllocateHeap",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t flags = vmem.read32(esp + 8);
            uint32_t size  = vmem.read32(esp + 12);
            uint32_t addr = heap.alloc(size);
            if (addr != 0 && (flags & HEAP_ZERO_MEMORY)) vmem.memset(addr, 0, size);
            ntdll_stdcall_ret(cpu, vmem, addr, 12);
            return 12;
        });

    // ---- RtlFreeHeap(HeapHandle, Flags, BaseAddress) ----
    disp.register_native("RtlFreeHeap",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ptr = vmem.read32(esp + 12);
            if (ptr != 0) heap.free(ptr);
            ntdll_stdcall_ret(cpu, vmem, 1, 12); // TRUE
            return 12;
        });

    // ---- RtlReAllocateHeap(HeapHandle, Flags, Ptr, Size) ----
    disp.register_native("RtlReAllocateHeap",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ptr  = vmem.read32(esp + 12);
            uint32_t size = vmem.read32(esp + 16);
            uint32_t addr = heap.realloc(ptr, size);
            ntdll_stdcall_ret(cpu, vmem, addr, 16);
            return 16;
        });

    // ---- RtlSizeHeap(HeapHandle, Flags, Ptr) ----
    disp.register_native("RtlSizeHeap",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            ntdll_stdcall_ret(cpu, vmem, 0x100u, 12); // Simplified
            return 12;
        });

    // ================================================================
    // Rtl* — Critical Section / SRW Lock
    // ================================================================

    // ---- RtlInitializeCriticalSection(lpCS) ----
    disp.register_native("RtlInitializeCriticalSection",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs = vmem.read32(esp + 4);
            CRITICAL_SECTION32 crit = {};
            crit.LockCount = static_cast<uint32_t>(-1);
            vmem.write(cs, &crit, sizeof(crit));
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- RtlEnterCriticalSection(lpCS) ----
    disp.register_native("RtlEnterCriticalSection",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs = vmem.read32(esp + 4);
            uint32_t rc = vmem.read32(cs + 8);
            vmem.write32(cs + 8, rc + 1);
            vmem.write32(cs + 12, FAKE_TID_NT);
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- RtlLeaveCriticalSection(lpCS) ----
    disp.register_native("RtlLeaveCriticalSection",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs = vmem.read32(esp + 4);
            uint32_t rc = vmem.read32(cs + 8);
            if (rc > 0) {
                vmem.write32(cs + 8, rc - 1);
                if (rc == 1) vmem.write32(cs + 12, 0);
            }
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- RtlDeleteCriticalSection(lpCS) ----
    disp.register_native("RtlDeleteCriticalSection",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs = vmem.read32(esp + 4);
            vmem.memset(cs, 0, sizeof(CRITICAL_SECTION32));
            ntdll_stdcall_ret(cpu, vmem, STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- SRW Lock operations — no-ops in single-threaded emulation ----
    auto srw_noop = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        ntdll_stdcall_ret(cpu, vmem, 0, 4); // void return, 1 arg
        return 4;
    };
    disp.register_native("RtlAcquireSRWLockExclusive", srw_noop);
    disp.register_native("RtlReleaseSRWLockExclusive", srw_noop);
    disp.register_native("RtlAcquireSRWLockShared", srw_noop);
    disp.register_native("RtlReleaseSRWLockShared", srw_noop);

    // Also register the kernel32 wrappers
    disp.register_native("AcquireSRWLockExclusive", srw_noop);
    disp.register_native("ReleaseSRWLockExclusive", srw_noop);
    disp.register_native("AcquireSRWLockShared", srw_noop);
    disp.register_native("ReleaseSRWLockShared", srw_noop);
    disp.register_native("InitializeSRWLock", srw_noop);

    // ================================================================
    // Debug APIs
    // ================================================================

    // ---- DbgPrint(Format, ...) — cdecl, log and continue ----
    disp.register_native("DbgPrint",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            // cdecl: caller cleans, just pop return address
            cpu.set_reg(X86_EAX, STATUS_SUCCESS);
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4);
            cpu.set_pc(ret);
            return 0;
        });

    // ---- DbgBreakPoint() — log and continue (don't actually break) ----
    disp.register_native("DbgBreakPoint",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            ntdll_stdcall_ret(cpu, vmem, 0, 0);
            return 0;
        });

    // ================================================================
    // Register Windows 10 syscall table
    // ================================================================
    syscall_interceptor.register_win10_syscalls(disp);

} // register_ntdll_apis

} // namespace vx
