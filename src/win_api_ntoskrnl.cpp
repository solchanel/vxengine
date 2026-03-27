/**
 * VXEngine ntoskrnl.exe API Stubs
 *
 * Emulated implementations of Windows kernel (ntoskrnl.exe) functions
 * for kernel driver (.sys) emulation. These stubs allow DriverEntry and
 * IRP dispatch routines to execute in the emulator without a real kernel.
 *
 * Each handler follows the same sentinel-driven pattern as win_api.cpp:
 *   - Reads arguments from the emulated stack via stack_arg()
 *   - Performs the emulated operation (allocation, object creation, etc.)
 *   - Returns result via stdcall_return() setting EAX
 *
 * Registration function: register_ntoskrnl_apis(APIDispatcher&)
 */

#include "../include/vxengine/win_api.h"
#include "../include/vxengine/kernel_env.h"
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <map>
#include <string>

namespace vx {

// ============================================================
// Kernel pool allocator state (module-local)
// ============================================================

static uint32_t s_pool_alloc_ptr = KERNEL_POOL_BASE;
static bool     s_pool_mapped = false;
static constexpr uint32_t POOL_REGION_SIZE = 0x01000000; // 16 MB

// Track pool allocations for ExFreePool
static std::map<uint32_t, uint32_t> s_pool_allocs; // addr -> size

// Fake IRQL state
static uint8_t s_current_irql = PASSIVE_LEVEL;

// Fake process/thread IDs
static constexpr uint32_t FAKE_EPROCESS     = 0xFB000000;
static constexpr uint32_t FAKE_ETHREAD      = 0xFB001000;
static constexpr uint32_t FAKE_PROCESS_ID   = 4;    // System process
static constexpr uint32_t FAKE_THREAD_ID    = 8;

// Fake object for ObReferenceObjectByHandle
static constexpr uint32_t FAKE_OBJECT_BASE  = 0xFB010000;

// DbgPrint buffer
static constexpr uint32_t DBGPRINT_BUF_ADDR = 0xFB020000;

// Symbolic link / device name storage
static std::map<std::string, std::string> s_symbolic_links;

// Registry key storage (simple key-value)
static std::map<uint32_t, std::string> s_open_keys;  // handle -> path
static uint32_t s_next_reg_handle = 0x80000100;
static std::map<std::string, std::vector<uint8_t>> s_registry_values;

// Event/mutex/timer objects (fake, tracked by address)
static std::map<uint32_t, bool> s_events;     // addr -> signaled
static std::map<uint32_t, bool> s_mutexes;    // addr -> held
static std::map<uint32_t, bool> s_timers;     // addr -> active

// Spinlock state
static std::map<uint32_t, uint8_t> s_spinlocks; // addr -> old_irql

// ============================================================
// Helper: ensure pool region is mapped
// ============================================================

static void ensure_pool_mapped(VirtualMemory& vmem) {
    if (!s_pool_mapped) {
        vmem.map(KERNEL_POOL_BASE, POOL_REGION_SIZE, PERM_RW);
        vmem.memset(KERNEL_POOL_BASE, 0, POOL_REGION_SIZE);
        s_pool_mapped = true;
    }
}

// ============================================================
// Helper: allocate from kernel pool
// ============================================================

static uint32_t pool_alloc(VirtualMemory& vmem, uint32_t size) {
    ensure_pool_mapped(vmem);

    // Align to 16 bytes
    uint32_t aligned = (size + 15) & ~15u;
    uint32_t addr = s_pool_alloc_ptr;
    s_pool_alloc_ptr += aligned;

    s_pool_allocs[addr] = aligned;
    return addr;
}

// ============================================================
// Helper: read wide string from emulated memory
// ============================================================

static std::string read_unicode_str(VirtualMemory& vmem, uint32_t ustr_addr) {
    // UNICODE_STRING: Length(u16), MaxLength(u16), Buffer(u32)
    uint16_t len = static_cast<uint16_t>(vmem.read32(ustr_addr) & 0xFFFF);
    uint32_t buf = vmem.read32(ustr_addr + 4);

    std::string result;
    for (uint16_t i = 0; i < len / 2; i++) {
        uint16_t wc = static_cast<uint16_t>(vmem.read32(buf + i * 2) & 0xFFFF);
        if (wc < 128) {
            result += static_cast<char>(wc);
        } else {
            result += '?';
        }
    }
    return result;
}

// ============================================================
// Registration function
// ============================================================

void register_ntoskrnl_apis(APIDispatcher& disp) {

    // ================================================================
    // MEMORY MANAGEMENT
    // ================================================================

    // ---- ExAllocatePoolWithTag(PoolType, NumberOfBytes, Tag) ----
    disp.register_native("ExAllocatePoolWithTag",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t pool_type = disp.stack_arg(0);
            uint32_t size      = disp.stack_arg(1);
            uint32_t tag       = disp.stack_arg(2);
            (void)pool_type; (void)tag;

            uint32_t addr = pool_alloc(vmem, size);
            disp.stdcall_return(addr, 12);
            return 12;
        });

    // ---- ExAllocatePool(PoolType, NumberOfBytes) ----
    disp.register_native("ExAllocatePool",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t pool_type = disp.stack_arg(0);
            uint32_t size      = disp.stack_arg(1);
            (void)pool_type;

            uint32_t addr = pool_alloc(vmem, size);
            disp.stdcall_return(addr, 8);
            return 8;
        });

    // ---- ExFreePoolWithTag(P, Tag) ----
    disp.register_native("ExFreePoolWithTag",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t ptr = disp.stack_arg(0);
            uint32_t tag = disp.stack_arg(1);
            (void)tag;

            s_pool_allocs.erase(ptr);
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- ExFreePool(P) ----
    disp.register_native("ExFreePool",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t ptr = disp.stack_arg(0);
            s_pool_allocs.erase(ptr);
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- MmGetSystemRoutineAddress(SystemRoutineName) ----
    disp.register_native("MmGetSystemRoutineAddress",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t ustr_addr = disp.stack_arg(0);
            // Return NULL — we don't resolve dynamic kernel imports
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- MmMapIoSpace(PhysAddr_lo, PhysAddr_hi, NumberOfBytes, CacheType) ----
    // Note: PHYSICAL_ADDRESS is 64-bit, passed as two 32-bit values on x86
    disp.register_native("MmMapIoSpace",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t phys_lo  = disp.stack_arg(0);
            uint32_t phys_hi  = disp.stack_arg(1);
            uint32_t size     = disp.stack_arg(2);
            uint32_t cache    = disp.stack_arg(3);
            (void)phys_hi; (void)cache;

            // Map a fake IO region
            uint32_t addr = pool_alloc(vmem, size);
            disp.stdcall_return(addr, 16);
            return 16;
        });

    // ---- MmUnmapIoSpace(BaseAddress, NumberOfBytes) ----
    disp.register_native("MmUnmapIoSpace",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t base = disp.stack_arg(0);
            uint32_t size = disp.stack_arg(1);
            (void)base; (void)size;
            // No-op
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- MmAllocateContiguousMemory(NumberOfBytes, HighestAcceptableAddress) ----
    disp.register_native("MmAllocateContiguousMemory",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t size    = disp.stack_arg(0);
            uint32_t highest = disp.stack_arg(1);
            (void)highest;

            uint32_t addr = pool_alloc(vmem, size);
            disp.stdcall_return(addr, 8);
            return 8;
        });

    // ---- MmFreeContiguousMemory(BaseAddress) ----
    disp.register_native("MmFreeContiguousMemory",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t base = disp.stack_arg(0);
            s_pool_allocs.erase(base);
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- MmGetPhysicalAddress(BaseAddress) -> PHYSICAL_ADDRESS (64-bit, via EDX:EAX) ----
    disp.register_native("MmGetPhysicalAddress",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t virt = disp.stack_arg(0);
            // Return the virtual address as the physical address (identity map)
            cpu.set_reg(X86_EAX, virt);
            cpu.set_reg(X86_EDX, 0);

            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ret_addr = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4); // pop ret + 1 arg
            cpu.set_pc(ret_addr);
            return 4;
        });

    // ---- MmMapLockedPagesSpecifyCache(...) ----
    disp.register_native("MmMapLockedPagesSpecifyCache",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mdl_addr   = disp.stack_arg(0);
            uint32_t access     = disp.stack_arg(1);
            uint32_t cache_type = disp.stack_arg(2);
            uint32_t req_addr   = disp.stack_arg(3);
            uint32_t bug_check  = disp.stack_arg(4);
            uint32_t priority   = disp.stack_arg(5);
            (void)access; (void)cache_type; (void)req_addr; (void)bug_check; (void)priority;

            // Return a fake mapped address from the MDL's StartVa
            uint32_t fake_va = pool_alloc(vmem, 0x1000);
            disp.stdcall_return(fake_va, 24);
            return 24;
        });

    // ---- ProbeForRead(Address, Length, Alignment) ----
    disp.register_native("ProbeForRead",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op in emulation — we don't raise exceptions for bad pointers here
            disp.stdcall_return(0, 12);
            return 12;
        });

    // ---- ProbeForWrite(Address, Length, Alignment) ----
    disp.register_native("ProbeForWrite",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(0, 12);
            return 12;
        });

    // ---- MmIsAddressValid(VirtualAddress) ----
    disp.register_native("MmIsAddressValid",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t addr = disp.stack_arg(0);
            uint32_t valid = vmem.is_mapped(addr) ? 1 : 0;
            disp.stdcall_return(valid, 4);
            return 4;
        });

    // ---- MmGetSystemAddressForMdl(Mdl) ----
    disp.register_native("MmGetSystemAddressForMdl",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mdl = disp.stack_arg(0);
            // Return a fake system address
            uint32_t addr = pool_alloc(vmem, 0x1000);
            disp.stdcall_return(addr, 4);
            return 4;
        });

    // ---- MmGetSystemAddressForMdlSafe(Mdl, Priority) ----
    disp.register_native("MmGetSystemAddressForMdlSafe",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mdl      = disp.stack_arg(0);
            uint32_t priority = disp.stack_arg(1);
            (void)mdl; (void)priority;

            uint32_t addr = pool_alloc(vmem, 0x1000);
            disp.stdcall_return(addr, 8);
            return 8;
        });

    // ================================================================
    // OBJECT MANAGER / IO MANAGER
    // ================================================================

    // ---- ObReferenceObjectByHandle(Handle, DesiredAccess, ObjectType, AccessMode, Object, HandleInformation) ----
    disp.register_native("ObReferenceObjectByHandle",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t handle   = disp.stack_arg(0);
            uint32_t access   = disp.stack_arg(1);
            uint32_t obj_type = disp.stack_arg(2);
            uint32_t mode     = disp.stack_arg(3);
            uint32_t obj_out  = disp.stack_arg(4);
            uint32_t info_out = disp.stack_arg(5);
            (void)handle; (void)access; (void)obj_type; (void)mode;

            // Write a fake object pointer
            if (obj_out != 0) {
                vmem.write32(obj_out, FAKE_OBJECT_BASE);
            }
            if (info_out != 0) {
                vmem.write32(info_out, 0);
            }
            disp.stdcall_return(STATUS_SUCCESS, 24);
            return 24;
        });

    // ---- ObDereferenceObject(Object) ----
    disp.register_native("ObDereferenceObject",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- ObOpenObjectByName(ObjectAttributes, ObjectType, AccessState, DesiredAccess, ParseContext, Object) ----
    disp.register_native("ObOpenObjectByName",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(STATUS_SUCCESS, 24);
            return 24;
        });

    // ---- IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName, DeviceType, DeviceCharacteristics, Exclusive, DeviceObject) ----
    disp.register_native("IoCreateDevice",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t drv_obj     = disp.stack_arg(0);
            uint32_t ext_size    = disp.stack_arg(1);
            uint32_t dev_name    = disp.stack_arg(2);
            uint32_t dev_type    = disp.stack_arg(3);
            uint32_t chars       = disp.stack_arg(4);
            uint32_t exclusive   = disp.stack_arg(5);
            uint32_t dev_obj_out = disp.stack_arg(6);
            (void)dev_name; (void)chars; (void)exclusive;

            // Allocate a DEVICE_OBJECT
            uint32_t dev_size = static_cast<uint32_t>(sizeof(DEVICE_OBJECT32));
            uint32_t dev_addr = pool_alloc(vmem, dev_size + ext_size);

            DEVICE_OBJECT32 dev = {};
            dev.Type = IO_TYPE_DEVICE;
            dev.Size = static_cast<uint16_t>(dev_size);
            dev.ReferenceCount = 1;
            dev.DriverObject = drv_obj;
            dev.DeviceType = dev_type;
            dev.DeviceExtension = (ext_size > 0) ? (dev_addr + dev_size) : 0;
            dev.StackSize = 1;
            vmem.write(dev_addr, &dev, sizeof(dev));

            // Write the device object pointer to the output parameter
            if (dev_obj_out != 0) {
                vmem.write32(dev_obj_out, dev_addr);
            }

            // Link to driver's device list
            uint32_t first_dev = vmem.read32(
                drv_obj + offsetof(DRIVER_OBJECT32, DeviceObject));
            if (first_dev == 0) {
                vmem.write32(drv_obj + offsetof(DRIVER_OBJECT32, DeviceObject), dev_addr);
            }

            disp.stdcall_return(STATUS_SUCCESS, 28);
            return 28;
        });

    // ---- IoDeleteDevice(DeviceObject) ----
    disp.register_native("IoDeleteDevice",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op in emulation (don't actually unmap)
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- IoCreateSymbolicLink(SymbolicLinkName, DeviceName) ----
    disp.register_native("IoCreateSymbolicLink",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t link_name = disp.stack_arg(0);
            uint32_t dev_name  = disp.stack_arg(1);

            std::string link = read_unicode_str(vmem, link_name);
            std::string dev  = read_unicode_str(vmem, dev_name);
            s_symbolic_links[link] = dev;

            disp.stdcall_return(STATUS_SUCCESS, 8);
            return 8;
        });

    // ---- IoDeleteSymbolicLink(SymbolicLinkName) ----
    disp.register_native("IoDeleteSymbolicLink",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t link_name = disp.stack_arg(0);
            std::string link = read_unicode_str(vmem, link_name);
            s_symbolic_links.erase(link);

            disp.stdcall_return(STATUS_SUCCESS, 4);
            return 4;
        });

    // ---- IoGetDeviceObjectPointer(ObjectName, DesiredAccess, FileObject, DeviceObject) ----
    disp.register_native("IoGetDeviceObjectPointer",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Return STATUS_OBJECT_NAME_NOT_FOUND — we don't have other devices
            disp.stdcall_return(STATUS_OBJECT_NAME_NOT_FOUND, 16);
            return 16;
        });

    // ---- IoCallDriver(DeviceObject, Irp) ----
    disp.register_native("IoCallDriver",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Just return STATUS_SUCCESS without actually dispatching
            disp.stdcall_return(STATUS_SUCCESS, 8);
            return 8;
        });

    // ---- IoCompleteRequest(Irp, PriorityBoost) ----
    disp.register_native("IoCompleteRequest",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op; the IRP's IoStatus is already set by the driver
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- IofCompleteRequest (fastcall: Irp in ECX, PriorityBoost in EDX) ----
    disp.register_native("IofCompleteRequest",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // fastcall: first two args in ECX, EDX — no stack cleanup needed
            // No-op in emulation
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ret_addr = vmem.read32(esp);
            cpu.set_sp(esp + 4); // pop return address only
            cpu.set_pc(ret_addr);
            cpu.set_reg(X86_EAX, 0);
            return 0;
        });

    // ---- IoAllocateIrp(StackSize, ChargeQuota) ----
    disp.register_native("IoAllocateIrp",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t stack_size = disp.stack_arg(0);
            uint32_t charge     = disp.stack_arg(1);
            (void)stack_size; (void)charge;

            uint32_t irp_size = static_cast<uint32_t>(sizeof(IRP32));
            uint32_t addr = pool_alloc(vmem, irp_size);
            vmem.memset(addr, 0, irp_size);

            // Set type
            uint16_t type = IO_TYPE_IRP;
            vmem.write(addr, &type, 2);
            uint16_t sz = static_cast<uint16_t>(irp_size);
            vmem.write(addr + 2, &sz, 2);

            disp.stdcall_return(addr, 8);
            return 8;
        });

    // ---- IoFreeIrp(Irp) ----
    disp.register_native("IoFreeIrp",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t irp = disp.stack_arg(0);
            (void)irp; // Could track and free
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- IoGetCurrentIrpStackLocation(Irp) ----
    // This is actually a macro/inline in real Windows, but some drivers import it
    disp.register_native("IoGetCurrentIrpStackLocation",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t irp = disp.stack_arg(0);
            uint32_t stack_loc = vmem.read32(
                irp + offsetof(IRP32, Tail_Overlay_CurrentStackLocation));
            disp.stdcall_return(stack_loc, 4);
            return 4;
        });

    // ---- IoMarkIrpPending(Irp) ----
    disp.register_native("IoMarkIrpPending",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t irp = disp.stack_arg(0);
            // Set PendingReturned flag
            uint8_t pending = 1;
            vmem.write(irp + offsetof(IRP32, PendingReturned), &pending, 1);
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ================================================================
    // PROCESS / THREAD
    // ================================================================

    // ---- PsGetCurrentProcess() ----
    disp.register_native("PsGetCurrentProcess",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(FAKE_EPROCESS, 0);
            return 0;
        });

    // ---- IoGetCurrentProcess() ---- (same as PsGetCurrentProcess)
    disp.register_native("IoGetCurrentProcess",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(FAKE_EPROCESS, 0);
            return 0;
        });

    // ---- PsGetCurrentProcessId() ----
    disp.register_native("PsGetCurrentProcessId",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(FAKE_PROCESS_ID, 0);
            return 0;
        });

    // ---- PsGetCurrentThread() ----
    disp.register_native("PsGetCurrentThread",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(FAKE_ETHREAD, 0);
            return 0;
        });

    // ---- PsGetCurrentThreadId() ----
    disp.register_native("PsGetCurrentThreadId",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(FAKE_THREAD_ID, 0);
            return 0;
        });

    // ---- PsLookupProcessByProcessId(ProcessId, Process) ----
    disp.register_native("PsLookupProcessByProcessId",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t pid     = disp.stack_arg(0);
            uint32_t out_ptr = disp.stack_arg(1);
            (void)pid;

            if (out_ptr != 0) {
                vmem.write32(out_ptr, FAKE_EPROCESS);
            }
            disp.stdcall_return(STATUS_SUCCESS, 8);
            return 8;
        });

    // ---- PsLookupThreadByThreadId(ThreadId, Thread) ----
    disp.register_native("PsLookupThreadByThreadId",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t tid     = disp.stack_arg(0);
            uint32_t out_ptr = disp.stack_arg(1);
            (void)tid;

            if (out_ptr != 0) {
                vmem.write32(out_ptr, FAKE_ETHREAD);
            }
            disp.stdcall_return(STATUS_SUCCESS, 8);
            return 8;
        });

    // ================================================================
    // IRQL MANAGEMENT
    // ================================================================

    // ---- KeGetCurrentIrql() ----
    disp.register_native("KeGetCurrentIrql",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(s_current_irql, 0);
            return 0;
        });

    // ---- KeLowerIrql(NewIrql) ----
    disp.register_native("KeLowerIrql",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t new_irql = disp.stack_arg(0);
            s_current_irql = static_cast<uint8_t>(new_irql & 0xFF);
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- KeRaiseIrql(NewIrql, OldIrql) ----
    disp.register_native("KeRaiseIrql",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t new_irql     = disp.stack_arg(0);
            uint32_t old_irql_ptr = disp.stack_arg(1);

            if (old_irql_ptr != 0) {
                uint8_t old = s_current_irql;
                vmem.write(old_irql_ptr, &old, 1);
            }
            s_current_irql = static_cast<uint8_t>(new_irql & 0xFF);
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ================================================================
    // SYNCHRONIZATION PRIMITIVES
    // ================================================================

    // ---- KeInitializeEvent(Event, Type, State) ----
    disp.register_native("KeInitializeEvent",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t event_ptr = disp.stack_arg(0);
            uint32_t type      = disp.stack_arg(1);
            uint32_t state     = disp.stack_arg(2);
            (void)type;

            s_events[event_ptr] = (state != 0);
            disp.stdcall_return(0, 12);
            return 12;
        });

    // ---- KeSetEvent(Event, Increment, Wait) ----
    disp.register_native("KeSetEvent",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t event_ptr = disp.stack_arg(0);
            uint32_t increment = disp.stack_arg(1);
            uint32_t wait      = disp.stack_arg(2);
            (void)increment; (void)wait;

            uint32_t prev = s_events.count(event_ptr) && s_events[event_ptr] ? 1 : 0;
            s_events[event_ptr] = true;
            disp.stdcall_return(prev, 12);
            return 12;
        });

    // ---- KeWaitForSingleObject(Object, WaitReason, WaitMode, Alertable, Timeout) ----
    disp.register_native("KeWaitForSingleObject",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Always return STATUS_SUCCESS immediately (no real waiting)
            disp.stdcall_return(STATUS_SUCCESS, 20);
            return 20;
        });

    // ---- KeInitializeSpinLock(SpinLock) ----
    disp.register_native("KeInitializeSpinLock",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t lock_ptr = disp.stack_arg(0);
            vmem.write32(lock_ptr, 0); // Unlocked
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- KeAcquireSpinLock(SpinLock, OldIrql) ----
    disp.register_native("KeAcquireSpinLock",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t lock_ptr     = disp.stack_arg(0);
            uint32_t old_irql_ptr = disp.stack_arg(1);

            if (old_irql_ptr != 0) {
                uint8_t old = s_current_irql;
                vmem.write(old_irql_ptr, &old, 1);
            }
            s_current_irql = DISPATCH_LEVEL;
            s_spinlocks[lock_ptr] = s_current_irql;
            vmem.write32(lock_ptr, 1); // Locked

            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- KeReleaseSpinLock(SpinLock, NewIrql) ----
    disp.register_native("KeReleaseSpinLock",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t lock_ptr = disp.stack_arg(0);
            uint32_t new_irql = disp.stack_arg(1);

            vmem.write32(lock_ptr, 0); // Unlocked
            s_current_irql = static_cast<uint8_t>(new_irql & 0xFF);
            s_spinlocks.erase(lock_ptr);

            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- KeInitializeMutex(Mutex, Level) ----
    disp.register_native("KeInitializeMutex",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mutex_ptr = disp.stack_arg(0);
            uint32_t level     = disp.stack_arg(1);
            (void)level;

            s_mutexes[mutex_ptr] = false; // Not held
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- KeReleaseMutex(Mutex, Wait) ----
    disp.register_native("KeReleaseMutex",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mutex_ptr = disp.stack_arg(0);
            uint32_t wait      = disp.stack_arg(1);
            (void)wait;

            s_mutexes[mutex_ptr] = false;
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- KeInitializeTimer(Timer) ----
    disp.register_native("KeInitializeTimer",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t timer_ptr = disp.stack_arg(0);
            s_timers[timer_ptr] = false;
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- KeSetTimer(Timer, DueTime_lo, DueTime_hi, Dpc) ----
    disp.register_native("KeSetTimer",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t timer_ptr = disp.stack_arg(0);
            // DueTime is LARGE_INTEGER (8 bytes on stack)
            uint32_t due_lo    = disp.stack_arg(1);
            uint32_t due_hi    = disp.stack_arg(2);
            uint32_t dpc       = disp.stack_arg(3);
            (void)due_lo; (void)due_hi; (void)dpc;

            bool was_set = s_timers.count(timer_ptr) && s_timers[timer_ptr];
            s_timers[timer_ptr] = true;
            disp.stdcall_return(was_set ? 1 : 0, 16);
            return 16;
        });

    // ---- KeCancelTimer(Timer) ----
    disp.register_native("KeCancelTimer",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t timer_ptr = disp.stack_arg(0);
            bool was_set = s_timers.count(timer_ptr) && s_timers[timer_ptr];
            s_timers[timer_ptr] = false;
            disp.stdcall_return(was_set ? 1 : 0, 4);
            return 4;
        });

    // ---- KeDelayExecutionThread(WaitMode, Alertable, Interval) ----
    disp.register_native("KeDelayExecutionThread",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op: return immediately
            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ---- ExInitializeFastMutex(FastMutex) ----
    disp.register_native("ExInitializeFastMutex",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mutex_ptr = disp.stack_arg(0);
            s_mutexes[mutex_ptr] = false;
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- ExAcquireFastMutex(FastMutex) ----
    disp.register_native("ExAcquireFastMutex",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mutex_ptr = disp.stack_arg(0);
            s_mutexes[mutex_ptr] = true;
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- ExReleaseFastMutex(FastMutex) ----
    disp.register_native("ExReleaseFastMutex",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t mutex_ptr = disp.stack_arg(0);
            s_mutexes[mutex_ptr] = false;
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ================================================================
    // REGISTRY
    // ================================================================

    // ---- ZwOpenKey(KeyHandle, DesiredAccess, ObjectAttributes) ----
    disp.register_native("ZwOpenKey",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t handle_out = disp.stack_arg(0);
            uint32_t access     = disp.stack_arg(1);
            uint32_t obj_attrs  = disp.stack_arg(2);
            (void)access;

            uint32_t h = s_next_reg_handle++;
            s_open_keys[h] = "\\Registry\\FakeKey";

            if (handle_out != 0) {
                vmem.write32(handle_out, h);
            }
            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ---- ZwCreateKey(KeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition) ----
    disp.register_native("ZwCreateKey",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t handle_out  = disp.stack_arg(0);
            uint32_t access      = disp.stack_arg(1);
            uint32_t obj_attrs   = disp.stack_arg(2);
            uint32_t title_idx   = disp.stack_arg(3);
            uint32_t cls         = disp.stack_arg(4);
            uint32_t create_opts = disp.stack_arg(5);
            uint32_t disposition = disp.stack_arg(6);
            (void)access; (void)obj_attrs; (void)title_idx;
            (void)cls; (void)create_opts;

            uint32_t h = s_next_reg_handle++;
            s_open_keys[h] = "\\Registry\\CreatedKey";

            if (handle_out != 0) {
                vmem.write32(handle_out, h);
            }
            if (disposition != 0) {
                vmem.write32(disposition, 1); // REG_CREATED_NEW_KEY
            }
            disp.stdcall_return(STATUS_SUCCESS, 28);
            return 28;
        });

    // ---- ZwQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength) ----
    disp.register_native("ZwQueryValueKey",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Return STATUS_OBJECT_NAME_NOT_FOUND — no values exist
            uint32_t result_len_ptr = disp.stack_arg(5);
            if (result_len_ptr != 0) {
                vmem.write32(result_len_ptr, 0);
            }
            disp.stdcall_return(STATUS_OBJECT_NAME_NOT_FOUND, 24);
            return 24;
        });

    // ---- ZwSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize) ----
    disp.register_native("ZwSetValueKey",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // Silently succeed
            disp.stdcall_return(STATUS_SUCCESS, 24);
            return 24;
        });

    // ---- ZwClose(Handle) ----
    disp.register_native("ZwClose",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t handle = disp.stack_arg(0);
            s_open_keys.erase(handle);
            disp.stdcall_return(STATUS_SUCCESS, 4);
            return 4;
        });

    // ================================================================
    // STRING FUNCTIONS
    // ================================================================

    // ---- RtlInitUnicodeString(DestinationString, SourceString) ----
    disp.register_native("RtlInitUnicodeString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest_ptr = disp.stack_arg(0);
            uint32_t src_ptr  = disp.stack_arg(1);

            if (src_ptr == 0) {
                // Empty string
                vmem.write32(dest_ptr, 0);     // Length = 0, MaximumLength = 0
                vmem.write32(dest_ptr + 4, 0); // Buffer = NULL
            } else {
                // Count characters in the wide string
                uint16_t len = 0;
                for (uint32_t i = 0; i < 0x7FFE; i += 2) {
                    uint16_t wc = static_cast<uint16_t>(vmem.read32(src_ptr + i) & 0xFFFF);
                    if (wc == 0) break;
                    len += 2;
                }
                uint16_t max_len = len + 2;
                vmem.write(dest_ptr, &len, 2);
                vmem.write(dest_ptr + 2, &max_len, 2);
                vmem.write32(dest_ptr + 4, src_ptr);
            }
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- RtlCopyUnicodeString(DestinationString, SourceString) ----
    disp.register_native("RtlCopyUnicodeString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest = disp.stack_arg(0);
            uint32_t src  = disp.stack_arg(1);

            if (src == 0 || dest == 0) {
                disp.stdcall_return(0, 8);
                return 8;
            }

            uint16_t src_len = static_cast<uint16_t>(vmem.read32(src) & 0xFFFF);
            uint16_t dst_max = static_cast<uint16_t>((vmem.read32(dest) >> 16) & 0xFFFF);
            uint32_t src_buf = vmem.read32(src + 4);
            uint32_t dst_buf = vmem.read32(dest + 4);

            uint16_t copy_len = std::min(src_len, dst_max);
            // Copy bytes
            for (uint16_t i = 0; i < copy_len; i++) {
                uint8_t b = 0;
                vmem.read(src_buf + i, &b, 1);
                vmem.write(dst_buf + i, &b, 1);
            }
            vmem.write(dest, &copy_len, 2);

            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- RtlCompareUnicodeString(String1, String2, CaseInSensitive) ----
    disp.register_native("RtlCompareUnicodeString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t str1 = disp.stack_arg(0);
            uint32_t str2 = disp.stack_arg(1);

            std::string s1 = read_unicode_str(vmem, str1);
            std::string s2 = read_unicode_str(vmem, str2);

            int result = s1.compare(s2);
            disp.stdcall_return(static_cast<uint32_t>(result), 12);
            return 12;
        });

    // ---- RtlAnsiStringToUnicodeString(DestinationString, SourceString, AllocateDestinationString) ----
    disp.register_native("RtlAnsiStringToUnicodeString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest       = disp.stack_arg(0);
            uint32_t src        = disp.stack_arg(1);
            uint32_t alloc_dest = disp.stack_arg(2);

            // Read ANSI_STRING: Length(u16), MaxLength(u16), Buffer(u32)
            uint16_t src_len = static_cast<uint16_t>(vmem.read32(src) & 0xFFFF);
            uint32_t src_buf = vmem.read32(src + 4);

            uint16_t uni_len = src_len * 2;
            uint16_t uni_max = uni_len + 2;

            uint32_t dst_buf;
            if (alloc_dest) {
                dst_buf = pool_alloc(vmem, uni_max);
            } else {
                dst_buf = vmem.read32(dest + 4);
            }

            // Convert ASCII to UTF-16LE
            for (uint16_t i = 0; i < src_len; i++) {
                uint8_t ch = 0;
                vmem.read(src_buf + i, &ch, 1);
                uint16_t wc = ch;
                vmem.write(dst_buf + i * 2, &wc, 2);
            }
            uint16_t null_term = 0;
            vmem.write(dst_buf + uni_len, &null_term, 2);

            vmem.write(dest, &uni_len, 2);
            vmem.write(dest + 2, &uni_max, 2);
            vmem.write32(dest + 4, dst_buf);

            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ---- RtlUnicodeStringToAnsiString(DestinationString, SourceString, AllocateDestinationString) ----
    disp.register_native("RtlUnicodeStringToAnsiString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest       = disp.stack_arg(0);
            uint32_t src        = disp.stack_arg(1);
            uint32_t alloc_dest = disp.stack_arg(2);

            uint16_t src_len = static_cast<uint16_t>(vmem.read32(src) & 0xFFFF);
            uint32_t src_buf = vmem.read32(src + 4);

            uint16_t ansi_len = src_len / 2;
            uint16_t ansi_max = ansi_len + 1;

            uint32_t dst_buf;
            if (alloc_dest) {
                dst_buf = pool_alloc(vmem, ansi_max);
            } else {
                dst_buf = vmem.read32(dest + 4);
            }

            // Convert UTF-16LE to ASCII
            for (uint16_t i = 0; i < ansi_len; i++) {
                uint16_t wc = 0;
                vmem.read(src_buf + i * 2, &wc, 2);
                uint8_t ch = (wc < 128) ? static_cast<uint8_t>(wc) : '?';
                vmem.write(dst_buf + i, &ch, 1);
            }
            uint8_t null_term = 0;
            vmem.write(dst_buf + ansi_len, &null_term, 1);

            vmem.write(dest, &ansi_len, 2);
            vmem.write(dest + 2, &ansi_max, 2);
            vmem.write32(dest + 4, dst_buf);

            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ---- RtlInitAnsiString(DestinationString, SourceString) ----
    disp.register_native("RtlInitAnsiString",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest_ptr = disp.stack_arg(0);
            uint32_t src_ptr  = disp.stack_arg(1);

            if (src_ptr == 0) {
                vmem.write32(dest_ptr, 0);
                vmem.write32(dest_ptr + 4, 0);
            } else {
                // Count length of ANSI string
                uint16_t len = 0;
                for (uint32_t i = 0; i < 0x7FFF; i++) {
                    uint8_t ch = 0;
                    vmem.read(src_ptr + i, &ch, 1);
                    if (ch == 0) break;
                    len++;
                }
                uint16_t max_len = len + 1;
                vmem.write(dest_ptr, &len, 2);
                vmem.write(dest_ptr + 2, &max_len, 2);
                vmem.write32(dest_ptr + 4, src_ptr);
            }
            disp.stdcall_return(0, 8);
            return 8;
        });

    // ---- RtlStringCbCopyA(pszDest, cbDest, pszSrc) ----
    disp.register_native("RtlStringCbCopyA",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest = disp.stack_arg(0);
            uint32_t cb   = disp.stack_arg(1);
            uint32_t src  = disp.stack_arg(2);

            // Simple bounded string copy
            for (uint32_t i = 0; i < cb - 1; i++) {
                uint8_t ch = 0;
                vmem.read(src + i, &ch, 1);
                vmem.write(dest + i, &ch, 1);
                if (ch == 0) break;
            }
            // Null-terminate
            uint8_t null_term = 0;
            vmem.write(dest + cb - 1, &null_term, 1);

            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ---- RtlStringCbPrintfA(pszDest, cbDest, pszFormat, ...) ----
    disp.register_native("RtlStringCbPrintfA",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t dest   = disp.stack_arg(0);
            uint32_t cb     = disp.stack_arg(1);
            uint32_t format = disp.stack_arg(2);

            // Just copy the format string as-is (no real printf processing)
            for (uint32_t i = 0; i < cb - 1; i++) {
                uint8_t ch = 0;
                vmem.read(format + i, &ch, 1);
                vmem.write(dest + i, &ch, 1);
                if (ch == 0) break;
            }
            uint8_t null_term = 0;
            vmem.write(dest + cb - 1, &null_term, 1);

            // Variable args — we pop 12 bytes minimum (3 fixed args)
            disp.stdcall_return(STATUS_SUCCESS, 12);
            return 12;
        });

    // ================================================================
    // DEBUG / MISC
    // ================================================================

    // ---- DbgPrint(Format, ...) ----
    // cdecl calling convention (caller cleans stack)
    disp.register_native("DbgPrint",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t format = disp.stack_arg(0);

            // Read the format string for debugging purposes
            std::string fmt = vmem.read_string(format, 256);
            // In a real implementation, would log this somewhere
            // For now, just silently succeed

            // cdecl: only pop return address
            disp.cdecl_return(STATUS_SUCCESS);
            return 0;
        });

    // ---- DbgBreakPoint() ----
    disp.register_native("DbgBreakPoint",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            // No-op: don't actually break
            disp.stdcall_return(0, 0);
            return 0;
        });

    // ---- KdDebuggerEnabled (global variable) ----
    // This is actually a global, not a function. Some drivers check it.
    // We register it as a no-arg function returning 0 (debugger not present).
    disp.register_native("KdDebuggerEnabled",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            disp.stdcall_return(0, 0);
            return 0;
        });

    // ---- KeQuerySystemTime(CurrentTime) ----
    disp.register_native("KeQuerySystemTime",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t time_ptr = disp.stack_arg(0);

            // Return a fake time (Windows FILETIME: 100ns intervals since 1601)
            // Use a plausible value for ~2024
            uint64_t fake_time = 133500000000000000ULL;
            if (time_ptr != 0) {
                vmem.write(time_ptr, &fake_time, 8);
            }
            disp.stdcall_return(0, 4);
            return 4;
        });

    // ---- KeQueryTickCount(TickCount) ----
    disp.register_native("KeQueryTickCount",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
            uint32_t tick_ptr = disp.stack_arg(0);

            // Return a plausible tick count
            uint64_t fake_ticks = 100000;
            if (tick_ptr != 0) {
                vmem.write(tick_ptr, &fake_ticks, 8);
            }
            disp.stdcall_return(0, 4);
            return 4;
        });

} // end register_ntoskrnl_apis

// Make stack_arg and stdcall_return/cdecl_return accessible to this TU.
// The APIDispatcher class already has them public/protected enough via
// the NativeAPIHandler callback pattern: each lambda captures `disp` by
// reference and calls disp.stack_arg(), disp.stdcall_return(), etc.
// This works because we declared register_ntoskrnl_apis as a free function
// that takes APIDispatcher& and uses the public interface.

} // namespace vx
