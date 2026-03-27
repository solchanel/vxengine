#pragma once
/**
 * VXEngine Kernel Environment Emulation
 *
 * Windows kernel driver (.sys) and Linux kernel module (.ko) support:
 *   - DRIVER_OBJECT / DEVICE_OBJECT creation and management
 *   - IRP dispatch (IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, etc.)
 *   - DriverEntry invocation with proper calling convention
 *   - Linux module_init / module_exit invocation
 *
 * Used for emulating kernel-mode drivers without a real OS kernel.
 * The environment fakes just enough kernel state for static/dynamic
 * analysis of driver dispatch routines and IOCTL handlers.
 */

#include "vxengine.h"
#include "memory.h"
#include "cpu/icpu.h"
#include <string>
#include <map>

namespace vx {

// ============================================================
// Windows Kernel Structures (32-bit, packed for emulated memory)
// ============================================================

#pragma pack(push, 1)

struct DRIVER_OBJECT32 {
    uint16_t Type;              // IO_TYPE_DRIVER = 4
    uint16_t Size;
    uint32_t DeviceObject;      // Ptr to first DEVICE_OBJECT
    uint32_t Flags;
    uint32_t DriverStart;       // Base address of driver image
    uint32_t DriverSize;        // Size of driver image
    uint32_t DriverSection;     // LDR entry (fake)
    uint32_t DriverExtension;   // Ptr to DRIVER_EXTENSION (fake)
    // UNICODE_STRING DriverName (inline)
    uint16_t DriverNameLength;
    uint16_t DriverNameMaxLength;
    uint32_t DriverNameBuffer;
    // Padding to align MajorFunction at offset 0x38
    uint8_t  Reserved[8];
    // IRP_MJ_xxx dispatch table (28 entries)
    uint32_t MajorFunction[28];
};

struct DEVICE_OBJECT32 {
    uint16_t Type;              // IO_TYPE_DEVICE = 3
    uint16_t Size;
    uint32_t ReferenceCount;
    uint32_t DriverObject;      // Back-ptr to DRIVER_OBJECT
    uint32_t NextDevice;        // Linked list of devices
    uint32_t AttachedDevice;    // Device attached above this one
    uint32_t CurrentIrp;
    uint32_t Flags;
    uint32_t DeviceExtension;   // Driver-private area
    uint32_t DeviceType;
    uint32_t StackSize;
    uint32_t AlignmentRequirement;
    uint32_t Characteristics;
    uint32_t SecurityDescriptor;
    // Enough fields for analysis; real struct is much larger
};

struct IRP32 {
    uint16_t Type;              // IO_TYPE_IRP = 6
    uint16_t Size;
    uint32_t MdlAddress;
    uint32_t Flags;
    // IO_STATUS_BLOCK
    uint32_t IoStatus_Status;
    uint32_t IoStatus_Information;
    // RequestorMode
    uint8_t  RequestorMode;     // 0 = KernelMode, 1 = UserMode
    uint8_t  PendingReturned;
    uint8_t  Cancel;
    uint8_t  CancelIrql;
    // Current stack location pointer
    uint32_t Tail_Overlay_CurrentStackLocation;
    // Associated buffers
    uint32_t AssociatedIrp_SystemBuffer;
    uint32_t UserBuffer;
};

struct IO_STACK_LOCATION32 {
    uint8_t  MajorFunction;
    uint8_t  MinorFunction;
    uint8_t  Flags;
    uint8_t  Control;
    // Parameters union — DeviceIoControl layout
    uint32_t OutputBufferLength;
    uint32_t InputBufferLength;
    uint32_t IoControlCode;
    uint32_t Type3InputBuffer;
    // Pointers
    uint32_t DeviceObject;
    uint32_t FileObject;
    uint32_t CompletionRoutine;
    uint32_t Context;
};

// UNICODE_STRING used for registry path argument to DriverEntry
struct KERNEL_UNICODE_STRING32 {
    uint16_t Length;
    uint16_t MaximumLength;
    uint32_t Buffer;
};

#pragma pack(pop)

// ============================================================
// IRP Major Function codes
// ============================================================

enum IrpMajorFunction : uint8_t {
    IRP_MJ_CREATE                   = 0,
    IRP_MJ_CREATE_NAMED_PIPE        = 1,
    IRP_MJ_CLOSE                    = 2,
    IRP_MJ_READ                     = 3,
    IRP_MJ_WRITE                    = 4,
    IRP_MJ_QUERY_INFORMATION        = 5,
    IRP_MJ_SET_INFORMATION          = 6,
    IRP_MJ_FLUSH_BUFFERS            = 9,
    IRP_MJ_DEVICE_CONTROL           = 14,
    IRP_MJ_INTERNAL_DEVICE_CONTROL  = 15,
    IRP_MJ_SHUTDOWN                 = 16,
    IRP_MJ_CLEANUP                  = 18,
    IRP_MJ_POWER                    = 22,
    IRP_MJ_SYSTEM_CONTROL           = 23,
    IRP_MJ_PNP                      = 27,
    IRP_MJ_MAXIMUM_FUNCTION         = 27,
};

// IO_TYPE constants
constexpr uint16_t IO_TYPE_DRIVER = 4;
constexpr uint16_t IO_TYPE_DEVICE = 3;
constexpr uint16_t IO_TYPE_IRP    = 6;

// NTSTATUS codes
constexpr uint32_t STATUS_SUCCESS              = 0x00000000;
constexpr uint32_t STATUS_UNSUCCESSFUL         = 0xC0000001;
constexpr uint32_t STATUS_NOT_IMPLEMENTED      = 0xC0000002;
constexpr uint32_t STATUS_INVALID_PARAMETER    = 0xC000000D;
constexpr uint32_t STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;
constexpr uint32_t STATUS_BUFFER_TOO_SMALL     = 0xC0000023;
constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

// Pool types
constexpr uint32_t NonPagedPool       = 0;
constexpr uint32_t PagedPool          = 1;
constexpr uint32_t NonPagedPoolNx     = 512;

// IRQL levels
constexpr uint8_t PASSIVE_LEVEL  = 0;
constexpr uint8_t APC_LEVEL      = 1;
constexpr uint8_t DISPATCH_LEVEL = 2;

// Kernel environment memory layout constants
constexpr uint32_t KERNEL_DRIVER_OBJ_BASE   = 0xFA000000;
constexpr uint32_t KERNEL_DEVICE_OBJ_BASE   = 0xFA010000;
constexpr uint32_t KERNEL_IRP_BASE          = 0xFA020000;
constexpr uint32_t KERNEL_IO_STACK_BASE     = 0xFA030000;
constexpr uint32_t KERNEL_REGISTRY_PATH_BASE = 0xFA040000;
constexpr uint32_t KERNEL_STRING_POOL_BASE  = 0xFA050000;
constexpr uint32_t KERNEL_DEVICE_EXT_BASE   = 0xFA060000;
constexpr uint32_t KERNEL_DEVICE_EXT_SIZE   = 0x1000;
constexpr uint32_t KERNEL_POOL_BASE         = 0xFA100000;

// ============================================================
// Windows Kernel Environment
// ============================================================

class WindowsKernelEnv {
public:
    WindowsKernelEnv(VirtualMemory& vmem, ICpuBackend& cpu);
    ~WindowsKernelEnv() = default;

    WindowsKernelEnv(const WindowsKernelEnv&) = delete;
    WindowsKernelEnv& operator=(const WindowsKernelEnv&) = delete;

    /// Full setup: allocates DRIVER_OBJECT, registry path, initial state.
    /// Call after loading the .sys PE image.
    void setup(uint64_t driver_base, uint64_t driver_size);

    /// Create a DRIVER_OBJECT in emulated memory.
    /// Returns the virtual address of the created object.
    uint64_t create_driver_object(uint64_t driver_base, uint64_t driver_size,
                                   const std::string& driver_name);

    /// Create a DEVICE_OBJECT linked to a DRIVER_OBJECT.
    /// Returns the virtual address of the created object.
    uint64_t create_device_object(uint64_t driver_obj, uint32_t device_type);

    /// Build and dispatch an IRP to the driver's MajorFunction handler.
    /// Returns the NTSTATUS from IoStatus.Status after the handler returns.
    uint32_t dispatch_irp(uint8_t major_function, uint64_t device_obj,
                           uint64_t input_buf = 0, uint32_t input_size = 0,
                           uint64_t output_buf = 0, uint32_t output_size = 0,
                           uint32_t ioctl_code = 0);

    /// Call DriverEntry(DRIVER_OBJECT*, UNICODE_STRING*).
    /// Sets up the stdcall stack frame and invokes the entry point.
    /// Returns NTSTATUS from the driver.
    uint32_t call_driver_entry(uint64_t entry_point);

    /// Read the MajorFunction dispatch table from the DRIVER_OBJECT.
    /// Returns map of IRP_MJ code -> handler address (non-zero entries only).
    std::map<uint8_t, uint64_t> read_dispatch_table() const;

    /// Accessors
    uint64_t driver_object() const { return driver_object_addr_; }
    uint64_t device_object() const { return device_object_addr_; }
    uint64_t registry_path() const { return registry_path_addr_; }

private:
    VirtualMemory& vmem_;
    ICpuBackend& cpu_;

    uint64_t driver_object_addr_ = 0;
    uint64_t device_object_addr_ = 0;
    uint64_t registry_path_addr_ = 0;
    uint64_t string_pool_ptr_ = KERNEL_STRING_POOL_BASE;
    uint64_t next_irp_addr_ = KERNEL_IRP_BASE;
    uint64_t next_io_stack_addr_ = KERNEL_IO_STACK_BASE;

    /// Write a UTF-16LE string to the kernel string pool, return VA
    uint64_t write_kernel_unicode(const std::string& str);

    /// Write a KERNEL_UNICODE_STRING32 structure at addr
    void write_unicode_struct(uint64_t addr, const std::string& str);

    /// Allocate an IRP + IO_STACK_LOCATION pair in emulated memory
    std::pair<uint64_t, uint64_t> alloc_irp();

    /// Call a function at the given address with stdcall convention.
    /// Pushes args right-to-left, pushes a return sentinel, runs until return.
    uint32_t call_stdcall(uint64_t func_addr,
                           const std::vector<uint32_t>& args);
};

// ============================================================
// Linux Kernel Environment
// ============================================================

class LinuxKernelEnv {
public:
    LinuxKernelEnv(VirtualMemory& vmem, ICpuBackend& cpu);
    ~LinuxKernelEnv() = default;

    LinuxKernelEnv(const LinuxKernelEnv&) = delete;
    LinuxKernelEnv& operator=(const LinuxKernelEnv&) = delete;

    /// Set up minimal Linux kernel-like environment.
    /// Allocates fake /proc and sysfs-like data areas.
    void setup();

    /// Call module_init (init_module function).
    /// Returns the int result (0 = success).
    int call_module_init(uint64_t init_func);

    /// Call module_exit (cleanup_module function).
    void call_module_exit(uint64_t exit_func);

private:
    VirtualMemory& vmem_;
    ICpuBackend& cpu_;

    // Fake kernel data area
    uint64_t kernel_data_base_ = 0xC0000000;

    /// Call a cdecl function with the given arguments.
    uint32_t call_cdecl(uint64_t func_addr,
                         const std::vector<uint32_t>& args);
};

} // namespace vx
