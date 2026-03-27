/**
 * VXEngine Kernel Environment Implementation
 *
 * Creates fake DRIVER_OBJECT, DEVICE_OBJECT, IRP structures in emulated
 * memory and provides methods to invoke DriverEntry, dispatch IRPs, and
 * read back the dispatch table after the driver has initialized.
 *
 * Also provides a minimal Linux kernel module environment for calling
 * module_init and module_exit entry points.
 */

#include "../include/vxengine/kernel_env.h"
#include <cstring>
#include <algorithm>
#include <cassert>

namespace vx {

// ============================================================
// Return sentinel: when execution reaches this address, we know
// the called function has returned.
// ============================================================
static constexpr uint64_t KERNEL_RETURN_SENTINEL = 0xDEAD0000;

// ============================================================
// WindowsKernelEnv — Construction
// ============================================================

WindowsKernelEnv::WindowsKernelEnv(VirtualMemory& vmem, ICpuBackend& cpu)
    : vmem_(vmem)
    , cpu_(cpu)
{
}

// ============================================================
// WindowsKernelEnv::setup
// ============================================================

void WindowsKernelEnv::setup(uint64_t driver_base, uint64_t driver_size) {
    // Map kernel structure regions
    vmem_.map(KERNEL_DRIVER_OBJ_BASE,  0x1000, PERM_RW);
    vmem_.map(KERNEL_DEVICE_OBJ_BASE,  0x1000, PERM_RW);
    vmem_.map(KERNEL_IRP_BASE,         0x10000, PERM_RW);
    vmem_.map(KERNEL_IO_STACK_BASE,    0x10000, PERM_RW);
    vmem_.map(KERNEL_REGISTRY_PATH_BASE, 0x1000, PERM_RW);
    vmem_.map(KERNEL_STRING_POOL_BASE, 0x10000, PERM_RW);
    vmem_.map(KERNEL_DEVICE_EXT_BASE,  KERNEL_DEVICE_EXT_SIZE, PERM_RW);

    // Map the return sentinel page with a HLT instruction (0xF4)
    vmem_.map(KERNEL_RETURN_SENTINEL & PAGE_MASK, PAGE_SIZE, PERM_RWX);
    uint8_t hlt = 0xF4; // HLT
    vmem_.write(KERNEL_RETURN_SENTINEL, &hlt, 1);

    // Create DRIVER_OBJECT
    driver_object_addr_ = create_driver_object(
        driver_base, driver_size, "\\Driver\\EmulatedDriver");

    // Create registry path: \Registry\Machine\System\...
    write_unicode_struct(KERNEL_REGISTRY_PATH_BASE,
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\EmulatedDriver");
    registry_path_addr_ = KERNEL_REGISTRY_PATH_BASE;
}

// ============================================================
// WindowsKernelEnv::create_driver_object
// ============================================================

uint64_t WindowsKernelEnv::create_driver_object(
    uint64_t driver_base, uint64_t driver_size,
    const std::string& driver_name)
{
    uint64_t addr = KERNEL_DRIVER_OBJ_BASE;

    // Zero-initialize the entire region
    vmem_.memset(addr, 0, sizeof(DRIVER_OBJECT32));

    DRIVER_OBJECT32 drv = {};
    drv.Type = IO_TYPE_DRIVER;
    drv.Size = sizeof(DRIVER_OBJECT32);
    drv.DeviceObject = 0;  // No device yet
    drv.Flags = 0;
    drv.DriverStart = static_cast<uint32_t>(driver_base);
    drv.DriverSize = static_cast<uint32_t>(driver_size);
    drv.DriverSection = 0;     // Fake LDR entry not needed
    drv.DriverExtension = 0;   // Could allocate if needed

    // Write driver name as UNICODE_STRING
    uint64_t name_buf = write_kernel_unicode(driver_name);
    drv.DriverNameLength = static_cast<uint16_t>(driver_name.size() * 2);
    drv.DriverNameMaxLength = static_cast<uint16_t>(driver_name.size() * 2 + 2);
    drv.DriverNameBuffer = static_cast<uint32_t>(name_buf);

    // Zero-init MajorFunction table (all entries = 0, meaning unhandled)
    for (int i = 0; i < 28; i++) {
        drv.MajorFunction[i] = 0;
    }

    vmem_.write(addr, &drv, sizeof(drv));

    driver_object_addr_ = addr;
    return addr;
}

// ============================================================
// WindowsKernelEnv::create_device_object
// ============================================================

uint64_t WindowsKernelEnv::create_device_object(
    uint64_t driver_obj, uint32_t device_type)
{
    uint64_t addr = KERNEL_DEVICE_OBJ_BASE;

    vmem_.memset(addr, 0, sizeof(DEVICE_OBJECT32));

    DEVICE_OBJECT32 dev = {};
    dev.Type = IO_TYPE_DEVICE;
    dev.Size = sizeof(DEVICE_OBJECT32);
    dev.ReferenceCount = 1;
    dev.DriverObject = static_cast<uint32_t>(driver_obj);
    dev.NextDevice = 0;
    dev.AttachedDevice = 0;
    dev.CurrentIrp = 0;
    dev.Flags = 0;
    dev.DeviceExtension = KERNEL_DEVICE_EXT_BASE;
    dev.DeviceType = device_type;
    dev.StackSize = 1;
    dev.AlignmentRequirement = 0;
    dev.Characteristics = 0;
    dev.SecurityDescriptor = 0;

    vmem_.write(addr, &dev, sizeof(dev));

    // Link the device to the driver object's DeviceObject field
    uint32_t dev_addr32 = static_cast<uint32_t>(addr);
    vmem_.write(driver_obj + offsetof(DRIVER_OBJECT32, DeviceObject),
                &dev_addr32, sizeof(dev_addr32));

    device_object_addr_ = addr;
    return addr;
}

// ============================================================
// WindowsKernelEnv::call_driver_entry
// ============================================================

uint32_t WindowsKernelEnv::call_driver_entry(uint64_t entry_point) {
    // DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    // stdcall on x86: args pushed right-to-left, callee cleans stack
    std::vector<uint32_t> args = {
        static_cast<uint32_t>(driver_object_addr_),
        static_cast<uint32_t>(registry_path_addr_)
    };
    return call_stdcall(entry_point, args);
}

// ============================================================
// WindowsKernelEnv::dispatch_irp
// ============================================================

uint32_t WindowsKernelEnv::dispatch_irp(
    uint8_t major_function, uint64_t device_obj,
    uint64_t input_buf, uint32_t input_size,
    uint64_t output_buf, uint32_t output_size,
    uint32_t ioctl_code)
{
    // Read the dispatch table to find the handler
    auto dispatch_table = read_dispatch_table();
    auto it = dispatch_table.find(major_function);
    if (it == dispatch_table.end() || it->second == 0) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    uint64_t handler_addr = it->second;

    // Allocate IRP + IO_STACK_LOCATION
    auto [irp_addr, io_stack_addr] = alloc_irp();

    // Fill IRP
    IRP32 irp = {};
    irp.Type = IO_TYPE_IRP;
    irp.Size = sizeof(IRP32);
    irp.MdlAddress = 0;
    irp.Flags = 0;
    irp.IoStatus_Status = STATUS_SUCCESS;
    irp.IoStatus_Information = 0;
    irp.RequestorMode = 1; // UserMode
    irp.PendingReturned = 0;
    irp.Cancel = 0;
    irp.CancelIrql = 0;
    irp.Tail_Overlay_CurrentStackLocation = static_cast<uint32_t>(io_stack_addr);
    irp.AssociatedIrp_SystemBuffer = static_cast<uint32_t>(input_buf);
    irp.UserBuffer = static_cast<uint32_t>(output_buf);

    vmem_.write(irp_addr, &irp, sizeof(irp));

    // Fill IO_STACK_LOCATION
    IO_STACK_LOCATION32 iosl = {};
    iosl.MajorFunction = major_function;
    iosl.MinorFunction = 0;
    iosl.Flags = 0;
    iosl.Control = 0;
    iosl.OutputBufferLength = output_size;
    iosl.InputBufferLength = input_size;
    iosl.IoControlCode = ioctl_code;
    iosl.Type3InputBuffer = 0;
    iosl.DeviceObject = static_cast<uint32_t>(device_obj);
    iosl.FileObject = 0;
    iosl.CompletionRoutine = 0;
    iosl.Context = 0;

    vmem_.write(io_stack_addr, &iosl, sizeof(iosl));

    // Call the dispatch handler: handler(DEVICE_OBJECT*, IRP*)
    // stdcall convention
    std::vector<uint32_t> args = {
        static_cast<uint32_t>(device_obj),
        static_cast<uint32_t>(irp_addr)
    };
    call_stdcall(handler_addr, args);

    // Read NTSTATUS from IRP's IoStatus.Status
    uint32_t status = vmem_.read32(
        irp_addr + offsetof(IRP32, IoStatus_Status));
    return status;
}

// ============================================================
// WindowsKernelEnv::read_dispatch_table
// ============================================================

std::map<uint8_t, uint64_t> WindowsKernelEnv::read_dispatch_table() const {
    std::map<uint8_t, uint64_t> table;

    if (driver_object_addr_ == 0) return table;

    uint64_t mf_offset = driver_object_addr_ +
        offsetof(DRIVER_OBJECT32, MajorFunction);

    for (uint8_t i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        uint32_t handler = vmem_.read32(mf_offset + i * 4);
        if (handler != 0) {
            table[i] = handler;
        }
    }

    return table;
}

// ============================================================
// WindowsKernelEnv — Helpers
// ============================================================

uint64_t WindowsKernelEnv::write_kernel_unicode(const std::string& str) {
    uint64_t addr = string_pool_ptr_;

    // Write UTF-16LE (simple ASCII -> UTF-16 conversion)
    for (size_t i = 0; i < str.size(); i++) {
        uint16_t wc = static_cast<uint16_t>(str[i]);
        vmem_.write(addr + i * 2, &wc, 2);
    }
    // Null terminator
    uint16_t null_term = 0;
    vmem_.write(addr + str.size() * 2, &null_term, 2);

    string_pool_ptr_ += static_cast<uint64_t>((str.size() + 1) * 2);
    // Align to 4 bytes
    string_pool_ptr_ = (string_pool_ptr_ + 3) & ~3ULL;

    return addr;
}

void WindowsKernelEnv::write_unicode_struct(uint64_t addr, const std::string& str) {
    uint64_t buf_addr = write_kernel_unicode(str);

    KERNEL_UNICODE_STRING32 us = {};
    us.Length = static_cast<uint16_t>(str.size() * 2);
    us.MaximumLength = static_cast<uint16_t>(str.size() * 2 + 2);
    us.Buffer = static_cast<uint32_t>(buf_addr);

    vmem_.write(addr, &us, sizeof(us));
}

std::pair<uint64_t, uint64_t> WindowsKernelEnv::alloc_irp() {
    uint64_t irp_addr = next_irp_addr_;
    next_irp_addr_ += sizeof(IRP32);
    // Align to 16 bytes
    next_irp_addr_ = (next_irp_addr_ + 15) & ~15ULL;

    uint64_t io_stack_addr = next_io_stack_addr_;
    next_io_stack_addr_ += sizeof(IO_STACK_LOCATION32);
    next_io_stack_addr_ = (next_io_stack_addr_ + 15) & ~15ULL;

    return {irp_addr, io_stack_addr};
}

uint32_t WindowsKernelEnv::call_stdcall(
    uint64_t func_addr, const std::vector<uint32_t>& args)
{
    // Save current state
    uint64_t saved_sp = cpu_.sp();
    uint64_t saved_pc = cpu_.pc();

    // Push args right-to-left (stdcall convention)
    uint64_t sp = saved_sp;
    for (int i = static_cast<int>(args.size()) - 1; i >= 0; i--) {
        sp -= 4;
        vmem_.write32(sp, args[i]);
    }

    // Push return sentinel as the return address
    sp -= 4;
    vmem_.write32(sp, static_cast<uint32_t>(KERNEL_RETURN_SENTINEL));

    cpu_.set_sp(sp);
    cpu_.set_pc(func_addr);

    // Run until we hit the return sentinel (HLT instruction)
    // Limit to 10M instructions to prevent infinite loops
    RunResult result = cpu_.run_until(KERNEL_RETURN_SENTINEL, 10000000);

    // Read EAX (return value)
    uint32_t retval = static_cast<uint32_t>(cpu_.reg(0)); // reg(0) = EAX on x86

    // Restore PC (SP should have been cleaned by callee for stdcall)
    cpu_.set_pc(saved_pc);

    return retval;
}

// ============================================================
// LinuxKernelEnv — Construction
// ============================================================

LinuxKernelEnv::LinuxKernelEnv(VirtualMemory& vmem, ICpuBackend& cpu)
    : vmem_(vmem)
    , cpu_(cpu)
{
}

// ============================================================
// LinuxKernelEnv::setup
// ============================================================

void LinuxKernelEnv::setup() {
    // Map a fake kernel data area for printk buffer, /proc, etc.
    vmem_.map(kernel_data_base_, 0x10000, PERM_RW);
    vmem_.memset(kernel_data_base_, 0, 0x10000);

    // Map the return sentinel
    uint64_t sentinel_page = KERNEL_RETURN_SENTINEL & PAGE_MASK;
    if (!vmem_.is_mapped(sentinel_page)) {
        vmem_.map(sentinel_page, PAGE_SIZE, PERM_RWX);
    }
    uint8_t hlt = 0xF4;
    vmem_.write(KERNEL_RETURN_SENTINEL, &hlt, 1);

    // Write a fake jiffies value at a known location
    uint32_t fake_jiffies = 1000000;
    vmem_.write32(kernel_data_base_ + 0x100, fake_jiffies);

    // Write a fake HZ value (100 for typical kernel)
    uint32_t fake_hz = 100;
    vmem_.write32(kernel_data_base_ + 0x104, fake_hz);
}

// ============================================================
// LinuxKernelEnv::call_module_init
// ============================================================

int LinuxKernelEnv::call_module_init(uint64_t init_func) {
    // Linux module init_module(void) -> int
    // cdecl, no arguments
    uint32_t result = call_cdecl(init_func, {});
    return static_cast<int>(result);
}

// ============================================================
// LinuxKernelEnv::call_module_exit
// ============================================================

void LinuxKernelEnv::call_module_exit(uint64_t exit_func) {
    // Linux module cleanup_module(void) -> void
    // cdecl, no arguments
    call_cdecl(exit_func, {});
}

// ============================================================
// LinuxKernelEnv — Helpers
// ============================================================

uint32_t LinuxKernelEnv::call_cdecl(
    uint64_t func_addr, const std::vector<uint32_t>& args)
{
    uint64_t saved_sp = cpu_.sp();
    uint64_t saved_pc = cpu_.pc();

    uint64_t sp = saved_sp;

    // Push args right-to-left (cdecl also pushes R-to-L, but caller cleans)
    for (int i = static_cast<int>(args.size()) - 1; i >= 0; i--) {
        sp -= 4;
        vmem_.write32(sp, args[i]);
    }

    // Push return sentinel
    sp -= 4;
    vmem_.write32(sp, static_cast<uint32_t>(KERNEL_RETURN_SENTINEL));

    cpu_.set_sp(sp);
    cpu_.set_pc(func_addr);

    // Run until return sentinel
    RunResult result = cpu_.run_until(KERNEL_RETURN_SENTINEL, 10000000);

    // Read return value from EAX
    uint32_t retval = static_cast<uint32_t>(cpu_.reg(0));

    // Restore state (cdecl: caller cleans stack)
    cpu_.set_sp(saved_sp);
    cpu_.set_pc(saved_pc);

    return retval;
}

} // namespace vx
