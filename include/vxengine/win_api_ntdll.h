#pragma once
/**
 * VXEngine NT Native API, Syscall Interception, and Device I/O
 *
 * Provides:
 *   - SyscallInterceptor: maps Windows syscall numbers to handlers
 *     (hooks int 0x2e / sysenter / syscall)
 *   - DeviceIOInterceptor: dispatches DeviceIoControl / NtDeviceIoControlFile
 *   - NT status codes and IOCTL macros
 */

#include "vxengine.h"
#include "memory.h"
#include "win_api.h"

#include <map>
#include <vector>
#include <string>
#include <functional>

namespace vx {

// ============================================================
// NT Status Codes
// ============================================================
constexpr uint32_t STATUS_SUCCESS                = 0x00000000;
constexpr uint32_t STATUS_INVALID_HANDLE         = 0xC0000008;
constexpr uint32_t STATUS_INVALID_PARAMETER      = 0xC000000D;
constexpr uint32_t STATUS_ACCESS_DENIED          = 0xC0000022;
constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND  = 0xC0000034;
constexpr uint32_t STATUS_INFO_LENGTH_MISMATCH   = 0xC0000004;
constexpr uint32_t STATUS_PORT_NOT_CONNECTED     = 0xC0000037;
constexpr uint32_t STATUS_INVALID_DEVICE_REQUEST = 0xC0000010;
constexpr uint32_t STATUS_BUFFER_TOO_SMALL       = 0xC0000023;
constexpr uint32_t STATUS_NOT_IMPLEMENTED        = 0xC0000002;
constexpr uint32_t STATUS_BUFFER_OVERFLOW        = 0x80000005;

// ProcessInformationClass values
constexpr uint32_t ProcessBasicInformation       = 0;
constexpr uint32_t ProcessDebugPort              = 7;
constexpr uint32_t ProcessDebugObjectHandle      = 0x1E;
constexpr uint32_t ProcessDebugFlags             = 0x1F;

// ThreadInformationClass values
constexpr uint32_t ThreadHideFromDebugger        = 0x11;

// SystemInformationClass values
constexpr uint32_t SystemBasicInformation        = 0;
constexpr uint32_t SystemProcessInformation      = 5;

// ============================================================
// IOCTL Macros
// ============================================================
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

constexpr uint32_t METHOD_BUFFERED    = 0;
constexpr uint32_t METHOD_IN_DIRECT   = 1;
constexpr uint32_t METHOD_OUT_DIRECT  = 2;
constexpr uint32_t METHOD_NEITHER     = 3;

constexpr uint32_t FILE_ANY_ACCESS    = 0;
constexpr uint32_t FILE_READ_ACCESS   = 1;
constexpr uint32_t FILE_WRITE_ACCESS  = 2;

// Extract fields from IOCTL code
inline uint32_t IOCTL_DEVICE_TYPE(uint32_t code) { return (code >> 16) & 0xFFFF; }
inline uint32_t IOCTL_ACCESS(uint32_t code)      { return (code >> 14) & 0x3; }
inline uint32_t IOCTL_FUNCTION(uint32_t code)     { return (code >> 2) & 0xFFF; }
inline uint32_t IOCTL_METHOD(uint32_t code)       { return code & 0x3; }

// ============================================================
// Syscall Interceptor
// ============================================================

class SyscallInterceptor {
public:
    struct SyscallEntry {
        uint32_t number;
        std::string name;
        NativeAPIHandler handler;
        bool logged = false;
    };

    SyscallInterceptor() = default;

    /// Register a syscall handler by number
    void register_syscall(uint32_t number, const std::string& name,
                          NativeAPIHandler handler);

    /// Dispatch a syscall. Syscall number is read from EAX.
    /// Returns true if handled.
    bool handle_syscall(uint32_t number, X86Backend& cpu,
                        VirtualMemory& vmem, EmulatedHeap& heap);

    /// Enable/disable syscall logging
    void set_logging(bool enable) { logging_enabled_ = enable; }

    /// Get syscall log: pairs of (syscall_number, arg_snapshot)
    const std::vector<std::pair<uint32_t, std::vector<uint32_t>>>& log() const {
        return syscall_log_;
    }

    /// Register all known Windows 10 22H2 syscalls
    void register_win10_syscalls(APIDispatcher& disp);

private:
    std::map<uint32_t, SyscallEntry> syscall_table_;
    std::vector<std::pair<uint32_t, std::vector<uint32_t>>> syscall_log_;
    bool logging_enabled_ = false;
};

// ============================================================
// Device I/O Interceptor
// ============================================================

class DeviceIOInterceptor {
public:
    using IOCTLHandlerFn = std::function<uint32_t(
        VirtualMemory& vmem,
        uint64_t in_buf, uint32_t in_size,
        uint64_t out_buf, uint32_t out_size)>;

    struct IOCTLHandler {
        uint32_t ioctl_code;
        std::string device_name;
        IOCTLHandlerFn handler;
    };

    DeviceIOInterceptor() = default;

    /// Register an IOCTL handler
    void register_ioctl(uint32_t code, const std::string& device,
                        IOCTLHandlerFn handler);

    /// Handle DeviceIoControl dispatch.
    /// Returns STATUS_SUCCESS or an NT error status.
    uint32_t handle_device_io_control(VirtualMemory& vmem,
                                      uint32_t ioctl_code,
                                      uint64_t in_buf, uint32_t in_size,
                                      uint64_t out_buf, uint32_t out_size,
                                      uint64_t bytes_returned_ptr);

    /// Register built-in IOCTL handlers (disk geometry, null device, etc.)
    void register_builtins();

private:
    std::map<uint32_t, IOCTLHandler> ioctl_handlers_;
};

// ============================================================
// Registration functions (called from APIDispatcher setup)
// ============================================================

/// Register extended kernel32 APIs (W/Ex variants, file, process, etc.)
void register_extended_apis(APIDispatcher& disp);

/// Register ntdll APIs, syscall interceptor, and device I/O handlers
void register_ntdll_apis(APIDispatcher& disp);

} // namespace vx
