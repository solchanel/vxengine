/**
 * VXEngine FltMgr (Filter Manager) API Stubs
 *
 * Implements stub handlers for minifilter driver registration, filtering,
 * file name queries, context management, and communication ports.
 *
 * Registration function: register_fltmgr_apis(APIDispatcher&)
 */

#include "vxengine/engine.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <string>
#include <cstdlib>
#include <iostream>

namespace vx {

// ============================================================
// Helpers
// ============================================================

// Scratch memory allocator
static uint32_t s_scratch_base = 0x0A400000;
static uint32_t s_scratch_ptr  = 0x0A400000;
static bool     s_scratch_mapped = false;

static uint32_t alloc_scratch(VirtualMemory& vmem, uint32_t size) {
    if (!s_scratch_mapped) {
        vmem.map(s_scratch_base, 0x00100000, 0x06); // RW
        s_scratch_mapped = true;
    }
    uint32_t addr = s_scratch_ptr;
    s_scratch_ptr += (size + 15) & ~15;
    return addr;
}

// NTSTATUS codes
static constexpr uint32_t STATUS_SUCCESS              = 0x00000000;
static constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

// Fake handle values
static constexpr uint32_t FAKE_FILTER_HANDLE = 0xF000;
static constexpr uint32_t FAKE_PORT_HANDLE   = 0xF100;

// ============================================================
// Registration
// ============================================================

void register_fltmgr_apis(APIDispatcher& api) {

    // ---- FltRegisterFilter (3 args, 12 bytes) ----
    api.register_api("FltRegisterFilter",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // Driver (esp+4), Registration (esp+8)
            uint32_t RetFilter = vmem.read32(esp + 12);

            if (RetFilter != 0) {
                vmem.write32(RetFilter, FAKE_FILTER_HANDLE);
            }

            cpu.set_sp(cpu.sp() + 12);
            return STATUS_SUCCESS;
        });

    // ---- FltUnregisterFilter (1 arg, 4 bytes) ----
    api.register_api("FltUnregisterFilter",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return STATUS_SUCCESS;
        });

    // ---- FltStartFiltering (1 arg, 4 bytes) ----
    api.register_api("FltStartFiltering",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return STATUS_SUCCESS;
        });

    // ---- FltGetFileNameInformation (3 args, 12 bytes) ----
    api.register_api("FltGetFileNameInformation",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        });

    // ---- FltReleaseFileNameInformation (1 arg, 4 bytes) ----
    api.register_api("FltReleaseFileNameInformation",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return STATUS_SUCCESS;
        });

    // ---- FltAllocateContext (4 args, 16 bytes) ----
    api.register_api("FltAllocateContext",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- FltSetStreamContext (4 args, 16 bytes) ----
    api.register_api("FltSetStreamContext",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- FltGetStreamContext (3 args, 12 bytes) ----
    api.register_api("FltGetStreamContext",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        });

    // ---- FltCloseCommunicationPort (1 arg, 4 bytes) ----
    api.register_api("FltCloseCommunicationPort",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return STATUS_SUCCESS;
        });

    // ---- FltCreateCommunicationPort (6 args, 24 bytes) ----
    api.register_api("FltCreateCommunicationPort",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // Filter (esp+4), ObjectAttributes (esp+8), ServerPortCookie (esp+12)
            // ConnectNotifyCallback (esp+16), DisconnectNotifyCallback (esp+20)
            // MessageNotifyCallback (esp+24)
            // The second arg is typically where the port handle pointer is,
            // but FltCreateCommunicationPort writes it to arg index 1 (ObjectAttributes contains it)
            // For simplicity, we write to a scratch location if needed
            // Actually: NTSTATUS FltCreateCommunicationPort(Filter, *ServerPort, ObjAttr, Cookie, Connect, Disconnect, Message, MaxConns)
            // The ServerPort is arg 2 (esp+8)
            uint32_t pServerPort = vmem.read32(esp + 8);

            if (pServerPort != 0) {
                vmem.write32(pServerPort, FAKE_PORT_HANDLE);
            }

            cpu.set_sp(cpu.sp() + 24);
            return STATUS_SUCCESS;
        });
}

} // namespace vx
