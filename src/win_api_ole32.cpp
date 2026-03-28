/**
 * VXEngine ole32.dll / COM Stubs
 *
 * Implements stub handlers for COM initialization and object creation
 * functions commonly encountered in malware samples.
 *
 * Registration function: register_ole32_apis(APIDispatcher&)
 */

#include "vxengine/engine.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <string>
#include <cstdlib>
#include <iostream>
#include <cstdio>

namespace vx {

// ============================================================
// Helpers
// ============================================================

static std::string read_guest_string(VirtualMemory& vmem, uint64_t addr,
                                      size_t max_len = 1024) {
    std::string result;
    for (size_t i = 0; i < max_len; ++i) {
        uint8_t ch = 0;
        vmem.read(addr + i, &ch, 1);
        if (ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

static std::string read_guest_wstring(VirtualMemory& vmem, uint64_t addr,
                                       size_t max_chars = 512) {
    std::string result;
    for (size_t i = 0; i < max_chars; ++i) {
        uint16_t wch = 0;
        vmem.read(addr + i * 2, &wch, 2);
        if (wch == 0) break;
        result += static_cast<char>(wch & 0xFF);
    }
    return result;
}

static void write_wide_string(VirtualMemory& vmem, uint64_t addr, const std::string& str) {
    for (size_t i = 0; i < str.size(); ++i) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
        vmem.write(addr + i * 2, &wc, 2);
    }
    uint16_t null_term = 0;
    vmem.write(addr + str.size() * 2, &null_term, 2);
}

// Scratch memory allocator
static uint32_t s_scratch_base = 0x0A200000;
static uint32_t s_scratch_ptr  = 0x0A200000;
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

// COM constants
static constexpr uint32_t S_OK            = 0x00000000;
static constexpr uint32_t E_NOINTERFACE   = 0x80004002;

// ============================================================
// Registration
// ============================================================

void register_ole32_apis(APIDispatcher& api) {

    // ---- CoInitialize (1 arg, 4 bytes) ----
    api.register_api("CoInitialize",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return S_OK;
        });

    // ---- CoInitializeEx (2 args, 8 bytes) ----
    api.register_api("CoInitializeEx",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return S_OK;
        });

    // ---- CoUninitialize (0 args) ----
    api.register_api("CoUninitialize",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            return 0;
        });

    // ---- CoCreateInstance (5 args, 20 bytes) ----
    api.register_api("CoCreateInstance",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t rclsid      = vmem.read32(esp + 4);
            // pUnkOuter (esp+8), dwClsContext (esp+12), riid (esp+16)
            uint32_t ppv         = vmem.read32(esp + 20);

            // Log the CLSID
            if (rclsid != 0) {
                uint8_t guid[16];
                vmem.read(rclsid, guid, 16);
                char buf[64];
                std::snprintf(buf, sizeof(buf),
                    "{%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                    guid[3], guid[2], guid[1], guid[0],
                    guid[5], guid[4], guid[7], guid[6],
                    guid[8], guid[9], guid[10], guid[11],
                    guid[12], guid[13], guid[14], guid[15]);
                std::cerr << "[ole32] CoCreateInstance CLSID=" << buf << std::endl;
            }

            // Write NULL to *ppv
            if (ppv != 0) {
                vmem.write32(ppv, 0);
            }

            cpu.set_sp(cpu.sp() + 20);
            return E_NOINTERFACE;
        });

    // ---- CoTaskMemAlloc (1 arg, 4 bytes) ----
    api.register_api("CoTaskMemAlloc",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cb = vmem.read32(esp + 4);

            uint32_t addr = alloc_scratch(vmem, cb);

            cpu.set_sp(cpu.sp() + 4);
            return addr;
        });

    // ---- CoTaskMemFree (1 arg, 4 bytes) ----
    api.register_api("CoTaskMemFree",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0;
        });

    // ---- CoTaskMemRealloc (2 args, 8 bytes) ----
    api.register_api("CoTaskMemRealloc",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // pv (esp+4) — old pointer, ignored (no deallocation in scratch)
            uint32_t cb = vmem.read32(esp + 8);

            uint32_t addr = alloc_scratch(vmem, cb);

            cpu.set_sp(cpu.sp() + 8);
            return addr;
        });

    // ---- OleInitialize (1 arg, 4 bytes) ----
    api.register_api("OleInitialize",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return S_OK;
        });

    // ---- OleUninitialize (0 args) ----
    api.register_api("OleUninitialize",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            return 0;
        });

    // ---- CLSIDFromString (2 args, 8 bytes) ----
    api.register_api("CLSIDFromString",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // lpsz (esp+4)
            uint32_t pclsid = vmem.read32(esp + 8);

            // Write zero GUID
            if (pclsid != 0) {
                uint8_t zeros[16] = {0};
                vmem.write(pclsid, zeros, 16);
            }

            cpu.set_sp(cpu.sp() + 8);
            return S_OK;
        });

    // ---- StringFromCLSID (2 args, 8 bytes) ----
    api.register_api("StringFromCLSID",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // rclsid (esp+4)
            uint32_t lplpsz = vmem.read32(esp + 8);

            // Allocate scratch for a fake GUID string
            std::string fake_guid = "{00000000-0000-0000-0000-000000000000}";
            uint32_t str_addr = alloc_scratch(vmem, static_cast<uint32_t>((fake_guid.size() + 1) * 2));
            write_wide_string(vmem, str_addr, fake_guid);

            if (lplpsz != 0) {
                vmem.write32(lplpsz, str_addr);
            }

            cpu.set_sp(cpu.sp() + 8);
            return S_OK;
        });
}

} // namespace vx
