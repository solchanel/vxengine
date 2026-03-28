/**
 * VXEngine advapi32.dll Security & Service API Stubs
 *
 * Implements stub handlers for token manipulation, service control,
 * user/computer name queries, and basic registry open used by malware.
 *
 * Registration function: register_advapi32_security_apis(APIDispatcher&)
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
static uint32_t s_scratch_base = 0x0A300000;
static uint32_t s_scratch_ptr  = 0x0A300000;
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

// Fake handle values
static constexpr uint32_t FAKE_TOKEN_HANDLE  = 0xD000;
static constexpr uint32_t FAKE_SC_HANDLE     = 0xD100;
static constexpr uint32_t FAKE_SVC_HANDLE    = 0xD200;
static constexpr uint32_t FAKE_SVC_HANDLE2   = 0xD201;
static constexpr uint32_t FAKE_REG_HANDLE    = 0xD300;

static constexpr uint32_t ERROR_SUCCESS = 0;

static uint32_t s_next_reg_handle = FAKE_REG_HANDLE;

// ============================================================
// Registration
// ============================================================

void register_advapi32_security_apis(APIDispatcher& api) {

    // ---- OpenProcessToken (3 args, 12 bytes) ----
    api.register_api("OpenProcessToken",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // ProcessHandle (esp+4), DesiredAccess (esp+8)
            uint32_t TokenHandle = vmem.read32(esp + 12);

            if (TokenHandle != 0) {
                vmem.write32(TokenHandle, FAKE_TOKEN_HANDLE);
            }

            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- GetTokenInformation (5 args, 20 bytes) ----
    api.register_api("GetTokenInformation",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // TokenHandle (esp+4), InfoClass (esp+8)
            uint32_t TokenInfo      = vmem.read32(esp + 12);
            uint32_t TokenInfoLength = vmem.read32(esp + 16);
            uint32_t ReturnLength   = vmem.read32(esp + 20);

            // Write minimal TOKEN_USER: a pointer to a fake SID
            // TOKEN_USER = { SID_AND_ATTRIBUTES { PSID, DWORD } }
            // Minimum: 8 bytes for TOKEN_USER, then a small SID after it
            uint32_t needed = 32;
            if (ReturnLength != 0) {
                vmem.write32(ReturnLength, needed);
            }

            if (TokenInfo != 0 && TokenInfoLength >= needed) {
                // Zero out the buffer first
                vmem.memset(TokenInfo, 0, needed);
                // SID starts at TokenInfo + 8
                uint32_t sid_addr = TokenInfo + 8;
                // TOKEN_USER.User.Sid = pointer to SID
                vmem.write32(TokenInfo, sid_addr);
                // TOKEN_USER.User.Attributes = 0
                vmem.write32(TokenInfo + 4, 0);
                // Write a minimal SID: revision=1, subAuthCount=1, authority={0,0,0,0,0,5}, subAuth={18} (Local System)
                uint8_t fake_sid[] = { 1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0 };
                vmem.write(sid_addr, fake_sid, sizeof(fake_sid));
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- LookupPrivilegeValueA (3 args, 12 bytes) ----
    api.register_api("LookupPrivilegeValueA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // lpSystemName (esp+4), lpName (esp+8)
            uint32_t lpLuid = vmem.read32(esp + 12);

            // Write fake LUID {1, 0}
            if (lpLuid != 0) {
                vmem.write32(lpLuid, 1);     // LowPart
                vmem.write32(lpLuid + 4, 0); // HighPart
            }

            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- LookupPrivilegeValueW (3 args, 12 bytes) ----
    api.register_api("LookupPrivilegeValueW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpLuid = vmem.read32(esp + 12);

            if (lpLuid != 0) {
                vmem.write32(lpLuid, 1);
                vmem.write32(lpLuid + 4, 0);
            }

            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- AdjustTokenPrivileges (6 args, 24 bytes) ----
    api.register_api("AdjustTokenPrivileges",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 24);
            return 1; // TRUE
        });

    // ---- OpenSCManagerA (3 args, 12 bytes) ----
    api.register_api("OpenSCManagerA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return FAKE_SC_HANDLE;
        });

    // ---- OpenSCManagerW (3 args, 12 bytes) ----
    api.register_api("OpenSCManagerW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return FAKE_SC_HANDLE;
        });

    // ---- CreateServiceA (13 args, 52 bytes) ----
    api.register_api("CreateServiceA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hSCManager (esp+4)
            uint32_t lpServiceName = vmem.read32(esp + 8);

            std::string svc_name = read_guest_string(vmem, lpServiceName);
            std::cerr << "[advapi32] CreateServiceA: " << svc_name << std::endl;

            cpu.set_sp(cpu.sp() + 52);
            return FAKE_SVC_HANDLE;
        });

    // ---- CreateServiceW (13 args, 52 bytes) ----
    api.register_api("CreateServiceW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpServiceName = vmem.read32(esp + 8);

            std::string svc_name = read_guest_wstring(vmem, lpServiceName);
            std::cerr << "[advapi32] CreateServiceW: " << svc_name << std::endl;

            cpu.set_sp(cpu.sp() + 52);
            return FAKE_SVC_HANDLE;
        });

    // ---- OpenServiceA (3 args, 12 bytes) ----
    api.register_api("OpenServiceA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return FAKE_SVC_HANDLE2;
        });

    // ---- OpenServiceW (3 args, 12 bytes) ----
    api.register_api("OpenServiceW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return FAKE_SVC_HANDLE2;
        });

    // ---- StartServiceA (3 args, 12 bytes) ----
    api.register_api("StartServiceA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- StartServiceW (3 args, 12 bytes) ----
    api.register_api("StartServiceW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- CloseServiceHandle (1 arg, 4 bytes) ----
    api.register_api("CloseServiceHandle",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ---- GetUserNameA (2 args, 8 bytes) ----
    api.register_api("GetUserNameA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer  = vmem.read32(esp + 4);
            uint32_t pcbBuffer = vmem.read32(esp + 8);

            const char* name = "Admin";
            uint32_t len = 6; // including null terminator
            if (lpBuffer != 0) {
                vmem.write(lpBuffer, name, len);
            }
            if (pcbBuffer != 0) {
                vmem.write32(pcbBuffer, len);
            }

            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- GetUserNameW (2 args, 8 bytes) ----
    api.register_api("GetUserNameW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer  = vmem.read32(esp + 4);
            uint32_t pcbBuffer = vmem.read32(esp + 8);

            std::string name = "Admin";
            if (lpBuffer != 0) {
                write_wide_string(vmem, lpBuffer, name);
            }
            if (pcbBuffer != 0) {
                vmem.write32(pcbBuffer, static_cast<uint32_t>(name.size() + 1));
            }

            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- GetComputerNameA (2 args, 8 bytes) ----
    api.register_api("GetComputerNameA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer   = vmem.read32(esp + 4);
            uint32_t lpnSize    = vmem.read32(esp + 8);

            const char* name = "DESKTOP-VX";
            uint32_t len = 11; // including null terminator
            if (lpBuffer != 0) {
                vmem.write(lpBuffer, name, len);
            }
            if (lpnSize != 0) {
                vmem.write32(lpnSize, len - 1); // nSize excludes null
            }

            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- GetComputerNameW (2 args, 8 bytes) ----
    api.register_api("GetComputerNameW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer = vmem.read32(esp + 4);
            uint32_t lpnSize  = vmem.read32(esp + 8);

            std::string name = "DESKTOP-VX";
            if (lpBuffer != 0) {
                write_wide_string(vmem, lpBuffer, name);
            }
            if (lpnSize != 0) {
                vmem.write32(lpnSize, static_cast<uint32_t>(name.size()));
            }

            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- RegOpenKeyA (3 args, 12 bytes) ----
    api.register_api("RegOpenKeyA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hKey (esp+4), lpSubKey (esp+8)
            uint32_t phkResult = vmem.read32(esp + 12);

            if (phkResult != 0) {
                vmem.write32(phkResult, s_next_reg_handle++);
            }

            cpu.set_sp(cpu.sp() + 12);
            return ERROR_SUCCESS;
        });

    // ---- RegOpenKeyW (3 args, 12 bytes) ----
    api.register_api("RegOpenKeyW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t phkResult = vmem.read32(esp + 12);

            if (phkResult != 0) {
                vmem.write32(phkResult, s_next_reg_handle++);
            }

            cpu.set_sp(cpu.sp() + 12);
            return ERROR_SUCCESS;
        });

    // ---- LookupAccountSidA (7 args, 28 bytes) ----
    api.register_api("LookupAccountSidA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // lpSystemName (esp+4), Sid (esp+8)
            uint32_t lpName       = vmem.read32(esp + 12);
            uint32_t cchName      = vmem.read32(esp + 16);
            uint32_t lpDomain     = vmem.read32(esp + 20);
            uint32_t cchDomain    = vmem.read32(esp + 24);
            // peUse (esp+28)

            const char* acct = "Admin";
            if (lpName != 0) {
                vmem.write(lpName, acct, 6); // "Admin\0"
            }
            if (cchName != 0) {
                vmem.write32(cchName, 6);
            }

            const char* domain = "DESKTOP-VX";
            if (lpDomain != 0) {
                vmem.write(lpDomain, domain, 11);
            }
            if (cchDomain != 0) {
                vmem.write32(cchDomain, 11);
            }

            cpu.set_sp(cpu.sp() + 28);
            return 1; // TRUE
        });

    // ---- LookupAccountSidW (7 args, 28 bytes) ----
    api.register_api("LookupAccountSidW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpName    = vmem.read32(esp + 12);
            uint32_t cchName   = vmem.read32(esp + 16);
            uint32_t lpDomain  = vmem.read32(esp + 20);
            uint32_t cchDomain = vmem.read32(esp + 24);

            if (lpName != 0) {
                write_wide_string(vmem, lpName, "Admin");
            }
            if (cchName != 0) {
                vmem.write32(cchName, 6);
            }

            if (lpDomain != 0) {
                write_wide_string(vmem, lpDomain, "DESKTOP-VX");
            }
            if (cchDomain != 0) {
                vmem.write32(cchDomain, 11);
            }

            cpu.set_sp(cpu.sp() + 28);
            return 1; // TRUE
        });
}

} // namespace vx
