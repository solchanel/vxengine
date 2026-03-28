/**
 * VXEngine winhttp.dll API Stubs
 *
 * Implements:
 *   - WinHttpOpen, WinHttpConnect, WinHttpOpenRequest,
 *     WinHttpSendRequest, WinHttpReceiveResponse, WinHttpReadData,
 *     WinHttpQueryHeaders, WinHttpCloseHandle, WinHttpSetOption,
 *     WinHttpQueryOption
 *
 * All handlers follow stdcall convention: the handler adjusts ESP to pop args,
 * then the dispatcher pops the return address and jumps back.
 */

#include "../include/vxengine/engine.h"
#include "../include/vxengine/memory.h"
#include "../include/vxengine/cpu/icpu.h"
#include <string>
#include <iostream>

namespace vx {

// ============================================================
// Guest memory helpers
// ============================================================

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

// ============================================================
// Static state
// ============================================================

static uint32_t s_winhttp_handle_counter = 0x3000;
static bool s_winhttp_read_first_call = true;

// ============================================================
// register_winhttp_apis
// ============================================================

void register_winhttp_apis(APIDispatcher& api) {

    // ================================================================
    // WinHttpOpen (5 args, 20 bytes)
    // HINTERNET WinHttpOpen(LPCWSTR pszAgentW, DWORD dwAccessType,
    //     LPCWSTR pszProxyW, LPCWSTR pszProxyBypassW, DWORD dwFlags)
    // ================================================================
    api.register_api("WinHttpOpen",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t pszAgent = vmem.read32(esp + 4);

            std::string agent = pszAgent ? read_guest_wstring(vmem, pszAgent) : "";
            std::cerr << "[vx] NET: WinHttpOpen agent=\"" << agent << "\"\n";

            cpu.set_sp(cpu.sp() + 20);
            return s_winhttp_handle_counter++;
        });

    // ================================================================
    // WinHttpConnect (4 args, 16 bytes)
    // HINTERNET WinHttpConnect(HINTERNET hSession, LPCWSTR pswzServerName,
    //     INTERNET_PORT nServerPort, DWORD dwReserved)
    // ================================================================
    api.register_api("WinHttpConnect",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t pswzServerName = vmem.read32(esp + 8);
            uint32_t nServerPort    = vmem.read32(esp + 12);

            std::string server = pswzServerName ? read_guest_wstring(vmem, pswzServerName) : "";
            uint16_t port = static_cast<uint16_t>(nServerPort);
            std::cerr << "[vx] NET: WinHttpConnect " << server << ":" << port << "\n";

            cpu.set_sp(cpu.sp() + 16);
            return s_winhttp_handle_counter++;
        });

    // ================================================================
    // WinHttpOpenRequest (7 args, 28 bytes)
    // HINTERNET WinHttpOpenRequest(HINTERNET hConnect, LPCWSTR pwszVerb,
    //     LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer,
    //     LPCWSTR* ppwszAcceptTypes, DWORD dwFlags)
    // ================================================================
    api.register_api("WinHttpOpenRequest",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t pwszVerb       = vmem.read32(esp + 8);
            uint32_t pwszObjectName = vmem.read32(esp + 12);

            std::string verb = pwszVerb ? read_guest_wstring(vmem, pwszVerb) : "GET";
            std::string path = pwszObjectName ? read_guest_wstring(vmem, pwszObjectName) : "/";
            std::cerr << "[vx] NET: WinHttpOpenRequest " << verb << " " << path << "\n";

            cpu.set_sp(cpu.sp() + 28);
            return s_winhttp_handle_counter++;
        });

    // ================================================================
    // WinHttpSendRequest (7 args, 28 bytes)
    // BOOL WinHttpSendRequest(HINTERNET hRequest, LPCWSTR lpszHeaders,
    //     DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength,
    //     DWORD dwTotalLength, DWORD_PTR dwContext)
    // ================================================================
    api.register_api("WinHttpSendRequest",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            std::cerr << "[vx] NET: WinHttpSendRequest\n";
            s_winhttp_read_first_call = true;
            cpu.set_sp(cpu.sp() + 28);
            return 1; // TRUE
        });

    // ================================================================
    // WinHttpReceiveResponse (2 args, 8 bytes)
    // BOOL WinHttpReceiveResponse(HINTERNET hRequest, LPVOID lpReserved)
    // ================================================================
    api.register_api("WinHttpReceiveResponse",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ================================================================
    // WinHttpReadData (4 args, 16 bytes)
    // BOOL WinHttpReadData(HINTERNET hRequest, LPVOID lpBuffer,
    //     DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
    // ================================================================
    api.register_api("WinHttpReadData",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer              = vmem.read32(esp + 8);
            uint32_t lpdwNumberOfBytesRead = vmem.read32(esp + 16);

            if (s_winhttp_read_first_call) {
                if (lpBuffer) {
                    uint8_t body[] = {'O', 'K'};
                    vmem.write(lpBuffer, body, 2);
                }
                if (lpdwNumberOfBytesRead) {
                    vmem.write32(lpdwNumberOfBytesRead, 2);
                }
                s_winhttp_read_first_call = false;
            } else {
                if (lpdwNumberOfBytesRead) {
                    vmem.write32(lpdwNumberOfBytesRead, 0);
                }
            }

            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // WinHttpQueryHeaders (6 args, 24 bytes)
    // BOOL WinHttpQueryHeaders(HINTERNET hRequest, DWORD dwInfoLevel,
    //     LPCWSTR pwszName, LPVOID lpBuffer, LPDWORD lpdwBufferLength,
    //     LPDWORD lpdwIndex)
    // ================================================================
    api.register_api("WinHttpQueryHeaders",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 24);
            return 0; // FALSE
        });

    // ================================================================
    // WinHttpCloseHandle (1 arg, 4 bytes)
    // BOOL WinHttpCloseHandle(HINTERNET hInternet)
    // ================================================================
    api.register_api("WinHttpCloseHandle",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ================================================================
    // WinHttpSetOption (4 args, 16 bytes)
    // BOOL WinHttpSetOption(HINTERNET hInternet, DWORD dwOption,
    //     LPVOID lpBuffer, DWORD dwBufferLength)
    // ================================================================
    api.register_api("WinHttpSetOption",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // WinHttpQueryOption (4 args, 16 bytes)
    // BOOL WinHttpQueryOption(HINTERNET hInternet, DWORD dwOption,
    //     LPVOID lpBuffer, LPDWORD lpdwBufferLength)
    // ================================================================
    api.register_api("WinHttpQueryOption",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0; // FALSE
        });

} // register_winhttp_apis

} // namespace vx
