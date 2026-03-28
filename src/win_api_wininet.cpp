/**
 * VXEngine wininet.dll API Stubs
 *
 * Implements:
 *   - InternetOpenA/W, InternetConnectA/W, HttpOpenRequestA/W,
 *     HttpSendRequestA/W, InternetReadFile, InternetOpenUrlA/W,
 *     InternetCloseHandle, InternetQueryOptionA/W,
 *     HttpQueryInfoA/W
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

// ============================================================
// Static state
// ============================================================

static uint32_t s_inet_handle_counter = 0x2000;
static bool s_inet_read_first_call = true;

// ============================================================
// register_wininet_apis
// ============================================================

void register_wininet_apis(APIDispatcher& api) {

    // ================================================================
    // InternetOpenA (5 args, 20 bytes)
    // HINTERNET InternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType,
    //     LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
    // ================================================================
    api.register_api("InternetOpenA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszAgent = vmem.read32(esp + 4);

            std::string agent = lpszAgent ? read_guest_string(vmem, lpszAgent) : "";
            std::cerr << "[vx] NET: InternetOpen agent=\"" << agent << "\"\n";

            cpu.set_sp(cpu.sp() + 20);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // InternetOpenW (5 args, 20 bytes)
    // ================================================================
    api.register_api("InternetOpenW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszAgent = vmem.read32(esp + 4);

            std::string agent = lpszAgent ? read_guest_wstring(vmem, lpszAgent) : "";
            std::cerr << "[vx] NET: InternetOpen agent=\"" << agent << "\"\n";

            cpu.set_sp(cpu.sp() + 20);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // InternetConnectA (8 args, 32 bytes)
    // HINTERNET InternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName,
    //     INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword,
    //     DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
    // ================================================================
    api.register_api("InternetConnectA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszServerName = vmem.read32(esp + 8);
            uint32_t nServerPort    = vmem.read32(esp + 12);

            std::string server = lpszServerName ? read_guest_string(vmem, lpszServerName) : "";
            uint16_t port = static_cast<uint16_t>(nServerPort);
            std::cerr << "[vx] NET: InternetConnect " << server << ":" << port << "\n";

            cpu.set_sp(cpu.sp() + 32);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // InternetConnectW (8 args, 32 bytes)
    // ================================================================
    api.register_api("InternetConnectW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszServerName = vmem.read32(esp + 8);
            uint32_t nServerPort    = vmem.read32(esp + 12);

            std::string server = lpszServerName ? read_guest_wstring(vmem, lpszServerName) : "";
            uint16_t port = static_cast<uint16_t>(nServerPort);
            std::cerr << "[vx] NET: InternetConnect " << server << ":" << port << "\n";

            cpu.set_sp(cpu.sp() + 32);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // HttpOpenRequestA (8 args, 32 bytes)
    // HINTERNET HttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb,
    //     LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer,
    //     LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
    // ================================================================
    api.register_api("HttpOpenRequestA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszVerb       = vmem.read32(esp + 8);
            uint32_t lpszObjectName = vmem.read32(esp + 12);

            std::string verb = lpszVerb ? read_guest_string(vmem, lpszVerb) : "GET";
            std::string path = lpszObjectName ? read_guest_string(vmem, lpszObjectName) : "/";
            std::cerr << "[vx] NET: HttpOpenRequest " << verb << " " << path << "\n";

            cpu.set_sp(cpu.sp() + 32);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // HttpOpenRequestW (8 args, 32 bytes)
    // ================================================================
    api.register_api("HttpOpenRequestW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszVerb       = vmem.read32(esp + 8);
            uint32_t lpszObjectName = vmem.read32(esp + 12);

            std::string verb = lpszVerb ? read_guest_wstring(vmem, lpszVerb) : "GET";
            std::string path = lpszObjectName ? read_guest_wstring(vmem, lpszObjectName) : "/";
            std::cerr << "[vx] NET: HttpOpenRequest " << verb << " " << path << "\n";

            cpu.set_sp(cpu.sp() + 32);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // HttpSendRequestA (5 args, 20 bytes)
    // BOOL HttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders,
    //     DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
    // ================================================================
    api.register_api("HttpSendRequestA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            std::cerr << "[vx] NET: HttpSendRequest\n";
            s_inet_read_first_call = true;
            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ================================================================
    // HttpSendRequestW (5 args, 20 bytes)
    // ================================================================
    api.register_api("HttpSendRequestW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            std::cerr << "[vx] NET: HttpSendRequest\n";
            s_inet_read_first_call = true;
            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ================================================================
    // InternetReadFile (4 args, 16 bytes)
    // BOOL InternetReadFile(HINTERNET hFile, LPVOID lpBuffer,
    //     DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
    // ================================================================
    api.register_api("InternetReadFile",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer             = vmem.read32(esp + 8);
            uint32_t lpdwNumberOfBytesRead = vmem.read32(esp + 16);

            if (s_inet_read_first_call) {
                // Return "OK" on first call
                if (lpBuffer) {
                    uint8_t ok_data[] = {'O', 'K'};
                    vmem.write(lpBuffer, ok_data, 2);
                }
                if (lpdwNumberOfBytesRead) {
                    vmem.write32(lpdwNumberOfBytesRead, 2);
                }
                s_inet_read_first_call = false;
            } else {
                // EOF on subsequent calls
                if (lpdwNumberOfBytesRead) {
                    vmem.write32(lpdwNumberOfBytesRead, 0);
                }
            }

            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // InternetOpenUrlA (6 args, 24 bytes)
    // HINTERNET InternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl,
    //     LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags,
    //     DWORD_PTR dwContext)
    // ================================================================
    api.register_api("InternetOpenUrlA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszUrl = vmem.read32(esp + 8);

            std::string url = lpszUrl ? read_guest_string(vmem, lpszUrl) : "";
            std::cerr << "[vx] NET: InternetOpenUrl " << url << "\n";

            s_inet_read_first_call = true;
            cpu.set_sp(cpu.sp() + 24);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // InternetOpenUrlW (6 args, 24 bytes)
    // ================================================================
    api.register_api("InternetOpenUrlW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpszUrl = vmem.read32(esp + 8);

            std::string url = lpszUrl ? read_guest_wstring(vmem, lpszUrl) : "";
            std::cerr << "[vx] NET: InternetOpenUrl " << url << "\n";

            s_inet_read_first_call = true;
            cpu.set_sp(cpu.sp() + 24);
            return s_inet_handle_counter++;
        });

    // ================================================================
    // InternetCloseHandle (1 arg, 4 bytes)
    // BOOL InternetCloseHandle(HINTERNET hInternet)
    // ================================================================
    api.register_api("InternetCloseHandle",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ================================================================
    // InternetQueryOptionA (4 args, 16 bytes)
    // BOOL InternetQueryOptionA(HINTERNET hInternet, DWORD dwOption,
    //     LPVOID lpBuffer, LPDWORD lpdwBufferLength)
    // ================================================================
    api.register_api("InternetQueryOptionA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0; // FALSE
        });

    // ================================================================
    // InternetQueryOptionW (4 args, 16 bytes)
    // ================================================================
    api.register_api("InternetQueryOptionW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0; // FALSE
        });

    // ================================================================
    // HttpQueryInfoA (5 args, 20 bytes)
    // BOOL HttpQueryInfoA(HINTERNET hRequest, DWORD dwInfoLevel,
    //     LPVOID lpBuffer, LPDWORD lpdwBufferLength, LPDWORD lpdwIndex)
    // ================================================================
    api.register_api("HttpQueryInfoA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer          = vmem.read32(esp + 12);
            uint32_t lpdwBufferLength  = vmem.read32(esp + 16);

            // Write "200" as status code string
            if (lpBuffer) {
                uint8_t status[] = {'2', '0', '0', 0};
                vmem.write(lpBuffer, status, 4);
            }
            if (lpdwBufferLength) {
                vmem.write32(lpdwBufferLength, 3);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ================================================================
    // HttpQueryInfoW (5 args, 20 bytes)
    // ================================================================
    api.register_api("HttpQueryInfoW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpBuffer          = vmem.read32(esp + 12);
            uint32_t lpdwBufferLength  = vmem.read32(esp + 16);

            // Write "200" as wide status code string
            if (lpBuffer) {
                uint16_t status[] = {'2', '0', '0', 0};
                vmem.write(lpBuffer, status, 8);
            }
            if (lpdwBufferLength) {
                vmem.write32(lpdwBufferLength, 6); // 3 wide chars = 6 bytes
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

} // register_wininet_apis

} // namespace vx
