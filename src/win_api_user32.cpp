/**
 * VXEngine user32.dll API Stubs
 *
 * Implements:
 *   - MessageBoxA/W, FindWindowA/W, GetDesktopWindow, GetForegroundWindow,
 *     GetSystemMetrics, SystemParametersInfoA/W, SetWindowsHookExA/W,
 *     UnhookWindowsHookEx, PostMessageA/W, SendMessageA/W,
 *     GetKeyboardLayout, LoadStringA/W, CharLowerA, CharUpperA,
 *     GetWindowTextA/W, IsWindow, ShowWindow, GetClientRect, GetCursorPos
 *
 * All handlers follow stdcall convention: the handler adjusts ESP to pop args,
 * then the dispatcher pops the return address and jumps back.
 */

#include "../include/vxengine/engine.h"
#include "../include/vxengine/memory.h"
#include "../include/vxengine/cpu/icpu.h"
#include <string>
#include <iostream>
#include <cctype>

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
// register_user32_apis
// ============================================================

void register_user32_apis(APIDispatcher& api) {

    // ================================================================
    // MessageBoxA (4 args, 16 bytes)
    // int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
    // ================================================================
    api.register_api("MessageBoxA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpText    = vmem.read32(esp + 8);
            uint32_t lpCaption = vmem.read32(esp + 12);

            std::string text    = lpText    ? read_guest_string(vmem, lpText)    : "";
            std::string caption = lpCaption ? read_guest_string(vmem, lpCaption) : "";
            std::cerr << "[vx] MessageBox: " << caption << " - " << text << "\n";

            cpu.set_sp(cpu.sp() + 16);
            return 1; // IDOK
        });

    // ================================================================
    // MessageBoxW (4 args, 16 bytes)
    // ================================================================
    api.register_api("MessageBoxW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpText    = vmem.read32(esp + 8);
            uint32_t lpCaption = vmem.read32(esp + 12);

            std::string text    = lpText    ? read_guest_wstring(vmem, lpText)    : "";
            std::string caption = lpCaption ? read_guest_wstring(vmem, lpCaption) : "";
            std::cerr << "[vx] MessageBox: " << caption << " - " << text << "\n";

            cpu.set_sp(cpu.sp() + 16);
            return 1; // IDOK
        });

    // ================================================================
    // FindWindowA (2 args, 8 bytes)
    // HWND FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
    // ================================================================
    api.register_api("FindWindowA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 0; // Not found (anti-debugger safe)
        });

    // ================================================================
    // FindWindowW (2 args, 8 bytes)
    // ================================================================
    api.register_api("FindWindowW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 0; // Not found
        });

    // ================================================================
    // GetDesktopWindow (0 args, 0 bytes)
    // HWND GetDesktopWindow(void)
    // ================================================================
    api.register_api("GetDesktopWindow",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            return 0x000D0001;
        });

    // ================================================================
    // GetForegroundWindow (0 args, 0 bytes)
    // HWND GetForegroundWindow(void)
    // ================================================================
    api.register_api("GetForegroundWindow",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            return 0x000D0002;
        });

    // ================================================================
    // GetSystemMetrics (1 arg, 4 bytes)
    // int GetSystemMetrics(int nIndex)
    // ================================================================
    api.register_api("GetSystemMetrics",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t nIndex = vmem.read32(esp + 4);

            uint32_t result = 0;
            switch (nIndex) {
                case 0:      result = 1920; break; // SM_CXSCREEN
                case 1:      result = 1080; break; // SM_CYSCREEN
                case 19:     result = 1;    break; // SM_MOUSEPRESENT
                case 63:     result = 1;    break; // SM_NETWORK
                case 0x1000: result = 0;    break; // SM_REMOTESESSION
                default:     result = 0;    break;
            }

            cpu.set_sp(cpu.sp() + 4);
            return result;
        });

    // ================================================================
    // SystemParametersInfoA (4 args, 16 bytes)
    // BOOL SystemParametersInfoA(UINT uiAction, UINT uiParam,
    //     PVOID pvParam, UINT fWinIni)
    // ================================================================
    api.register_api("SystemParametersInfoA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // SystemParametersInfoW (4 args, 16 bytes)
    // ================================================================
    api.register_api("SystemParametersInfoW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // SetWindowsHookExA (4 args, 16 bytes)
    // HHOOK SetWindowsHookExA(int idHook, HOOKPROC lpfn,
    //     HINSTANCE hmod, DWORD dwThreadId)
    // ================================================================
    api.register_api("SetWindowsHookExA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t idHook = vmem.read32(esp + 4);

            std::cerr << "[vx] SetWindowsHookEx: hook type " << idHook << "\n";

            cpu.set_sp(cpu.sp() + 16);
            return 0xAA00 + idHook; // Fake HHOOK
        });

    // ================================================================
    // SetWindowsHookExW (4 args, 16 bytes)
    // ================================================================
    api.register_api("SetWindowsHookExW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t idHook = vmem.read32(esp + 4);

            std::cerr << "[vx] SetWindowsHookEx: hook type " << idHook << "\n";

            cpu.set_sp(cpu.sp() + 16);
            return 0xAA00 + idHook;
        });

    // ================================================================
    // UnhookWindowsHookEx (1 arg, 4 bytes)
    // BOOL UnhookWindowsHookEx(HHOOK hhk)
    // ================================================================
    api.register_api("UnhookWindowsHookEx",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ================================================================
    // PostMessageA (4 args, 16 bytes)
    // BOOL PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
    // ================================================================
    api.register_api("PostMessageA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // PostMessageW (4 args, 16 bytes)
    // ================================================================
    api.register_api("PostMessageW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ================================================================
    // SendMessageA (4 args, 16 bytes)
    // LRESULT SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
    // ================================================================
    api.register_api("SendMessageA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0;
        });

    // ================================================================
    // SendMessageW (4 args, 16 bytes)
    // ================================================================
    api.register_api("SendMessageW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0;
        });

    // ================================================================
    // GetKeyboardLayout (1 arg, 4 bytes)
    // HKL GetKeyboardLayout(DWORD idThread)
    // ================================================================
    api.register_api("GetKeyboardLayout",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0x04090409; // English (US)
        });

    // ================================================================
    // LoadStringA (4 args, 16 bytes)
    // int LoadStringA(HINSTANCE hInstance, UINT uID,
    //     LPSTR lpBuffer, int cchBufferMax)
    // ================================================================
    api.register_api("LoadStringA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0;
        });

    // ================================================================
    // LoadStringW (4 args, 16 bytes)
    // ================================================================
    api.register_api("LoadStringW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 0;
        });

    // ================================================================
    // CharLowerA (1 arg, 4 bytes)
    // LPSTR CharLowerA(LPSTR lpsz)
    // ================================================================
    api.register_api("CharLowerA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpsz = vmem.read32(esp + 4);

            cpu.set_sp(cpu.sp() + 4);

            if (lpsz > 0xFFFF) {
                // Pointer to string: lowercase in-place
                for (size_t i = 0; i < 1024; ++i) {
                    uint8_t ch = 0;
                    vmem.read(lpsz + i, &ch, 1);
                    if (ch == 0) break;
                    if (ch >= 'A' && ch <= 'Z') {
                        ch = ch - 'A' + 'a';
                        vmem.write(lpsz + i, &ch, 1);
                    }
                }
                return lpsz;
            } else {
                // Single character in low word
                char ch = static_cast<char>(lpsz & 0xFF);
                return static_cast<uint64_t>(static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(ch))));
            }
        });

    // ================================================================
    // CharUpperA (1 arg, 4 bytes)
    // LPSTR CharUpperA(LPSTR lpsz)
    // ================================================================
    api.register_api("CharUpperA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpsz = vmem.read32(esp + 4);

            cpu.set_sp(cpu.sp() + 4);

            if (lpsz > 0xFFFF) {
                // Pointer to string: uppercase in-place
                for (size_t i = 0; i < 1024; ++i) {
                    uint8_t ch = 0;
                    vmem.read(lpsz + i, &ch, 1);
                    if (ch == 0) break;
                    if (ch >= 'a' && ch <= 'z') {
                        ch = ch - 'a' + 'A';
                        vmem.write(lpsz + i, &ch, 1);
                    }
                }
                return lpsz;
            } else {
                char ch = static_cast<char>(lpsz & 0xFF);
                return static_cast<uint64_t>(static_cast<uint8_t>(std::toupper(static_cast<unsigned char>(ch))));
            }
        });

    // ================================================================
    // GetWindowTextA (3 args, 12 bytes)
    // int GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount)
    // ================================================================
    api.register_api("GetWindowTextA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpString = vmem.read32(esp + 8);

            if (lpString) {
                uint8_t null_byte = 0;
                vmem.write(lpString, &null_byte, 1);
            }

            cpu.set_sp(cpu.sp() + 12);
            return 0;
        });

    // ================================================================
    // GetWindowTextW (3 args, 12 bytes)
    // ================================================================
    api.register_api("GetWindowTextW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpString = vmem.read32(esp + 8);

            if (lpString) {
                uint16_t null_wchar = 0;
                vmem.write(lpString, &null_wchar, 2);
            }

            cpu.set_sp(cpu.sp() + 12);
            return 0;
        });

    // ================================================================
    // IsWindow (1 arg, 4 bytes)
    // BOOL IsWindow(HWND hWnd)
    // ================================================================
    api.register_api("IsWindow",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0; // FALSE
        });

    // ================================================================
    // ShowWindow (2 args, 8 bytes)
    // BOOL ShowWindow(HWND hWnd, int nCmdShow)
    // ================================================================
    api.register_api("ShowWindow",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ================================================================
    // GetClientRect (2 args, 8 bytes)
    // BOOL GetClientRect(HWND hWnd, LPRECT lpRect)
    // ================================================================
    api.register_api("GetClientRect",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpRect = vmem.read32(esp + 8);

            if (lpRect) {
                // RECT { left, top, right, bottom } — each 4 bytes
                vmem.write32(lpRect + 0,  0);    // left
                vmem.write32(lpRect + 4,  0);    // top
                vmem.write32(lpRect + 8,  1920); // right
                vmem.write32(lpRect + 12, 1080); // bottom
            }

            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ================================================================
    // GetCursorPos (1 arg, 4 bytes)
    // BOOL GetCursorPos(LPPOINT lpPoint)
    // ================================================================
    api.register_api("GetCursorPos",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t lpPoint = vmem.read32(esp + 4);

            if (lpPoint) {
                // POINT { x, y } — each 4 bytes
                vmem.write32(lpPoint + 0, 500); // x
                vmem.write32(lpPoint + 4, 500); // y
            }

            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

} // register_user32_apis

} // namespace vx
