/**
 * VXEngine Extended Windows API Implementations
 *
 * Adds ~200 additional kernel32.dll APIs:
 *   - W (wide char) and Ex (extended) variants for all existing A functions
 *   - File I/O (CreateFile, ReadFile, WriteFile, FindFirstFile, etc.)
 *   - Process/Thread management
 *   - Extended memory (Heap, Global, Local, IsBadPtr)
 *   - Extended synchronization (Events, Semaphores, SRW, Interlocked)
 *   - Debug/Error (OutputDebugString, IsDebuggerPresent, FormatMessage)
 *   - String/Conversion (MultiByteToWideChar, lstr*, wsprintf*)
 *   - Environment (GetEnvironmentVariable, GetCommandLine, GetStdHandle)
 *   - Atom APIs
 *   - Misc (EncodePointer, FLS, GetVersion, GetComputerName, etc.)
 *
 * All handlers use the same register_native() pattern as win_api.cpp.
 * Wide (W) variants read UTF-16LE from memory, narrow to ASCII, delegate to A.
 */

#include "../include/vxengine/win_api.h"
#include "../include/vxengine/win_api_ntdll.h"
#include <algorithm>
#include <cstring>
#include <cctype>
#include <ctime>
#include <cstdio>
#include <cstdarg>

namespace vx {

// ============================================================
// Helpers
// ============================================================

/// Read a UTF-16LE string from virtual memory, narrow to ASCII
static std::string read_wide_string(VirtualMemory& vmem, uint64_t addr, size_t max = 2048) {
    std::string result;
    for (size_t i = 0; i < max; i++) {
        uint16_t wc = static_cast<uint16_t>(vmem.read32(addr + i * 2) & 0xFFFF);
        if (wc == 0) break;
        result.push_back(static_cast<char>(wc & 0xFF));
    }
    return result;
}

/// Write a narrow string as UTF-16LE into virtual memory
static void write_wide_string(VirtualMemory& vmem, uint64_t addr, const std::string& str) {
    for (size_t i = 0; i < str.size(); i++) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
        vmem.write(addr + i * 2, &wc, 2);
    }
    uint16_t null = 0;
    vmem.write(addr + str.size() * 2, &null, 2);
}

/// Wide string length in characters (not bytes)
static uint32_t wstrlen(VirtualMemory& vmem, uint64_t addr, size_t max = 0x10000) {
    for (size_t i = 0; i < max; i++) {
        uint16_t wc = static_cast<uint16_t>(vmem.read32(addr + i * 2) & 0xFFFF);
        if (wc == 0) return static_cast<uint32_t>(i);
    }
    return static_cast<uint32_t>(max);
}

// Fake handle constants
constexpr uint32_t FAKE_PROCESS_HANDLE  = 0xFFFFFFFF; // -1
constexpr uint32_t FAKE_THREAD_HANDLE   = 0xFFFFFFFE; // -2
constexpr uint32_t FAKE_STDIN_HANDLE    = 0x00000003;
constexpr uint32_t FAKE_STDOUT_HANDLE   = 0x00000007;
constexpr uint32_t FAKE_STDERR_HANDLE   = 0x0000000B;
constexpr uint32_t FAKE_HEAP_HANDLE     = 0x00050000;
constexpr uint32_t FAKE_PID             = 0x1000;
constexpr uint32_t FAKE_TID             = 0x1004;
constexpr uint32_t INVALID_HANDLE_VALUE = 0xFFFFFFFF;
constexpr uint32_t INVALID_FILE_ATTRS   = 0xFFFFFFFF;
constexpr uint32_t FILE_ATTRIBUTE_NORMAL = 0x80;
constexpr uint32_t FILE_ATTRIBUTE_DIRECTORY = 0x10;
constexpr uint32_t WAIT_OBJECT_0        = 0x00000000;
constexpr uint32_t WAIT_TIMEOUT         = 0x00000102;
constexpr uint32_t ERROR_NO_MORE_FILES  = 18;
constexpr uint32_t ERROR_FILE_NOT_FOUND = 2;
constexpr uint32_t ERROR_INSUFFICIENT_BUFFER = 122;

// Atom tracking
static uint16_t next_atom_ = 0xC000;
static std::map<uint16_t, std::string> atom_table_;
static std::map<std::string, uint16_t> atom_reverse_;

// FLS tracking (fiber-local storage, same as TLS in single-threaded)
static uint32_t next_fls_index_ = 0;
static std::map<uint32_t, uint32_t> fls_values_;

// Exception filter
static uint32_t unhandled_exception_filter_ = 0;

// Command line storage
static const char* fake_cmdline_a = "C:\\target.exe";
static const wchar_t* fake_cmdline_w = L"C:\\target.exe";

// ============================================================
// register_extended_apis — the main entry point
// ============================================================

void register_extended_apis(APIDispatcher& disp) {

    // ================================================================
    // MODULE APIs — W/Ex variants
    // ================================================================

    // ---- GetModuleHandleW(lpModuleName) ----
    disp.register_native("GetModuleHandleW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                      EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t name_ptr = vmem.read32(esp + 4);

        if (name_ptr == 0) {
            uint32_t image_base = vmem.read32(PEB_ADDRESS + 0x08);
            cpu.set_reg(X86_EAX, image_base);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4);
            cpu.set_pc(ret);
        } else {
            std::string name = read_wide_string(vmem, name_ptr, 256);
            // Write narrow name to temp buffer, call through GetModuleHandleA logic
            for (auto& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            uint32_t ldr_addr = vmem.read32(PEB_ADDRESS + 0x0C);
            uint32_t list_head = ldr_addr + 0x0C;
            uint32_t entry = vmem.read32(list_head);
            uint32_t result = 0;

            while (entry != list_head && entry != 0) {
                uint32_t name_buf = vmem.read32(entry + 0x30);
                uint16_t name_len = 0;
                vmem.read(entry + 0x2C, &name_len, 2);

                std::string mod_name;
                for (uint16_t i = 0; i < name_len / 2; ++i) {
                    uint16_t wc = 0;
                    vmem.read(name_buf + i * 2, &wc, 2);
                    mod_name += static_cast<char>(wc & 0xFF);
                }
                for (auto& c : mod_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

                if (mod_name == name || mod_name.find(name) != std::string::npos) {
                    result = vmem.read32(entry + 0x18);
                    break;
                }
                entry = vmem.read32(entry);
            }

            cpu.set_reg(X86_EAX, result);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4);
            cpu.set_pc(ret);
        }
        return 4;
    });

    // ---- GetModuleHandleExA(dwFlags, lpModuleName, phModule) ----
    disp.register_native("GetModuleHandleExA", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                        EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t flags    = vmem.read32(esp + 4);
        uint32_t name_ptr = vmem.read32(esp + 8);
        uint32_t out_ptr  = vmem.read32(esp + 12);

        uint32_t handle = 0;
        if (name_ptr == 0) {
            handle = vmem.read32(PEB_ADDRESS + 0x08);
        } else {
            // Simplified: return image base for any name
            handle = vmem.read32(PEB_ADDRESS + 0x08);
        }

        if (out_ptr != 0) vmem.write32(out_ptr, handle);

        cpu.set_reg(X86_EAX, handle != 0 ? 1u : 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- GetModuleHandleExW ----
    disp.register_native("GetModuleHandleExW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                        EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t flags    = vmem.read32(esp + 4);
        uint32_t name_ptr = vmem.read32(esp + 8);
        uint32_t out_ptr  = vmem.read32(esp + 12);

        uint32_t handle = vmem.read32(PEB_ADDRESS + 0x08);
        if (out_ptr != 0) vmem.write32(out_ptr, handle);

        cpu.set_reg(X86_EAX, 1);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- LoadLibraryW(lpLibFileName) ----
    disp.register_native("LoadLibraryW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t name_ptr = vmem.read32(esp + 4);
        // Return fake module handle
        static uint32_t fake_base_w = 0x75000000;
        uint32_t handle = fake_base_w;
        fake_base_w += 0x00100000;

        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- LoadLibraryExA(lpLibFileName, hFile, dwFlags) ----
    disp.register_native("LoadLibraryExA", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        static uint32_t fake_base_exa = 0x76000000;
        uint32_t handle = fake_base_exa;
        fake_base_exa += 0x00100000;

        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- LoadLibraryExW(lpLibFileName, hFile, dwFlags) ----
    disp.register_native("LoadLibraryExW", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        static uint32_t fake_base_exw = 0x77000000;
        uint32_t handle = fake_base_exw;
        fake_base_exw += 0x00100000;

        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- GetModuleFileNameW(hModule, lpFilename, nSize) ----
    disp.register_native("GetModuleFileNameW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t hModule  = vmem.read32(esp + 4);
        uint32_t buf      = vmem.read32(esp + 8);
        uint32_t buf_size = vmem.read32(esp + 12);

        std::string path = "C:\\target.exe";
        uint32_t copy_len = std::min(static_cast<uint32_t>(path.size()), buf_size - 1);
        write_wide_string(vmem, buf, path.substr(0, copy_len));

        cpu.set_reg(X86_EAX, copy_len);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- GetProcAddressForCaller(hModule, lpProcName, hCaller) ----
    disp.register_native("GetProcAddressForCaller", [](X86Backend& cpu, VirtualMemory& vmem,
                                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u); // Not found
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ================================================================
    // FILE I/O APIs
    // ================================================================

    // Helper lambda for stdcall return pattern used throughout
    auto make_stdcall = [](X86Backend& cpu, VirtualMemory& vmem,
                           uint32_t retval, uint32_t arg_bytes) {
        cpu.set_reg(X86_EAX, retval);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + arg_bytes);
        cpu.set_pc(ret);
    };

    // ---- CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurity, dwCreation, dwFlags, hTemplate) ----
    disp.register_native("CreateFileA", [](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        // Return a fake file handle
        static uint32_t next_file_handle = 0x200;
        uint32_t handle = next_file_handle++;

        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 28); // 7 args * 4
        cpu.set_pc(ret);
        return 28;
    });

    // ---- CreateFileW ----
    disp.register_native("CreateFileW", [](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        static uint32_t next_file_handle_w = 0x300;
        uint32_t handle = next_file_handle_w++;

        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 28);
        cpu.set_pc(ret);
        return 28;
    });

    // ---- ReadFile(hFile, lpBuffer, nBytesToRead, lpBytesRead, lpOverlapped) ----
    disp.register_native("ReadFile", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t bytes_read_ptr = vmem.read32(esp + 16);
        if (bytes_read_ptr != 0) vmem.write32(bytes_read_ptr, 0);

        cpu.set_reg(X86_EAX, 1u); // TRUE (success, 0 bytes read = EOF)
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20);
        cpu.set_pc(ret);
        return 20;
    });

    // ---- WriteFile(hFile, lpBuffer, nBytesToWrite, lpBytesWritten, lpOverlapped) ----
    disp.register_native("WriteFile", [](X86Backend& cpu, VirtualMemory& vmem,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t bytes_to_write = vmem.read32(esp + 12);
        uint32_t bytes_written_ptr = vmem.read32(esp + 16);
        if (bytes_written_ptr != 0) vmem.write32(bytes_written_ptr, bytes_to_write);

        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20);
        cpu.set_pc(ret);
        return 20;
    });

    // ---- SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod) ----
    disp.register_native("SetFilePointer", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t distance = vmem.read32(esp + 8);
        cpu.set_reg(X86_EAX, distance); // Return new position (simplified)
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    // ---- SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod) ----
    disp.register_native("SetFilePointerEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20); // hFile + LARGE_INTEGER(8) + ptr + method
        cpu.set_pc(ret);
        return 20;
    });

    // ---- GetFileSize(hFile, lpFileSizeHigh) ----
    disp.register_native("GetFileSize", [](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t high_ptr = vmem.read32(esp + 8);
        if (high_ptr != 0) vmem.write32(high_ptr, 0);
        cpu.set_reg(X86_EAX, 0u); // File size 0
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetFileSizeEx(hFile, lpFileSize) ----
    disp.register_native("GetFileSizeEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t size_ptr = vmem.read32(esp + 8);
        if (size_ptr != 0) {
            vmem.write32(size_ptr, 0);
            vmem.write32(size_ptr + 4, 0);
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- FindFirstFileA(lpFileName, lpFindFileData) ----
    disp.register_native("FindFirstFileA", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        disp.set_last_error(ERROR_FILE_NOT_FOUND);
        cpu.set_reg(X86_EAX, INVALID_HANDLE_VALUE);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- FindFirstFileW ----
    disp.register_native("FindFirstFileW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        disp.set_last_error(ERROR_FILE_NOT_FOUND);
        cpu.set_reg(X86_EAX, INVALID_HANDLE_VALUE);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- FindNextFileA/W ----
    disp.register_native("FindNextFileA", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        disp.set_last_error(ERROR_NO_MORE_FILES);
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("FindNextFileW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        disp.set_last_error(ERROR_NO_MORE_FILES);
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- FindClose(hFindFile) ----
    disp.register_native("FindClose", [](X86Backend& cpu, VirtualMemory& vmem,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetFileAttributesA/W ----
    disp.register_native("GetFileAttributesA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, INVALID_FILE_ATTRS);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("GetFileAttributesW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, INVALID_FILE_ATTRS);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetFileAttributesExA/W(lpFileName, fInfoLevelId, lpFileInfo) ----
    disp.register_native("GetFileAttributesExA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u); // Failure
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });
    disp.register_native("GetFileAttributesExW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- CreateDirectoryA/W(lpPathName, lpSecurityAttributes) ----
    disp.register_native("CreateDirectoryA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("CreateDirectoryW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetCurrentDirectoryA/W(nBufferLength, lpBuffer) ----
    disp.register_native("GetCurrentDirectoryA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf_len = vmem.read32(esp + 4);
        uint32_t buf     = vmem.read32(esp + 8);
        std::string cwd = "C:\\";
        if (buf != 0 && buf_len > cwd.size()) {
            vmem.write_string(buf, cwd);
        }
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(cwd.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("GetCurrentDirectoryW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf_len = vmem.read32(esp + 4);
        uint32_t buf     = vmem.read32(esp + 8);
        std::string cwd = "C:\\";
        if (buf != 0 && buf_len > cwd.size()) {
            write_wide_string(vmem, buf, cwd);
        }
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(cwd.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- SetCurrentDirectoryA/W(lpPathName) ----
    disp.register_native("SetCurrentDirectoryA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("SetCurrentDirectoryW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetTempPathA/W(nBufferLength, lpBuffer) ----
    disp.register_native("GetTempPathA", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf_len = vmem.read32(esp + 4);
        uint32_t buf     = vmem.read32(esp + 8);
        std::string tmp = "C:\\Temp\\";
        if (buf != 0 && buf_len > tmp.size()) vmem.write_string(buf, tmp);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(tmp.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("GetTempPathW", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf_len = vmem.read32(esp + 4);
        uint32_t buf     = vmem.read32(esp + 8);
        std::string tmp = "C:\\Temp\\";
        if (buf != 0 && buf_len > tmp.size()) write_wide_string(vmem, buf, tmp);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(tmp.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetSystemDirectoryA/W(lpBuffer, uSize) ----
    disp.register_native("GetSystemDirectoryA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf  = vmem.read32(esp + 4);
        uint32_t size = vmem.read32(esp + 8);
        std::string dir = "C:\\Windows\\System32";
        if (buf != 0 && size > dir.size()) vmem.write_string(buf, dir);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(dir.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("GetSystemDirectoryW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf  = vmem.read32(esp + 4);
        uint32_t size = vmem.read32(esp + 8);
        std::string dir = "C:\\Windows\\System32";
        if (buf != 0 && size > dir.size()) write_wide_string(vmem, buf, dir);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(dir.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetWindowsDirectoryA/W(lpBuffer, uSize) ----
    disp.register_native("GetWindowsDirectoryA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf  = vmem.read32(esp + 4);
        uint32_t size = vmem.read32(esp + 8);
        std::string dir = "C:\\Windows";
        if (buf != 0 && size > dir.size()) vmem.write_string(buf, dir);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(dir.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("GetWindowsDirectoryW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf  = vmem.read32(esp + 4);
        uint32_t size = vmem.read32(esp + 8);
        std::string dir = "C:\\Windows";
        if (buf != 0 && size > dir.size()) write_wide_string(vmem, buf, dir);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(dir.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ================================================================
    // PROCESS / THREAD APIs
    // ================================================================

    // ---- GetCurrentProcess() ----
    disp.register_native("GetCurrentProcess", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, FAKE_PROCESS_HANDLE);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetCurrentProcessId() ----
    disp.register_native("GetCurrentProcessId", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, FAKE_PID);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetCurrentThread() ----
    disp.register_native("GetCurrentThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, FAKE_THREAD_HANDLE);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- CreateThread(lpAttr, dwStackSize, lpStartAddr, lpParam, dwFlags, lpThreadId) ----
    disp.register_native("CreateThread", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t tid_ptr = vmem.read32(esp + 24);
        uint32_t handle = disp.alloc_handle();
        if (tid_ptr != 0) vmem.write32(tid_ptr, FAKE_TID + 1);
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 24);
        cpu.set_pc(ret);
        return 24;
    });

    // ---- ExitThread(dwExitCode) ----
    disp.register_native("ExitThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                          EmulatedHeap&) -> uint32_t {
        // Halt emulation
        cpu.set_pc(0xDEADDEAD);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_sp(esp + 4 + 4);
        return 4;
    });

    // ---- TerminateThread(hThread, dwExitCode) ----
    disp.register_native("TerminateThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetExitCodeThread(hThread, lpExitCode) ----
    disp.register_native("GetExitCodeThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                                 EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t exit_ptr = vmem.read32(esp + 8);
        if (exit_ptr != 0) vmem.write32(exit_ptr, 0);
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- SuspendThread / ResumeThread (hThread) ----
    disp.register_native("SuspendThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u); // Previous suspend count
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("ResumeThread", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- WaitForMultipleObjects(nCount, lpHandles, bWaitAll, dwMilliseconds) ----
    disp.register_native("WaitForMultipleObjects", [](X86Backend& cpu, VirtualMemory& vmem,
                                                      EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, WAIT_OBJECT_0);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    // ---- WaitForSingleObject(hHandle, dwMilliseconds) ----
    // May already exist, register to be safe (duplicate registration overwrites)
    disp.register_native("WaitForSingleObject", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, WAIT_OBJECT_0);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- WaitForSingleObjectEx / WaitForMultipleObjectsEx ----
    disp.register_native("WaitForSingleObjectEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                                     EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, WAIT_OBJECT_0);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12); // hHandle, dwMilliseconds, bAlertable
        cpu.set_pc(ret);
        return 12;
    });
    disp.register_native("WaitForMultipleObjectsEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, WAIT_OBJECT_0);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20); // nCount, lpHandles, bWaitAll, dwMs, bAlertable
        cpu.set_pc(ret);
        return 20;
    });

    // ---- SignalObjectAndWait(hSignal, hWait, dwMs, bAlertable) ----
    disp.register_native("SignalObjectAndWait", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, WAIT_OBJECT_0);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    // ---- GetProcessHeap() ----
    disp.register_native("GetProcessHeap", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, FAKE_HEAP_HANDLE);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- IsProcessorFeaturePresent(ProcessorFeature) ----
    disp.register_native("IsProcessorFeaturePresent", [](X86Backend& cpu, VirtualMemory& vmem,
                                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t feature = vmem.read32(esp + 4);
        // PF_XMMI_INSTRUCTIONS_AVAILABLE (6) = SSE
        // PF_XMMI64_INSTRUCTIONS_AVAILABLE (10) = SSE2
        uint32_t result = (feature == 6 || feature == 10) ? 1u : 0u;
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetSystemInfo / GetNativeSystemInfo(lpSystemInfo) ----
    auto system_info_handler = [](X86Backend& cpu, VirtualMemory& vmem,
                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf = vmem.read32(esp + 4);
        // SYSTEM_INFO structure (36 bytes)
        vmem.memset(buf, 0, 36);
        vmem.write32(buf + 0, 0);          // wProcessorArchitecture = x86
        vmem.write32(buf + 4, 0x1000);     // dwPageSize = 4096
        vmem.write32(buf + 8, 0x00010000); // lpMinimumApplicationAddress
        vmem.write32(buf + 12, 0x7FFEFFFF);// lpMaximumApplicationAddress
        vmem.write32(buf + 16, 0x0F);      // dwActiveProcessorMask
        vmem.write32(buf + 20, 4);         // dwNumberOfProcessors
        vmem.write32(buf + 24, 586);       // dwProcessorType = PROCESSOR_INTEL_PENTIUM
        vmem.write32(buf + 28, 0x10000);   // dwAllocationGranularity
        // wProcessorLevel=6, wProcessorRevision=0x3C03
        vmem.write32(buf + 32, 0x3C030006);
        cpu.set_reg(X86_EAX, 0u); // void return
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GetSystemInfo", system_info_handler);
    disp.register_native("GetNativeSystemInfo", system_info_handler);

    // ---- QueryPerformanceCounter(lpPerformanceCount) ----
    disp.register_native("QueryPerformanceCounter", [](X86Backend& cpu, VirtualMemory& vmem,
                                                       EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        static uint64_t perf_counter = 1000000;
        perf_counter += 1000;
        if (ptr != 0) {
            vmem.write32(ptr, static_cast<uint32_t>(perf_counter & 0xFFFFFFFF));
            vmem.write32(ptr + 4, static_cast<uint32_t>(perf_counter >> 32));
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- QueryPerformanceFrequency(lpFrequency) ----
    disp.register_native("QueryPerformanceFrequency", [](X86Backend& cpu, VirtualMemory& vmem,
                                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        uint64_t freq = 10000000; // 10 MHz
        if (ptr != 0) {
            vmem.write32(ptr, static_cast<uint32_t>(freq & 0xFFFFFFFF));
            vmem.write32(ptr + 4, static_cast<uint32_t>(freq >> 32));
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetSystemTimeAsFileTime(lpSystemTimeAsFileTime) ----
    disp.register_native("GetSystemTimeAsFileTime", [](X86Backend& cpu, VirtualMemory& vmem,
                                                       EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        // Fake FILETIME: Jan 1 2023 00:00:00 UTC = 133155264000000000
        uint64_t ft = 133155264000000000ULL;
        if (ptr != 0) {
            vmem.write32(ptr, static_cast<uint32_t>(ft & 0xFFFFFFFF));
            vmem.write32(ptr + 4, static_cast<uint32_t>(ft >> 32));
        }
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetLocalTime / GetSystemTime(lpSystemTime) ----
    auto systemtime_handler = [](X86Backend& cpu, VirtualMemory& vmem,
                                 EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        // SYSTEMTIME: 16 bytes (8 x uint16_t)
        if (ptr != 0) {
            vmem.memset(ptr, 0, 16);
            uint16_t vals[] = {2023, 1, 0, 1, 12, 0, 0, 0}; // 2023-01-01 12:00:00.000 Sun
            vmem.write(ptr, vals, 16);
        }
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GetLocalTime", systemtime_handler);
    disp.register_native("GetSystemTime", systemtime_handler);

    // ---- FileTimeToSystemTime / SystemTimeToFileTime ----
    disp.register_native("FileTimeToSystemTime", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t st_ptr = vmem.read32(esp + 8);
        if (st_ptr != 0) {
            vmem.memset(st_ptr, 0, 16);
            uint16_t vals[] = {2023, 1, 0, 1, 0, 0, 0, 0};
            vmem.write(st_ptr, vals, 16);
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("SystemTimeToFileTime", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ft_ptr = vmem.read32(esp + 8);
        if (ft_ptr != 0) {
            uint64_t ft = 133155264000000000ULL;
            vmem.write32(ft_ptr, static_cast<uint32_t>(ft & 0xFFFFFFFF));
            vmem.write32(ft_ptr + 4, static_cast<uint32_t>(ft >> 32));
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ================================================================
    // MEMORY EXTENDED
    // ================================================================

    // ---- HeapCreate(flOptions, dwInitialSize, dwMaximumSize) ----
    disp.register_native("HeapCreate", [](X86Backend& cpu, VirtualMemory& vmem,
                                          EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        static uint32_t next_heap = FAKE_HEAP_HANDLE + 0x10000;
        uint32_t handle = next_heap;
        next_heap += 0x10000;
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- HeapDestroy(hHeap) ----
    disp.register_native("HeapDestroy", [](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- HeapSize(hHeap, dwFlags, lpMem) ----
    disp.register_native("HeapSize", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        // Return a non-zero size (simplified)
        cpu.set_reg(X86_EAX, 0x100u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- HeapValidate(hHeap, dwFlags, lpMem) ----
    disp.register_native("HeapValidate", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u); // Valid
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- HeapWalk(hHeap, lpEntry) ----
    disp.register_native("HeapWalk", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u); // No more entries
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- Global/Local memory family ----
    // GlobalAlloc / LocalAlloc: (uFlags, dwBytes)
    auto galloc = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t flags = vmem.read32(esp + 4);
        uint32_t size  = vmem.read32(esp + 8);
        uint32_t addr = heap.alloc(size ? size : 1);
        if (addr != 0 && (flags & 0x40)) vmem.memset(addr, 0, size); // GMEM_ZEROINIT
        cpu.set_reg(X86_EAX, addr);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    };
    disp.register_native("GlobalAlloc", galloc);
    disp.register_native("LocalAlloc", galloc);

    // GlobalFree / LocalFree: (hMem)
    auto gfree = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        if (ptr != 0) heap.free(ptr);
        cpu.set_reg(X86_EAX, 0u); // NULL on success
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GlobalFree", gfree);
    disp.register_native("LocalFree", gfree);

    // GlobalLock / LocalLock: (hMem) -> pointer (identity for fixed allocs)
    auto glock = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        cpu.set_reg(X86_EAX, ptr); // Fixed memory: lock returns same pointer
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GlobalLock", glock);
    disp.register_native("LocalLock", glock);

    // GlobalUnlock / LocalUnlock: (hMem) -> BOOL
    auto gunlock = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GlobalUnlock", gunlock);
    disp.register_native("LocalUnlock", gunlock);

    // GlobalReAlloc / LocalReAlloc: (hMem, dwBytes, uFlags)
    auto grealloc = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap& heap) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr  = vmem.read32(esp + 4);
        uint32_t size = vmem.read32(esp + 8);
        uint32_t addr = heap.realloc(ptr, size);
        cpu.set_reg(X86_EAX, addr);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    };
    disp.register_native("GlobalReAlloc", grealloc);
    disp.register_native("LocalReAlloc", grealloc);

    // GlobalSize / LocalSize: (hMem) -> SIZE_T
    auto gsize = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0x100u); // Simplified
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("GlobalSize", gsize);
    disp.register_native("LocalSize", gsize);

    // ---- IsBadReadPtr(lp, ucb) / IsBadWritePtr(lp, ucb) ----
    disp.register_native("IsBadReadPtr", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        uint32_t result = vmem.is_mapped(ptr) ? 0u : 1u;
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("IsBadWritePtr", [](X86Backend& cpu, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        uint32_t result = vmem.is_mapped(ptr) ? 0u : 1u;
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- VirtualAllocEx / VirtualProtectEx / VirtualQueryEx / VirtualFreeEx ----
    // These take an extra hProcess as first arg, which we ignore
    disp.register_native("VirtualAllocEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t addr    = vmem.read32(esp + 8);  // skip hProcess
        uint32_t size    = vmem.read32(esp + 12);
        uint32_t type    = vmem.read32(esp + 16);
        uint32_t protect = vmem.read32(esp + 20);

        uint8_t perms = PERM_RW;
        if (protect & PAGE_EXECUTE_READWRITE) perms = PERM_RWX;
        else if (protect & PAGE_EXECUTE_READ) perms = PERM_RX;
        else if (protect & PAGE_READWRITE) perms = PERM_RW;
        else if (protect & PAGE_READONLY) perms = PERM_READ;

        uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
        if (aligned == 0) aligned = PAGE_SIZE;

        if (addr == 0) {
            static uint32_t va_ex_ptr = 0x31000000;
            addr = va_ex_ptr;
            va_ex_ptr += static_cast<uint32_t>(aligned);
        }
        vmem.map(addr, aligned, perms);
        vmem.memset(addr, 0, static_cast<size_t>(aligned));

        cpu.set_reg(X86_EAX, addr);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20);
        cpu.set_pc(ret);
        return 20;
    });

    disp.register_native("VirtualProtectEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t old_prot_p = vmem.read32(esp + 20);
        if (old_prot_p != 0) vmem.write32(old_prot_p, PAGE_READWRITE);
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20);
        cpu.set_pc(ret);
        return 20;
    });

    disp.register_native("VirtualQueryEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t addr   = vmem.read32(esp + 8);
        uint32_t buf    = vmem.read32(esp + 12);
        uint32_t length = vmem.read32(esp + 16);

        MEMORY_BASIC_INFORMATION32 mbi = {};
        uint32_t page_addr = addr & static_cast<uint32_t>(PAGE_MASK);
        if (vmem.is_mapped(addr)) {
            mbi.BaseAddress = page_addr;
            mbi.AllocationBase = page_addr;
            mbi.AllocationProtect = PAGE_READWRITE;
            mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
            mbi.State = MEM_COMMIT;
            mbi.Protect = PAGE_READWRITE;
            mbi.Type = 0x20000;
        } else {
            mbi.BaseAddress = page_addr;
            mbi.RegionSize = static_cast<uint32_t>(PAGE_SIZE);
            mbi.State = MEM_FREE;
            mbi.Protect = PAGE_NOACCESS;
        }
        uint32_t ws = std::min(length, static_cast<uint32_t>(sizeof(mbi)));
        vmem.write(buf, &mbi, ws);

        cpu.set_reg(X86_EAX, ws);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    disp.register_native("VirtualFreeEx", [](X86Backend& cpu, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    // ================================================================
    // SYNCHRONIZATION EXTENDED
    // ================================================================

    // ---- CreateEventA/W(lpAttr, bManualReset, bInitialState, lpName) ----
    auto create_event = [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t handle = disp.alloc_handle();
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    };
    disp.register_native("CreateEventA", create_event);
    disp.register_native("CreateEventW", create_event);

    // ---- SetEvent / ResetEvent / PulseEvent (hEvent) ----
    auto event_op = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("SetEvent", event_op);
    disp.register_native("ResetEvent", event_op);
    disp.register_native("PulseEvent", event_op);

    // ---- CreateSemaphoreA/W(lpAttr, lInitialCount, lMaximumCount, lpName) ----
    auto create_semaphore = [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t handle = disp.alloc_handle();
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    };
    disp.register_native("CreateSemaphoreA", create_semaphore);
    disp.register_native("CreateSemaphoreW", create_semaphore);

    // ---- ReleaseSemaphore(hSemaphore, lReleaseCount, lpPreviousCount) ----
    disp.register_native("ReleaseSemaphore", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t prev_ptr = vmem.read32(esp + 12);
        if (prev_ptr != 0) vmem.write32(prev_ptr, 0);
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- CreateMutexW(lpAttr, bInitialOwner, lpName) ----
    disp.register_native("CreateMutexW", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t handle = disp.alloc_handle();
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ---- CreateMutexExA/W(lpAttr, lpName, dwFlags, dwDesiredAccess) ----
    auto create_mutex_ex = [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t handle = disp.alloc_handle();
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    };
    disp.register_native("CreateMutexExA", create_mutex_ex);
    disp.register_native("CreateMutexExW", create_mutex_ex);

    // ---- InitializeCriticalSectionAndSpinCount(lpCS, dwSpinCount) ----
    disp.register_native("InitializeCriticalSectionAndSpinCount",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs_ptr = vmem.read32(esp + 4);
            CRITICAL_SECTION32 cs = {};
            cs.LockCount = static_cast<uint32_t>(-1);
            vmem.write(cs_ptr, &cs, sizeof(cs));
            cpu.set_reg(X86_EAX, 1u);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 8);
            cpu.set_pc(ret);
            return 8;
        });

    // ---- InitializeCriticalSectionEx(lpCS, dwSpinCount, Flags) ----
    disp.register_native("InitializeCriticalSectionEx",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs_ptr = vmem.read32(esp + 4);
            CRITICAL_SECTION32 cs = {};
            cs.LockCount = static_cast<uint32_t>(-1);
            vmem.write(cs_ptr, &cs, sizeof(cs));
            cpu.set_reg(X86_EAX, 1u);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 12);
            cpu.set_pc(ret);
            return 12;
        });

    // ---- TryEnterCriticalSection(lpCS) ----
    disp.register_native("TryEnterCriticalSection",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t cs_ptr = vmem.read32(esp + 4);
            uint32_t rc = vmem.read32(cs_ptr + 8);
            vmem.write32(cs_ptr + 8, rc + 1);
            vmem.write32(cs_ptr + 12, FAKE_TID);
            cpu.set_reg(X86_EAX, 1u); // Always succeed in single-threaded
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4);
            cpu.set_pc(ret);
            return 4;
        });

    // ---- Interlocked operations ----
    // InterlockedExchange(Target, Value)
    disp.register_native("InterlockedExchange", [](X86Backend& cpu, VirtualMemory& vmem,
                                                   EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        uint32_t val = vmem.read32(esp + 8);
        uint32_t old = vmem.read32(ptr);
        vmem.write32(ptr, val);
        cpu.set_reg(X86_EAX, old);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // InterlockedCompareExchange(Destination, Exchange, Comperand)
    disp.register_native("InterlockedCompareExchange",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ptr      = vmem.read32(esp + 4);
            uint32_t exchange = vmem.read32(esp + 8);
            uint32_t comperand= vmem.read32(esp + 12);
            uint32_t old = vmem.read32(ptr);
            if (old == comperand) vmem.write32(ptr, exchange);
            cpu.set_reg(X86_EAX, old);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 12);
            cpu.set_pc(ret);
            return 12;
        });

    // InterlockedExchangeAdd(Addend, Value)
    disp.register_native("InterlockedExchangeAdd",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t ptr = vmem.read32(esp + 4);
            uint32_t val = vmem.read32(esp + 8);
            uint32_t old = vmem.read32(ptr);
            vmem.write32(ptr, old + val);
            cpu.set_reg(X86_EAX, old);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 8);
            cpu.set_pc(ret);
            return 8;
        });

    // ================================================================
    // ERROR / DEBUG APIs
    // ================================================================

    // ---- OutputDebugStringA(lpOutputString) ----
    disp.register_native("OutputDebugStringA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        // Could log: vmem.read_string(vmem.read32(esp + 4));
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("OutputDebugStringW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- IsDebuggerPresent() — anti-debug: return 0 ----
    disp.register_native("IsDebuggerPresent", [](X86Backend& cpu, VirtualMemory& vmem,
                                                 EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, 0u); // Not being debugged
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent) ----
    disp.register_native("CheckRemoteDebuggerPresent",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t out_ptr = vmem.read32(esp + 8);
            if (out_ptr != 0) vmem.write32(out_ptr, 0); // FALSE — no debugger
            cpu.set_reg(X86_EAX, 1u); // Success
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 8);
            cpu.set_pc(ret);
            return 8;
        });

    // ---- SetUnhandledExceptionFilter(lpTopLevelExceptionFilter) ----
    disp.register_native("SetUnhandledExceptionFilter",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t new_filter = vmem.read32(esp + 4);
            uint32_t old_filter = unhandled_exception_filter_;
            unhandled_exception_filter_ = new_filter;
            cpu.set_reg(X86_EAX, old_filter);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 4);
            cpu.set_pc(ret);
            return 4;
        });

    // ---- RaiseException(dwExceptionCode, dwFlags, nArgs, lpArguments) ----
    disp.register_native("RaiseException", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        // In emulation: just continue (caller may have set up SEH)
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 16);
        cpu.set_pc(ret);
        return 16;
    });

    // ---- FormatMessageA/W — stub: return 0 (no message) ----
    disp.register_native("FormatMessageA", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 28); // 7 args
        cpu.set_pc(ret);
        return 28;
    });
    disp.register_native("FormatMessageW", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 28);
        cpu.set_pc(ret);
        return 28;
    });

    // ================================================================
    // STRING / CONVERSION APIs
    // ================================================================

    // ---- MultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar) ----
    disp.register_native("MultiByteToWideChar",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t mb_str   = vmem.read32(esp + 12);
            int32_t  mb_count = static_cast<int32_t>(vmem.read32(esp + 16));
            uint32_t wc_str   = vmem.read32(esp + 20);
            uint32_t wc_count = vmem.read32(esp + 24);

            std::string src = (mb_count == -1)
                ? vmem.read_string(mb_str, 4096)
                : vmem.read_string(mb_str, static_cast<size_t>(mb_count));
            if (mb_count == -1) mb_count = static_cast<int32_t>(src.size() + 1);

            uint32_t needed = static_cast<uint32_t>(mb_count);
            if (wc_str == 0 || wc_count == 0) {
                // Query mode: return required size
                cpu.set_reg(X86_EAX, needed);
            } else {
                uint32_t to_copy = std::min(needed, wc_count);
                for (uint32_t i = 0; i < to_copy && i < src.size(); i++) {
                    uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(src[i]));
                    vmem.write(wc_str + i * 2, &wc, 2);
                }
                if (mb_count == static_cast<int32_t>(src.size() + 1) && to_copy <= wc_count) {
                    uint16_t null = 0;
                    vmem.write(wc_str + src.size() * 2, &null, 2);
                }
                cpu.set_reg(X86_EAX, to_copy);
            }
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 24);
            cpu.set_pc(ret);
            return 24;
        });

    // ---- WideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar) ----
    disp.register_native("WideCharToMultiByte",
        [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t wc_str   = vmem.read32(esp + 12);
            int32_t  wc_count = static_cast<int32_t>(vmem.read32(esp + 16));
            uint32_t mb_str   = vmem.read32(esp + 20);
            uint32_t mb_count = vmem.read32(esp + 24);

            std::string src;
            if (wc_count == -1) {
                src = read_wide_string(vmem, wc_str, 4096);
                wc_count = static_cast<int32_t>(src.size() + 1);
            } else {
                src = read_wide_string(vmem, wc_str, static_cast<size_t>(wc_count));
            }

            uint32_t needed = static_cast<uint32_t>(wc_count);
            if (mb_str == 0 || mb_count == 0) {
                cpu.set_reg(X86_EAX, needed);
            } else {
                uint32_t to_copy = std::min(needed, mb_count);
                for (uint32_t i = 0; i < to_copy && i < src.size(); i++) {
                    uint8_t c = static_cast<uint8_t>(src[i]);
                    vmem.write(mb_str + i, &c, 1);
                }
                if (wc_count == static_cast<int32_t>(src.size() + 1) && to_copy <= mb_count) {
                    uint8_t null = 0;
                    vmem.write(mb_str + src.size(), &null, 1);
                }
                cpu.set_reg(X86_EAX, to_copy);
            }
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 32);
            cpu.set_pc(ret);
            return 32;
        });

    // ---- lstrlenA(lpString) ----
    disp.register_native("lstrlenA", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        uint32_t len = (str != 0) ? static_cast<uint32_t>(vmem.read_string(str, 0x10000).size()) : 0;
        cpu.set_reg(X86_EAX, len);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- lstrlenW(lpString) ----
    disp.register_native("lstrlenW", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        uint32_t len = (str != 0) ? wstrlen(vmem, str) : 0;
        cpu.set_reg(X86_EAX, len);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- lstrcpyA(lpString1, lpString2) ----
    disp.register_native("lstrcpyA", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t dst = vmem.read32(esp + 4);
        uint32_t src = vmem.read32(esp + 8);
        std::string s = vmem.read_string(src, 0x10000);
        vmem.write_string(dst, s);
        cpu.set_reg(X86_EAX, dst);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- lstrcpyW(lpString1, lpString2) ----
    disp.register_native("lstrcpyW", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t dst = vmem.read32(esp + 4);
        uint32_t src = vmem.read32(esp + 8);
        std::string s = read_wide_string(vmem, src);
        write_wide_string(vmem, dst, s);
        cpu.set_reg(X86_EAX, dst);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- lstrcmpA / lstrcmpW ----
    disp.register_native("lstrcmpA", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string a = vmem.read_string(vmem.read32(esp + 4), 0x10000);
        std::string b = vmem.read_string(vmem.read32(esp + 8), 0x10000);
        int r = a.compare(b);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(r < 0 ? -1 : (r > 0 ? 1 : 0)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("lstrcmpW", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string a = read_wide_string(vmem, vmem.read32(esp + 4));
        std::string b = read_wide_string(vmem, vmem.read32(esp + 8));
        int r = a.compare(b);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(r < 0 ? -1 : (r > 0 ? 1 : 0)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- lstrcmpiA / lstrcmpiW (case-insensitive) ----
    disp.register_native("lstrcmpiA", [](X86Backend& cpu, VirtualMemory& vmem,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string a = vmem.read_string(vmem.read32(esp + 4), 0x10000);
        std::string b = vmem.read_string(vmem.read32(esp + 8), 0x10000);
        for (auto& c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (auto& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        int r = a.compare(b);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(r < 0 ? -1 : (r > 0 ? 1 : 0)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("lstrcmpiW", [](X86Backend& cpu, VirtualMemory& vmem,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string a = read_wide_string(vmem, vmem.read32(esp + 4));
        std::string b = read_wide_string(vmem, vmem.read32(esp + 8));
        for (auto& c : a) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (auto& c : b) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        int r = a.compare(b);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(r < 0 ? -1 : (r > 0 ? 1 : 0)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- wsprintfA/W, wvsprintfA/W — simplified: copy format string ----
    auto wsprintf_stub_a = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf = vmem.read32(esp + 4);
        uint32_t fmt = vmem.read32(esp + 8);
        std::string fmtstr = vmem.read_string(fmt, 0x1000);
        vmem.write_string(buf, fmtstr);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(fmtstr.size()));
        // cdecl: caller cleans
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    };
    disp.register_native("wsprintfA", wsprintf_stub_a);
    disp.register_native("wvsprintfA", wsprintf_stub_a);

    auto wsprintf_stub_w = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf = vmem.read32(esp + 4);
        uint32_t fmt = vmem.read32(esp + 8);
        std::string fmtstr = read_wide_string(vmem, fmt, 0x800);
        write_wide_string(vmem, buf, fmtstr);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(fmtstr.size()));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    };
    disp.register_native("wsprintfW", wsprintf_stub_w);
    disp.register_native("wvsprintfW", wsprintf_stub_w);

    // ---- CompareStringA/W(Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2) ----
    disp.register_native("CompareStringA", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t s1_ptr = vmem.read32(esp + 12);
        int32_t  s1_len = static_cast<int32_t>(vmem.read32(esp + 16));
        uint32_t s2_ptr = vmem.read32(esp + 20);
        int32_t  s2_len = static_cast<int32_t>(vmem.read32(esp + 24));
        std::string s1 = vmem.read_string(s1_ptr, s1_len == -1 ? 4096 : s1_len);
        std::string s2 = vmem.read_string(s2_ptr, s2_len == -1 ? 4096 : s2_len);
        int cmp = s1.compare(s2);
        // CSTR_LESS_THAN=1, CSTR_EQUAL=2, CSTR_GREATER_THAN=3
        uint32_t result = (cmp < 0) ? 1 : ((cmp > 0) ? 3 : 2);
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 24);
        cpu.set_pc(ret);
        return 24;
    });
    disp.register_native("CompareStringW", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t s1_ptr = vmem.read32(esp + 12);
        int32_t  s1_len = static_cast<int32_t>(vmem.read32(esp + 16));
        uint32_t s2_ptr = vmem.read32(esp + 20);
        int32_t  s2_len = static_cast<int32_t>(vmem.read32(esp + 24));
        std::string s1 = read_wide_string(vmem, s1_ptr, s1_len == -1 ? 4096 : s1_len);
        std::string s2 = read_wide_string(vmem, s2_ptr, s2_len == -1 ? 4096 : s2_len);
        int cmp = s1.compare(s2);
        uint32_t result = (cmp < 0) ? 1 : ((cmp > 0) ? 3 : 2);
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 24);
        cpu.set_pc(ret);
        return 24;
    });

    // ---- CompareStringOrdinal(lpString1, cchCount1, lpString2, cchCount2, bIgnoreCase) ----
    disp.register_native("CompareStringOrdinal", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t s1_ptr = vmem.read32(esp + 4);
        int32_t  s1_len = static_cast<int32_t>(vmem.read32(esp + 8));
        uint32_t s2_ptr = vmem.read32(esp + 12);
        int32_t  s2_len = static_cast<int32_t>(vmem.read32(esp + 16));
        std::string s1 = read_wide_string(vmem, s1_ptr, s1_len == -1 ? 4096 : s1_len);
        std::string s2 = read_wide_string(vmem, s2_ptr, s2_len == -1 ? 4096 : s2_len);
        int cmp = s1.compare(s2);
        uint32_t result = (cmp < 0) ? 1 : ((cmp > 0) ? 3 : 2);
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 20);
        cpu.set_pc(ret);
        return 20;
    });

    // ================================================================
    // ENVIRONMENT APIs
    // ================================================================

    // ---- GetEnvironmentVariableA(lpName, lpBuffer, nSize) ----
    disp.register_native("GetEnvironmentVariableA",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            disp.set_last_error(203); // ERROR_ENVVAR_NOT_FOUND
            cpu.set_reg(X86_EAX, 0u);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 12);
            cpu.set_pc(ret);
            return 12;
        });
    disp.register_native("GetEnvironmentVariableW",
        [&disp](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            disp.set_last_error(203);
            cpu.set_reg(X86_EAX, 0u);
            uint32_t ret = vmem.read32(esp);
            cpu.set_sp(esp + 4 + 12);
            cpu.set_pc(ret);
            return 12;
        });

    // ---- SetEnvironmentVariableA/W(lpName, lpValue) ----
    auto setenv = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    };
    disp.register_native("SetEnvironmentVariableA", setenv);
    disp.register_native("SetEnvironmentVariableW", setenv);

    // ---- GetCommandLineA() ----
    disp.register_native("GetCommandLineA", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap& heap) -> uint32_t {
        static uint32_t cmdline_addr = 0;
        if (cmdline_addr == 0) {
            cmdline_addr = heap.alloc(256);
            vmem.write_string(cmdline_addr, fake_cmdline_a);
        }
        cpu.set_reg(X86_EAX, cmdline_addr);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetCommandLineW() ----
    disp.register_native("GetCommandLineW", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap& heap) -> uint32_t {
        static uint32_t cmdline_addr_w = 0;
        if (cmdline_addr_w == 0) {
            cmdline_addr_w = heap.alloc(512);
            write_wide_string(vmem, cmdline_addr_w, fake_cmdline_a);
        }
        cpu.set_reg(X86_EAX, cmdline_addr_w);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetStartupInfoA/W(lpStartupInfo) — fill with zeros ----
    disp.register_native("GetStartupInfoA", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        vmem.memset(ptr, 0, 68); // sizeof(STARTUPINFOA)
        vmem.write32(ptr, 68);   // cb
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("GetStartupInfoW", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        vmem.memset(ptr, 0, 68);
        vmem.write32(ptr, 68);
        cpu.set_reg(X86_EAX, 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetStdHandle(nStdHandle) ----
    disp.register_native("GetStdHandle", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t type = vmem.read32(esp + 4);
        uint32_t handle;
        switch (type) {
            case 0xFFFFFFF6: handle = FAKE_STDIN_HANDLE; break;  // STD_INPUT_HANDLE
            case 0xFFFFFFF5: handle = FAKE_STDOUT_HANDLE; break; // STD_OUTPUT_HANDLE
            case 0xFFFFFFF4: handle = FAKE_STDERR_HANDLE; break; // STD_ERROR_HANDLE
            default: handle = INVALID_HANDLE_VALUE; break;
        }
        cpu.set_reg(X86_EAX, handle);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- SetStdHandle(nStdHandle, hHandle) ----
    disp.register_native("SetStdHandle", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- GetConsoleMode / SetConsoleMode ----
    disp.register_native("GetConsoleMode", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t mode_ptr = vmem.read32(esp + 8);
        if (mode_ptr != 0) vmem.write32(mode_ptr, 0x0007); // ENABLE_PROCESSED_INPUT etc.
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("SetConsoleMode", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ================================================================
    // ATOM APIs
    // ================================================================

    auto add_atom_impl = [](const std::string& name) -> uint16_t {
        auto it = atom_reverse_.find(name);
        if (it != atom_reverse_.end()) return it->second;
        uint16_t atom = next_atom_++;
        atom_table_[atom] = name;
        atom_reverse_[name] = atom;
        return atom;
    };

    // AddAtomW(lpString)
    disp.register_native("AddAtomW", [add_atom_impl](X86Backend& cpu, VirtualMemory& vmem,
                                                      EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        std::string name = read_wide_string(vmem, str, 256);
        uint16_t atom = add_atom_impl(name);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(atom));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // AddAtomA(lpString) — may already be registered, overwrite is fine
    disp.register_native("AddAtomA", [add_atom_impl](X86Backend& cpu, VirtualMemory& vmem,
                                                      EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        std::string name = vmem.read_string(str, 256);
        uint16_t atom = add_atom_impl(name);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(atom));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // FindAtomA/W
    auto find_atom_a = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        std::string name = vmem.read_string(str, 256);
        auto it = atom_reverse_.find(name);
        uint32_t result = (it != atom_reverse_.end()) ? static_cast<uint32_t>(it->second) : 0;
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("FindAtomA", find_atom_a);

    disp.register_native("FindAtomW", [](X86Backend& cpu, VirtualMemory& vmem,
                                         EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t str = vmem.read32(esp + 4);
        std::string name = read_wide_string(vmem, str, 256);
        auto it = atom_reverse_.find(name);
        uint32_t result = (it != atom_reverse_.end()) ? static_cast<uint32_t>(it->second) : 0;
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // GetAtomNameA/W
    disp.register_native("GetAtomNameA", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint16_t atom = static_cast<uint16_t>(vmem.read32(esp + 4));
        uint32_t buf  = vmem.read32(esp + 8);
        uint32_t size = vmem.read32(esp + 12);
        auto it = atom_table_.find(atom);
        uint32_t result = 0;
        if (it != atom_table_.end() && buf != 0 && size > 0) {
            uint32_t len = std::min(static_cast<uint32_t>(it->second.size()), size - 1);
            vmem.write(buf, it->second.c_str(), len);
            uint8_t null = 0;
            vmem.write(buf + len, &null, 1);
            result = len;
        }
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });
    disp.register_native("GetAtomNameW", [](X86Backend& cpu, VirtualMemory& vmem,
                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint16_t atom = static_cast<uint16_t>(vmem.read32(esp + 4));
        uint32_t buf  = vmem.read32(esp + 8);
        uint32_t size = vmem.read32(esp + 12);
        auto it = atom_table_.find(atom);
        uint32_t result = 0;
        if (it != atom_table_.end() && buf != 0 && size > 0) {
            uint32_t len = std::min(static_cast<uint32_t>(it->second.size()), size - 1);
            write_wide_string(vmem, buf, it->second.substr(0, len));
            result = len;
        }
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // Global atom variants — same implementation, different namespace in real Windows
    disp.register_native("GlobalAddAtomA", [add_atom_impl](X86Backend& cpu, VirtualMemory& vmem,
                                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string name = vmem.read_string(vmem.read32(esp + 4), 256);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(add_atom_impl(name)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("GlobalAddAtomW", [add_atom_impl](X86Backend& cpu, VirtualMemory& vmem,
                                                            EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string name = read_wide_string(vmem, vmem.read32(esp + 4), 256);
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(add_atom_impl(name)));
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    disp.register_native("GlobalFindAtomA", find_atom_a);
    disp.register_native("GlobalFindAtomW", [](X86Backend& cpu, VirtualMemory& vmem,
                                               EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        std::string name = read_wide_string(vmem, vmem.read32(esp + 4), 256);
        auto it = atom_reverse_.find(name);
        cpu.set_reg(X86_EAX, (it != atom_reverse_.end()) ? static_cast<uint32_t>(it->second) : 0u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });
    // GlobalGetAtomNameA/W — identical to GetAtomNameA/W in our emulation
    disp.register_native("GlobalGetAtomNameA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint16_t atom = static_cast<uint16_t>(vmem.read32(esp + 4));
        uint32_t buf  = vmem.read32(esp + 8);
        uint32_t size = vmem.read32(esp + 12);
        auto it = atom_table_.find(atom);
        uint32_t result = 0;
        if (it != atom_table_.end() && buf != 0 && size > 0) {
            uint32_t len = std::min(static_cast<uint32_t>(it->second.size()), size - 1);
            vmem.write(buf, it->second.c_str(), len);
            uint8_t null = 0;
            vmem.write(buf + len, &null, 1);
            result = len;
        }
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });
    disp.register_native("GlobalGetAtomNameW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint16_t atom = static_cast<uint16_t>(vmem.read32(esp + 4));
        uint32_t buf  = vmem.read32(esp + 8);
        uint32_t size = vmem.read32(esp + 12);
        auto it = atom_table_.find(atom);
        uint32_t result = 0;
        if (it != atom_table_.end() && buf != 0 && size > 0) {
            uint32_t len = std::min(static_cast<uint32_t>(it->second.size()), size - 1);
            write_wide_string(vmem, buf, it->second.substr(0, len));
            result = len;
        }
        cpu.set_reg(X86_EAX, result);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 12);
        cpu.set_pc(ret);
        return 12;
    });

    // ================================================================
    // MISC APIs
    // ================================================================

    // ---- GetVersion() ----
    disp.register_native("GetVersion", [](X86Backend& cpu, VirtualMemory& vmem,
                                          EmulatedHeap&) -> uint32_t {
        // Windows 7: major=6 minor=1, build=7601
        // Low word: minor<<8 | major. High word: build
        uint32_t ver = (7601u << 16) | (1u << 8) | 6u;
        cpu.set_reg(X86_EAX, ver);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetVersionExW(lpVersionInformation) ----
    disp.register_native("GetVersionExW", [](X86Backend& cpu, VirtualMemory& vmem,
                                             EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t info_ptr = vmem.read32(esp + 4);
        // OSVERSIONINFOW is same layout but with wide CSD string
        vmem.write32(info_ptr + 4, 6);    // Major
        vmem.write32(info_ptr + 8, 1);    // Minor
        vmem.write32(info_ptr + 12, 7601);// Build
        vmem.write32(info_ptr + 16, 2);   // Platform = VER_PLATFORM_WIN32_NT
        // szCSDVersion at offset 20, wide string
        std::string csd = "Service Pack 1";
        write_wide_string(vmem, info_ptr + 20, csd);
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- EncodePointer / DecodePointer (ptr) — identity transform for emulation ----
    auto ptr_identity = [](X86Backend& cpu, VirtualMemory& vmem, EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ptr = vmem.read32(esp + 4);
        cpu.set_reg(X86_EAX, ptr);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    };
    disp.register_native("EncodePointer", ptr_identity);
    disp.register_native("DecodePointer", ptr_identity);

    // ---- FLS (Fiber-Local Storage) — same as TLS in single-threaded ----
    disp.register_native("FlsAlloc", [](X86Backend& cpu, VirtualMemory& vmem,
                                        EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t idx = next_fls_index_++;
        fls_values_[idx] = 0;
        cpu.set_reg(X86_EAX, idx);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4); // lpCallback
        cpu.set_pc(ret);
        return 4;
    });

    disp.register_native("FlsGetValue", [&disp](X86Backend& cpu, VirtualMemory& vmem,
                                                 EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t idx = vmem.read32(esp + 4);
        auto it = fls_values_.find(idx);
        uint32_t val = (it != fls_values_.end()) ? it->second : 0;
        disp.set_last_error(0);
        cpu.set_reg(X86_EAX, val);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    disp.register_native("FlsSetValue", [](X86Backend& cpu, VirtualMemory& vmem,
                                           EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t idx = vmem.read32(esp + 4);
        uint32_t val = vmem.read32(esp + 8);
        fls_values_[idx] = val;
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    disp.register_native("FlsFree", [](X86Backend& cpu, VirtualMemory& vmem,
                                       EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t idx = vmem.read32(esp + 4);
        fls_values_.erase(idx);
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 4);
        cpu.set_pc(ret);
        return 4;
    });

    // ---- GetTickCount64() ----
    disp.register_native("GetTickCount64", [](X86Backend& cpu, VirtualMemory& vmem,
                                              EmulatedHeap&) -> uint32_t {
        static uint64_t tick64 = 100000;
        tick64 += 16;
        // Returns ULONGLONG — in 32-bit, low in EAX, high in EDX
        cpu.set_reg(X86_EAX, static_cast<uint32_t>(tick64 & 0xFFFFFFFF));
        cpu.set_reg(X86_EDX, static_cast<uint32_t>(tick64 >> 32));
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    // ---- GetComputerNameA/W(lpBuffer, lpnSize) ----
    disp.register_native("GetComputerNameA", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf = vmem.read32(esp + 4);
        uint32_t size_ptr = vmem.read32(esp + 8);
        std::string name = "VXENGINE";
        if (buf != 0 && size_ptr != 0) {
            vmem.write_string(buf, name);
            vmem.write32(size_ptr, static_cast<uint32_t>(name.size()));
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });
    disp.register_native("GetComputerNameW", [](X86Backend& cpu, VirtualMemory& vmem,
                                                EmulatedHeap&) -> uint32_t {
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t buf = vmem.read32(esp + 4);
        uint32_t size_ptr = vmem.read32(esp + 8);
        std::string name = "VXENGINE";
        if (buf != 0 && size_ptr != 0) {
            write_wide_string(vmem, buf, name);
            vmem.write32(size_ptr, static_cast<uint32_t>(name.size()));
        }
        cpu.set_reg(X86_EAX, 1u);
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4 + 8);
        cpu.set_pc(ret);
        return 8;
    });

    // ---- Locale APIs ----
    disp.register_native("GetUserDefaultLCID", [](X86Backend& cpu, VirtualMemory& vmem,
                                                  EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, 0x0409u); // en-US
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    disp.register_native("GetUserDefaultUILanguage", [](X86Backend& cpu, VirtualMemory& vmem,
                                                        EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, 0x0409u); // en-US
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

    disp.register_native("GetSystemDefaultLCID", [](X86Backend& cpu, VirtualMemory& vmem,
                                                    EmulatedHeap&) -> uint32_t {
        cpu.set_reg(X86_EAX, 0x0409u);
        uint32_t esp = static_cast<uint32_t>(cpu.sp());
        uint32_t ret = vmem.read32(esp);
        cpu.set_sp(esp + 4);
        cpu.set_pc(ret);
        return 0;
    });

} // register_extended_apis

} // namespace vx
