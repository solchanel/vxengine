/**
 * VXEngine VFS-backed Windows File API Handlers
 *
 * Routes Win32 file APIs (CreateFileA/W, ReadFile, WriteFile, etc.)
 * through the VirtualFileSystem instead of touching the real host OS.
 *
 * All handlers use the active APIDispatcher from engine.h:
 *   APIHandler = std::function<uint64_t(ICpuBackend& cpu, VirtualMemory& vmem)>
 * Handler returns uint64_t (set as EAX). Dispatcher auto-handles RET (pops
 * return addr). For stdcall, handlers must pop args: cpu.set_sp(cpu.sp() + N*4).
 */

#include "vfs.h"
#include "vxengine/engine.h"
#include <cstring>
#include <iostream>

namespace vx {

// ============================================================
// Helpers
// ============================================================

/// Read a null-terminated ASCII string from guest memory
static std::string read_guest_string(VirtualMemory& vmem, uint64_t addr, size_t max = 1024) {
    std::string result;
    result.reserve(256);
    for (size_t i = 0; i < max; ++i) {
        uint8_t ch = 0;
        vmem.read(addr + i, &ch, 1);
        if (ch == 0) break;
        result.push_back(static_cast<char>(ch));
    }
    return result;
}

/// Read a null-terminated UTF-16LE string from guest memory, narrow to ASCII
static std::string read_guest_wstring(VirtualMemory& vmem, uint64_t addr, size_t max_chars = 1024) {
    std::string result;
    result.reserve(256);
    for (size_t i = 0; i < max_chars; ++i) {
        uint16_t wc = 0;
        vmem.read(addr + i * 2, &wc, 2);
        if (wc == 0) break;
        result.push_back(static_cast<char>(wc & 0xFF));
    }
    return result;
}

/// Write a null-terminated ASCII string to guest memory
static void write_guest_string(VirtualMemory& vmem, uint64_t addr, const std::string& str) {
    vmem.write(addr, str.data(), str.size());
    uint8_t null_byte = 0;
    vmem.write(addr + str.size(), &null_byte, 1);
}

/// Write a null-terminated UTF-16LE string to guest memory
static void write_guest_wstring(VirtualMemory& vmem, uint64_t addr, const std::string& str) {
    for (size_t i = 0; i < str.size(); ++i) {
        uint16_t wc = static_cast<uint16_t>(static_cast<uint8_t>(str[i]));
        vmem.write(addr + i * 2, &wc, 2);
    }
    uint16_t null_wc = 0;
    vmem.write(addr + str.size() * 2, &null_wc, 2);
}

/// Read a stdcall argument from guest stack (arg 0 is at [ESP+4])
static uint32_t stack_arg(ICpuBackend& cpu, VirtualMemory& vmem, int index) {
    uint64_t esp = cpu.sp();
    return vmem.read32(static_cast<uint32_t>(esp) + 4 + index * 4);
}

/// Write a WIN32_FIND_DATAA struct to guest memory
static void write_find_data(VirtualMemory& vmem, uint64_t addr,
                             uint32_t attrs, uint32_t file_size,
                             const std::string& filename) {
    // Zero-fill the entire 318-byte structure
    uint8_t zeros[320] = {};
    vmem.write(addr, zeros, 318);

    // dwFileAttributes at offset +0 (4 bytes)
    vmem.write32(addr + 0, attrs);

    // nFileSizeHigh at +28 (4 bytes) — always 0 for our files
    vmem.write32(addr + 28, 0);

    // nFileSizeLow at +32 (4 bytes)
    vmem.write32(addr + 32, file_size);

    // cFileName at +44 (MAX_PATH = 260 bytes)
    size_t name_len = std::min(filename.size(), size_t(259));
    vmem.write(addr + 44, filename.data(), name_len);
    uint8_t null_byte = 0;
    vmem.write(addr + 44 + name_len, &null_byte, 1);
}

// ============================================================
// Registration
// ============================================================

void register_vfs_apis(APIDispatcher& api, VirtualFileSystem& vfs) {

    // ---- CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSA,
    //                  dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) ----
    // 7 args = 28 bytes stdcall
    api.register_api("CreateFileA",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName             = stack_arg(cpu, vmem, 0);
            uint32_t dwDesiredAccess        = stack_arg(cpu, vmem, 1);
            // dwShareMode(2), lpSA(3) — ignored
            uint32_t dwCreationDisposition  = stack_arg(cpu, vmem, 4);
            // dwFlagsAndAttributes(5), hTemplateFile(6) — ignored

            std::string filename = read_guest_string(vmem, lpFileName);
            uint32_t handle = vfs.open(filename, dwDesiredAccess, dwCreationDisposition);

            cpu.set_sp(cpu.sp() + 28); // 7 args * 4
            return handle;
        });

    // ---- CreateFileW — wide string variant ----
    api.register_api("CreateFileW",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName             = stack_arg(cpu, vmem, 0);
            uint32_t dwDesiredAccess        = stack_arg(cpu, vmem, 1);
            uint32_t dwCreationDisposition  = stack_arg(cpu, vmem, 4);

            std::string filename = read_guest_wstring(vmem, lpFileName);
            uint32_t handle = vfs.open(filename, dwDesiredAccess, dwCreationDisposition);

            cpu.set_sp(cpu.sp() + 28);
            return handle;
        });

    // ---- ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) ----
    // 5 args = 20 bytes stdcall
    api.register_api("ReadFile",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFile              = stack_arg(cpu, vmem, 0);
            uint32_t lpBuffer           = stack_arg(cpu, vmem, 1);
            uint32_t nBytesToRead       = stack_arg(cpu, vmem, 2);
            uint32_t lpBytesRead        = stack_arg(cpu, vmem, 3);
            // lpOverlapped(4) — ignored

            cpu.set_sp(cpu.sp() + 20);

            if (!vfs.is_vfs_handle(hFile)) {
                // Not a VFS handle — return failure
                if (lpBytesRead) vmem.write32(lpBytesRead, 0);
                return 0; // FALSE
            }

            // Read into temp buffer
            std::vector<uint8_t> buf(nBytesToRead);
            uint32_t bytes_read = 0;
            bool ok = vfs.read(hFile, buf.data(), nBytesToRead, &bytes_read);

            if (ok && bytes_read > 0) {
                vmem.write(lpBuffer, buf.data(), bytes_read);
            }
            if (lpBytesRead) {
                vmem.write32(lpBytesRead, bytes_read);
            }

            return ok ? 1u : 0u; // TRUE/FALSE
        });

    // ---- WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) ----
    // 5 args = 20 bytes stdcall
    api.register_api("WriteFile",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFile              = stack_arg(cpu, vmem, 0);
            uint32_t lpBuffer           = stack_arg(cpu, vmem, 1);
            uint32_t nBytesToWrite      = stack_arg(cpu, vmem, 2);
            uint32_t lpBytesWritten     = stack_arg(cpu, vmem, 3);
            // lpOverlapped(4) — ignored

            cpu.set_sp(cpu.sp() + 20);

            if (!vfs.is_vfs_handle(hFile)) {
                if (lpBytesWritten) vmem.write32(lpBytesWritten, 0);
                return 0;
            }

            // Read data from guest memory
            std::vector<uint8_t> buf(nBytesToWrite);
            vmem.read(lpBuffer, buf.data(), nBytesToWrite);

            uint32_t bytes_written = 0;
            bool ok = vfs.write(hFile, buf.data(), nBytesToWrite, &bytes_written);

            if (lpBytesWritten) {
                vmem.write32(lpBytesWritten, bytes_written);
            }

            return ok ? 1u : 0u;
        });

    // ---- CloseHandle(hObject) ----
    // 1 arg = 4 bytes stdcall
    api.register_api("CloseHandle",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hObject = stack_arg(cpu, vmem, 0);

            cpu.set_sp(cpu.sp() + 4);

            if (vfs.is_vfs_handle(hObject)) {
                vfs.close(hObject);
            }
            // Always return TRUE (even for non-VFS handles — other subsystems
            // may have handled it, or it's a no-op)
            return 1;
        });

    // ---- GetFileSize(hFile, lpFileSizeHigh) ----
    // 2 args = 8 bytes stdcall
    api.register_api("GetFileSize",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFile          = stack_arg(cpu, vmem, 0);
            uint32_t lpFileSizeHigh = stack_arg(cpu, vmem, 1);

            cpu.set_sp(cpu.sp() + 8);

            if (!vfs.is_vfs_handle(hFile)) {
                return 0xFFFFFFFF; // INVALID_FILE_SIZE
            }

            uint32_t size = vfs.get_size(hFile);
            if (lpFileSizeHigh != 0) {
                vmem.write32(lpFileSizeHigh, 0); // High DWORD = 0
            }
            return size;
        });

    // ---- SetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod) ----
    // 4 args = 16 bytes stdcall
    api.register_api("SetFilePointer",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFile                  = stack_arg(cpu, vmem, 0);
            int32_t  lDistanceToMove        = static_cast<int32_t>(stack_arg(cpu, vmem, 1));
            // lpDistanceToMoveHigh(2) — ignored for 32-bit files
            uint32_t dwMoveMethod           = stack_arg(cpu, vmem, 3);

            cpu.set_sp(cpu.sp() + 16);

            if (!vfs.is_vfs_handle(hFile)) {
                return 0xFFFFFFFF; // INVALID_SET_FILE_POINTER
            }

            vfs.set_pointer(hFile, lDistanceToMove, dwMoveMethod);
            return vfs.get_pointer(hFile);
        });

    // ---- GetFileAttributesA(lpFileName) ----
    // 1 arg = 4 bytes stdcall
    api.register_api("GetFileAttributesA",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName = stack_arg(cpu, vmem, 0);

            cpu.set_sp(cpu.sp() + 4);

            std::string filename = read_guest_string(vmem, lpFileName);
            return vfs.get_attributes(filename);
        });

    // ---- GetFileAttributesW — wide variant ----
    api.register_api("GetFileAttributesW",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName = stack_arg(cpu, vmem, 0);

            cpu.set_sp(cpu.sp() + 4);

            std::string filename = read_guest_wstring(vmem, lpFileName);
            return vfs.get_attributes(filename);
        });

    // ---- FindFirstFileA(lpFileName, lpFindFileData) ----
    // 2 args = 8 bytes stdcall
    api.register_api("FindFirstFileA",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName     = stack_arg(cpu, vmem, 0);
            uint32_t lpFindFileData = stack_arg(cpu, vmem, 1);

            cpu.set_sp(cpu.sp() + 8);

            std::string pattern = read_guest_string(vmem, lpFileName);
            std::string found_name;
            uint32_t attrs = 0;
            uint32_t file_size = 0;

            uint32_t find_handle = vfs.find_first(pattern, &found_name, &attrs, &file_size);
            if (find_handle == VirtualFileSystem::INVALID_HANDLE) {
                return 0xFFFFFFFF; // INVALID_HANDLE_VALUE
            }

            write_find_data(vmem, lpFindFileData, attrs, file_size, found_name);
            return find_handle;
        });

    // ---- FindNextFileA(hFindFile, lpFindFileData) ----
    // 2 args = 8 bytes stdcall
    api.register_api("FindNextFileA",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFindFile      = stack_arg(cpu, vmem, 0);
            uint32_t lpFindFileData = stack_arg(cpu, vmem, 1);

            cpu.set_sp(cpu.sp() + 8);

            std::string found_name;
            uint32_t attrs = 0;
            uint32_t file_size = 0;

            bool ok = vfs.find_next(hFindFile, &found_name, &attrs, &file_size);
            if (!ok) {
                return 0; // FALSE — ERROR_NO_MORE_FILES
            }

            write_find_data(vmem, lpFindFileData, attrs, file_size, found_name);
            return 1; // TRUE
        });

    // ---- FindClose(hFindFile) ----
    // 1 arg = 4 bytes stdcall
    api.register_api("FindClose",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t hFindFile = stack_arg(cpu, vmem, 0);

            cpu.set_sp(cpu.sp() + 4);

            vfs.find_close(hFindFile);
            return 1; // TRUE
        });

    // ---- DeleteFileA(lpFileName) ----
    // 1 arg = 4 bytes stdcall
    api.register_api("DeleteFileA",
        [&vfs](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t lpFileName = stack_arg(cpu, vmem, 0);

            cpu.set_sp(cpu.sp() + 4);

            std::string filename = read_guest_string(vmem, lpFileName);
            // Log the deletion attempt but don't actually remove from VFS
            // (behavioral analysis: we want to see what the binary tries to delete)
            std::cerr << "[vfs] DeleteFileA: " << filename << "\n";
            return 1; // TRUE — pretend success
        });

    // ---- GetTempPathA(nBufferLength, lpBuffer) ----
    // 2 args = 8 bytes stdcall
    api.register_api("GetTempPathA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t nBufferLength = stack_arg(cpu, vmem, 0);
            uint32_t lpBuffer      = stack_arg(cpu, vmem, 1);

            cpu.set_sp(cpu.sp() + 8);

            const std::string temp_path = "C:\\Temp\\";
            uint32_t len = static_cast<uint32_t>(temp_path.size());

            if (lpBuffer != 0 && nBufferLength > len) {
                write_guest_string(vmem, lpBuffer, temp_path);
            }

            return len; // Return length excluding null terminator
        });

    // ---- GetTempPathW — wide variant ----
    api.register_api("GetTempPathW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t nBufferLength = stack_arg(cpu, vmem, 0);
            uint32_t lpBuffer      = stack_arg(cpu, vmem, 1);

            cpu.set_sp(cpu.sp() + 8);

            const std::string temp_path = "C:\\Temp\\";
            uint32_t len = static_cast<uint32_t>(temp_path.size());

            if (lpBuffer != 0 && nBufferLength > len) {
                write_guest_wstring(vmem, lpBuffer, temp_path);
            }

            return len; // Return length in characters
        });
}

} // namespace vx
