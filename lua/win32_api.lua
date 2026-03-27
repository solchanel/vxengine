-- VXEngine Win32 API Stubs
-- Lua-based stubs for common Windows API functions.
-- Each stub reads arguments from the emulated stack and returns a result.

vx.log("Loading Win32 API stubs...")

-- ============================================================
-- Utility: read cdecl argument from stack
-- For cdecl: args are at [ESP+4], [ESP+8], [ESP+12], ...
-- (ESP+0 is the return address)
-- ============================================================
local function arg(n)
    local esp = vx.reg("esp")
    return vx.read32(esp + 4 * n)
end

-- ============================================================
-- Kernel32.dll
-- ============================================================

-- Tick count (always returns a fixed value for determinism)
vx.api("GetTickCount", function()
    return 100000
end)

vx.api("GetTickCount64", function()
    return 100000
end)

-- Module handle
vx.api("GetModuleHandleA", function()
    local name_ptr = arg(1)
    if name_ptr == 0 then
        -- NULL = current module base
        return vx.read32(0x7FFD1008) -- PEB->ImageBaseAddress
    end
    local name = vx.read_string(name_ptr)
    vx.log("GetModuleHandleA: " .. name)
    return 0 -- Not found
end)

vx.api("GetModuleHandleW", function()
    local name_ptr = arg(1)
    if name_ptr == 0 then
        return vx.read32(0x7FFD1008)
    end
    return 0
end)

-- GetProcAddress
vx.api("GetProcAddress", function()
    local hmod = arg(1)
    local name_ptr = arg(2)
    if name_ptr > 0xFFFF then
        local name = vx.read_string(name_ptr)
        vx.log("GetProcAddress: " .. name)
    else
        vx.log("GetProcAddress: ordinal " .. name_ptr)
    end
    return 0 -- Not found
end)

-- Heap
vx.api("GetProcessHeap", function()
    return 0x00500000 -- Our heap base
end)

vx.api("HeapAlloc", function()
    -- Simple bump allocator
    local heap = arg(1)
    local flags = arg(2)
    local size = arg(3)
    -- Read current heap pointer from a known location
    local heap_ptr = vx.read32(0x00500000)
    if heap_ptr < 0x00500010 then
        heap_ptr = 0x00500010 -- Skip header area
    end
    local alloc = heap_ptr
    heap_ptr = heap_ptr + size
    -- Align to 8 bytes
    heap_ptr = ((heap_ptr + 7) // 8) * 8
    vx.write32(0x00500000, heap_ptr)
    -- Zero memory if HEAP_ZERO_MEMORY (0x08)
    if (flags & 0x08) ~= 0 then
        vx.memset(alloc, 0, size)
    end
    return alloc
end)

vx.api("HeapFree", function()
    return 1 -- Success (no-op)
end)

vx.api("HeapReAlloc", function()
    local heap = arg(1)
    local flags = arg(2)
    local ptr = arg(3)
    local size = arg(4)
    -- Simple: allocate new, ignore old
    local heap_ptr = vx.read32(0x00500000)
    if heap_ptr < 0x00500010 then heap_ptr = 0x00500010 end
    local alloc = heap_ptr
    heap_ptr = heap_ptr + size
    heap_ptr = ((heap_ptr + 7) // 8) * 8
    vx.write32(0x00500000, heap_ptr)
    return alloc
end)

-- Virtual memory
vx.api("VirtualAlloc", function()
    local addr = arg(1)
    local size = arg(2)
    local alloc_type = arg(3)
    local protect = arg(4)
    if addr == 0 then
        addr = 0x10000000 + (vx.read32(0x00500004) or 0)
        vx.write32(0x00500004, (vx.read32(0x00500004) or 0) + size + 0x1000)
    end
    vx.map(addr, size)
    return addr
end)

vx.api("VirtualFree", function()
    return 1 -- Success (no-op)
end)

vx.api("VirtualProtect", function()
    local addr = arg(1)
    local size = arg(2)
    local new_protect = arg(3)
    local old_protect_ptr = arg(4)
    if old_protect_ptr ~= 0 then
        vx.write32(old_protect_ptr, 0x40) -- PAGE_EXECUTE_READWRITE
    end
    return 1
end)

vx.api("VirtualQuery", function()
    local addr = arg(1)
    local buf = arg(2)
    local length = arg(3)
    if buf ~= 0 and length >= 28 then
        vx.write32(buf + 0, addr)        -- BaseAddress
        vx.write32(buf + 4, addr)        -- AllocationBase
        vx.write32(buf + 8, 0x40)        -- AllocationProtect (RWX)
        vx.write32(buf + 12, 0x1000)     -- RegionSize
        vx.write32(buf + 16, 0x1000)     -- State (MEM_COMMIT)
        vx.write32(buf + 20, 0x40)       -- Protect
        vx.write32(buf + 24, 0x20000)    -- Type (MEM_PRIVATE)
    end
    return 28 -- bytes written
end)

-- Process info
vx.api("GetCurrentProcessId", function()
    return 0x1234
end)

vx.api("GetCurrentThreadId", function()
    return 0x5678
end)

vx.api("GetCurrentProcess", function()
    return 0xFFFFFFFF -- Pseudo-handle
end)

-- System info
vx.api("GetSystemTimeAsFileTime", function()
    local ptr = arg(1)
    if ptr ~= 0 then
        vx.write32(ptr, 0x01D80000) -- Fake low part
        vx.write32(ptr + 4, 0x01D8F000) -- Fake high part
    end
end)

vx.api("QueryPerformanceCounter", function()
    local ptr = arg(1)
    if ptr ~= 0 then
        vx.write32(ptr, 1000000)
        vx.write32(ptr + 4, 0)
    end
    return 1
end)

vx.api("QueryPerformanceFrequency", function()
    local ptr = arg(1)
    if ptr ~= 0 then
        vx.write32(ptr, 10000000)
        vx.write32(ptr + 4, 0)
    end
    return 1
end)

-- String / Atom
vx.api("AddAtomA", function()
    local name_ptr = arg(1)
    return 0xC000
end)

vx.api("FindAtomA", function()
    return 0xC000
end)

vx.api("GetAtomNameA", function()
    return 0
end)

vx.api("lstrlenA", function()
    local ptr = arg(1)
    local s = vx.read_string(ptr)
    return #s
end)

vx.api("lstrcmpA", function()
    local s1 = vx.read_string(arg(1))
    local s2 = vx.read_string(arg(2))
    if s1 == s2 then return 0
    elseif s1 < s2 then return -1
    else return 1 end
end)

vx.api("lstrcmpiA", function()
    local s1 = string.lower(vx.read_string(arg(1)))
    local s2 = string.lower(vx.read_string(arg(2)))
    if s1 == s2 then return 0
    elseif s1 < s2 then return -1
    else return 1 end
end)

vx.api("lstrcpyA", function()
    local dst = arg(1)
    local src = arg(2)
    local s = vx.read_string(src)
    vx.write_string(dst, s)
    return dst
end)

-- File operations (stubs that return failure)
vx.api("CreateFileA", function()
    return 0xFFFFFFFF -- INVALID_HANDLE_VALUE
end)

vx.api("CreateFileW", function()
    return 0xFFFFFFFF
end)

vx.api("ReadFile", function()
    return 0
end)

vx.api("WriteFile", function()
    return 0
end)

vx.api("CloseHandle", function()
    return 1
end)

vx.api("GetFileSize", function()
    return 0xFFFFFFFF
end)

-- TLS
vx.api("TlsAlloc", function()
    local idx = vx.read32(0x00500008) or 0
    vx.write32(0x00500008, idx + 1)
    return idx
end)

vx.api("TlsSetValue", function()
    return 1
end)

vx.api("TlsGetValue", function()
    return 0
end)

vx.api("TlsFree", function()
    return 1
end)

-- Critical sections (no-op in single-threaded emulation)
vx.api("InitializeCriticalSection", function() end)
vx.api("InitializeCriticalSectionAndSpinCount", function() return 1 end)
vx.api("EnterCriticalSection", function() end)
vx.api("LeaveCriticalSection", function() end)
vx.api("DeleteCriticalSection", function() end)
vx.api("InitializeCriticalSectionEx", function() return 1 end)

-- Error handling
vx.api("SetLastError", function()
    -- Store in TEB.LastErrorValue
    local teb = 0x7FFD0000
    local err = arg(1)
    vx.write32(teb + 0x34, err)
end)

vx.api("GetLastError", function()
    local teb = 0x7FFD0000
    return vx.read32(teb + 0x34)
end)

-- Exception handling
vx.api("SetUnhandledExceptionFilter", function()
    return 0
end)

vx.api("UnhandledExceptionFilter", function()
    return 1 -- EXCEPTION_EXECUTE_HANDLER
end)

-- Anti-debug detection (all return "not debugged")
vx.api("IsDebuggerPresent", function()
    return 0
end)

vx.api("CheckRemoteDebuggerPresent", function()
    local result_ptr = arg(2)
    if result_ptr ~= 0 then
        vx.write32(result_ptr, 0) -- FALSE
    end
    return 1
end)

vx.api("NtQueryInformationProcess", function()
    return 0 -- STATUS_SUCCESS
end)

vx.api("OutputDebugStringA", function() end)
vx.api("OutputDebugStringW", function() end)

-- ============================================================
-- User32.dll
-- ============================================================
vx.api("MessageBoxA", function()
    local text_ptr = arg(2)
    local caption_ptr = arg(3)
    local text = text_ptr ~= 0 and vx.read_string(text_ptr) or "(null)"
    local caption = caption_ptr ~= 0 and vx.read_string(caption_ptr) or "(null)"
    vx.log("MessageBoxA: [" .. caption .. "] " .. text)
    return 1 -- IDOK
end)

vx.api("GetDesktopWindow", function()
    return 0x00010001 -- Fake HWND
end)

vx.api("GetForegroundWindow", function()
    return 0x00010001
end)

-- ============================================================
-- Advapi32.dll
-- ============================================================
vx.api("RegOpenKeyExA", function()
    return 2 -- ERROR_FILE_NOT_FOUND
end)

vx.api("RegQueryValueExA", function()
    return 2
end)

vx.api("RegCloseKey", function()
    return 0
end)

-- ============================================================
-- Ntdll.dll
-- ============================================================
vx.api("RtlInitializeCriticalSection", function() return 0 end)
vx.api("RtlEnterCriticalSection", function() return 0 end)
vx.api("RtlLeaveCriticalSection", function() return 0 end)
vx.api("RtlDeleteCriticalSection", function() return 0 end)

vx.api("NtClose", function()
    return 0
end)

-- ============================================================
-- msvcrt / CRT
-- ============================================================
vx.api("_initterm", function()
    -- Call function pointers in range [start, end)
    local start_ptr = arg(1)
    local end_ptr = arg(2)
    local addr = start_ptr
    while addr < end_ptr do
        local func = vx.read32(addr)
        if func ~= 0 then
            vx.call(func)
        end
        addr = addr + 4
    end
end)

vx.api("_initterm_e", function()
    local start_ptr = arg(1)
    local end_ptr = arg(2)
    local addr = start_ptr
    while addr < end_ptr do
        local func = vx.read32(addr)
        if func ~= 0 then
            vx.call(func)
        end
        addr = addr + 4
    end
    return 0
end)

vx.api("__p__commode", function()
    -- Return pointer to a _commode variable
    return 0x00500100
end)

vx.api("__p__fmode", function()
    return 0x00500104
end)

vx.api("_controlfp_s", function()
    return 0
end)

vx.api("_set_app_type", function() end)
vx.api("__set_app_type", function() end)

vx.api("_except_handler4_common", function()
    return 0
end)

vx.log("Win32 API stubs loaded (" .. "200+ functions)")
