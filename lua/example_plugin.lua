--[[
    VXEngine Example Plugin
    =======================

    This file demonstrates how to write a VXEngine Lua plugin using the
    unified plugin API. Copy this as a template for your own plugins.

    Place your plugin in the lua/ directory — it will be auto-discovered,
    or load it manually with: vx.plugin.load("path/to/plugin.lua")

    Plugin Lifecycle:
        1. Plugin file is executed by Lua
        2. vx.plugin.register() is called with metadata
        3. init() function is called
        4. Event handlers receive callbacks during execution
        5. shutdown() is called on unload
]]

-- ============================================================
-- Register the plugin
-- ============================================================
vx.plugin.register({
    name        = "example",
    version     = "1.0.0",
    description = "Example plugin showing all VXEngine plugin APIs",
    author      = "VXEngine",

    -- Called when plugin is loaded
    init = function()
        vx.log("[example] Plugin initialized!")
    end,

    -- Called when plugin is unloaded
    shutdown = function()
        vx.log("[example] Plugin shutting down")
    end,
})

-- ============================================================
-- Register API stubs
-- ============================================================
-- Use vx.plugin.api(dll, function_name, handler, [nargs], [calling_conv])

-- Simple stub that returns a constant
vx.plugin.api("kernel32.dll", "GetTickCount", function()
    return 100000  -- Always return 100 seconds
end, 0, "stdcall")

-- Stub that reads arguments from the emulated stack
vx.plugin.api("kernel32.dll", "GetModuleHandleA", function(name_ptr)
    if name_ptr == 0 then
        return 0x400000  -- Return main module base
    end
    local name = vx.read_string(name_ptr):lower()
    if name:find("kernel32") then return 0x76000000 end
    if name:find("ntdll")    then return 0x77000000 end
    return 0x75000000  -- Generic DLL base
end, 1, "stdcall")

-- VirtualAlloc with actual memory mapping
vx.plugin.api("kernel32.dll", "VirtualAlloc", function(addr, size, type, protect)
    if addr == 0 then
        addr = vx.heap_alloc(size)
    end
    vx.map(addr, size)
    return addr
end, 4, "stdcall")

-- ============================================================
-- Register event handlers
-- ============================================================
-- Use vx.plugin.on(event_name, handler)
-- Events: "load", "step", "breakpoint", "watchpoint", "api_call",
--         "exception", "branch", "mem_map", "dll_load", "init_complete"

-- Called every time an instruction is stepped (use sparingly — slow!)
vx.plugin.on("step", function(addr, disasm)
    -- Only log specific addresses to avoid flooding
    if addr == 0x621c8e08 then
        vx.log(string.format("[example] Handler registration at 0x%08x", addr))
    end
end)

-- Called when a breakpoint is hit
vx.plugin.on("breakpoint", function(addr)
    vx.log(string.format("[example] Breakpoint hit at 0x%08x", addr))
    vx.log("  EAX=" .. string.format("0x%08x", vx.reg("eax")))
    vx.log("  ESP=" .. string.format("0x%08x", vx.reg("esp")))
end)

-- Called when a watchpoint fires
vx.plugin.on("watchpoint", function(addr, size, value)
    vx.log(string.format("[example] Write to 0x%08x: 0x%08x (%d bytes)",
        addr, value, size))
end)

-- Called when DLL init completes
vx.plugin.on("init_complete", function()
    vx.log("[example] DLL initialization completed!")
end)

-- ============================================================
-- Register REPL commands
-- ============================================================
-- Use vx.plugin.command(name, description, handler, [usage])

vx.plugin.command("hello", "Print a greeting", function(args)
    vx.log("Hello from VXEngine! Args: " .. (args or "none"))
end, "hello [name]")

-- Useful command: dump memory as hex
vx.plugin.command("hexdump", "Dump memory as hex", function(args)
    -- Parse: hexdump <addr> [size]
    local parts = {}
    for w in args:gmatch("%S+") do parts[#parts+1] = w end

    local addr = tonumber(parts[1], 16) or tonumber(parts[1]) or 0
    local size = tonumber(parts[2]) or 64

    vx.log(string.format("Hexdump at 0x%08x (%d bytes):", addr, size))
    for row = 0, size - 1, 16 do
        local hex_parts = {}
        local ascii = ""
        for col = 0, 15 do
            if row + col < size then
                local byte = vx.read(addr + row + col, 1):byte()
                hex_parts[#hex_parts+1] = string.format("%02x", byte)
                if byte >= 0x20 and byte < 0x7f then
                    ascii = ascii .. string.char(byte)
                else
                    ascii = ascii .. "."
                end
            end
        end
        vx.log(string.format("  %08x: %-48s  %s",
            addr + row, table.concat(hex_parts, " "), ascii))
    end
end, "hexdump <addr> [size]")

-- ============================================================
-- Plugin-local helper functions
-- ============================================================
-- These are just regular Lua functions scoped to this file

local function is_in_text_section(addr)
    return addr >= 0x62181000 and addr < 0x621EC000
end

local function format_handler(idx, val)
    local location = is_in_text_section(val) and "CODE" or "ENCRYPTED"
    return string.format("  handler[%3d] = 0x%08x  [%s]", idx, val, location)
end

-- ============================================================
-- Exported module functions (accessible via require or dofile)
-- ============================================================
-- These can be called from the REPL or other scripts

function dump_all_handlers(table_addr, count)
    table_addr = table_addr or 0x62201B80
    count = count or 288
    local found = 0
    for i = 0, count - 1 do
        local val = vx.read32(table_addr + i * 4)
        if val ~= 0xFFFFFFFF and val ~= 0 then
            vx.log(format_handler(i, val))
            found = found + 1
        end
    end
    vx.log(string.format("Total: %d/%d handlers populated", found, count))
    return found
end
