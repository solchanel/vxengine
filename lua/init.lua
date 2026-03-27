-- VXEngine init.lua
-- Auto-loaded on startup. Prints banner and loads other scripts.

print("========================================")
print("  VXEngine Lua Environment")
print("  Type vx.help() for available commands")
print("========================================")
print("")

-- Helper: print hex value
function hex(val)
    return string.format("0x%08X", val)
end

-- Helper: print register state
function regs()
    local names = {"eax","ecx","edx","ebx","esp","ebp","esi","edi","eip","eflags"}
    for _, name in ipairs(names) do
        local val = vx.reg(name)
        print(string.format("  %-8s = 0x%08X", name, val))
    end
end

-- Helper: disassemble N instructions at addr (or PC)
function dis(addr, count)
    addr = addr or vx.reg("eip")
    count = count or 10
    for i = 0, count - 1 do
        local text = vx.disasm(addr + i)
        print(string.format("  0x%08X: %s", addr + i, text))
    end
end

-- Helper: hexdump memory
function dump(addr, size)
    size = size or 64
    local data = vx.read(addr, size)
    local lines = {}
    for i = 1, #data, 16 do
        local hex_part = ""
        local ascii_part = ""
        for j = 0, 15 do
            if i + j <= #data then
                local b = string.byte(data, i + j)
                hex_part = hex_part .. string.format("%02X ", b)
                if b >= 32 and b < 127 then
                    ascii_part = ascii_part .. string.char(b)
                else
                    ascii_part = ascii_part .. "."
                end
            end
        end
        print(string.format("  0x%08X: %-48s %s", addr + i - 1, hex_part, ascii_part))
    end
end

-- Show help
vx.help = function()
    print("VXEngine Lua Commands:")
    print("  vx.load(path)              -- Load PE/ELF binary")
    print("  vx.step()                  -- Single step")
    print("  vx.run_until(addr)         -- Run to address")
    print("  vx.reg(name) / set_reg()   -- Read/write register")
    print("  vx.read(addr, size)        -- Read memory bytes")
    print("  vx.write(addr, data)       -- Write memory bytes")
    print("  vx.read32(addr)            -- Read DWORD")
    print("  vx.write32(addr, val)      -- Write DWORD")
    print("  vx.read_string(addr)       -- Read null-terminated string")
    print("  vx.map(addr, size)         -- Map memory region")
    print("  vx.split_page(addr)        -- Shadow PTE split-view")
    print("  vx.stealth_hook(addr, b)   -- Install invisible hook")
    print("  vx.watch(addr, size, cb)   -- Set watchpoint")
    print("  vx.bp(addr)                -- Set breakpoint")
    print("  vx.disasm(addr)            -- Disassemble")
    print("  vx.api(name, handler)      -- Register API stub")
    print("  vx.call(addr, ...)         -- Call function")
    print("  vx.log(msg)               -- Print message")
    print("")
    print("Helpers:")
    print("  regs()                     -- Print all registers")
    print("  dis(addr, count)           -- Disassemble N instructions")
    print("  dump(addr, size)           -- Hexdump memory")
    print("  hex(val)                   -- Format as hex string")
end

-- ============================================================
-- Plugin auto-discovery
-- ============================================================
-- Load win32_api.lua first (provides critical API stubs)
-- Then load any other plugins from the lua/ directory

local plugin_load_order = {
    "lua/win32_api.lua",       -- Windows API stubs (load first!)
    "lua/deobfuscate.lua",     -- Deobfuscation helpers
}

for _, script in ipairs(plugin_load_order) do
    local ok, err = pcall(function() dofile(script) end)
    if ok then
        vx.log("[init] Loaded: " .. script)
    end
end

-- Auto-discover additional plugins (*.lua files not already loaded)
local loaded_set = {}
for _, s in ipairs(plugin_load_order) do loaded_set[s] = true end
loaded_set["lua/init.lua"] = true  -- Don't re-load ourselves

if vx.plugin and vx.plugin.load then
    -- Use the plugin manager if available
    local ok, err = pcall(function()
        local dir = "lua"
        -- Platform-independent directory listing via Lua
        local handle = io.popen('ls "' .. dir .. '"/*.lua 2>/dev/null || dir /b "' .. dir .. '"\\*.lua 2>nul')
        if handle then
            for file in handle:lines() do
                local path = dir .. "/" .. file:match("[^/\\]+$")
                if not loaded_set[path] and not loaded_set[dir .. "\\" .. file] then
                    local load_ok = pcall(function() dofile(path) end)
                    if load_ok then
                        vx.log("[init] Auto-loaded plugin: " .. path)
                    end
                end
            end
            handle:close()
        end
    end)
end

-- Show loaded plugins if plugin manager is available
if vx.plugin and vx.plugin.list then
    local plugins = vx.plugin.list()
    if #plugins > 0 then
        print("")
        print("Loaded plugins:")
        for _, p in ipairs(plugins) do
            print(string.format("  %-20s v%-8s %s", p.name, p.version, p.description or ""))
        end
    end
end

print("")
print("Type vx.help() for commands, vx.plugin.list() for plugins")
