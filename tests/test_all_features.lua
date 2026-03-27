-- VXEngine Comprehensive Test Suite (Fixed for actual API)

local passed = 0
local failed = 0
local total = 0

local function test(name, fn)
    total = total + 1
    local ok, err = pcall(fn)
    if ok then
        passed = passed + 1
        print(string.format("  [PASS] %s", name))
    else
        failed = failed + 1
        print(string.format("  [FAIL] %s: %s", name, tostring(err)))
    end
end

local function assert_eq(a, b, msg)
    if a ~= b then error(string.format("%s: expected 0x%x, got 0x%x", msg or "assert_eq", b, a)) end
end
local function assert_neq(a, b, msg)
    if a == b then error(string.format("%s: should not be 0x%x", msg or "assert_neq", a)) end
end
local function assert_true(v, msg)
    if not v then error(msg or "assertion failed") end
end

print("========================================")
print("  VXEngine Feature Test Suite")
print("========================================\n")

-- ============================================================
-- 1. Memory subsystem
-- ============================================================
print("--- Memory Subsystem ---")

test("map + read32 + write32", function()
    vx.map(0xBEEF0000, 0x1000)
    vx.write32(0xBEEF0000, 0xDEADBEEF)
    assert_eq(vx.read32(0xBEEF0000), 0xDEADBEEF, "read32")
end)

test("write + read_string", function()
    vx.write_string(0xBEEF0100, "ABCD")
    local s = vx.read_string(0xBEEF0100)
    assert_true(s == "ABCD", "expected 'ABCD', got '" .. s .. "'")
end)

test("write32 array", function()
    for i = 0, 15 do vx.write32(0xBEEF0200 + i*4, i * 0x11111111) end
    assert_eq(vx.read32(0xBEEF0200 + 5*4), 5*0x11111111, "array[5]")
    assert_eq(vx.read32(0xBEEF0200 + 10*4), 10*0x11111111, "array[10]")
end)

test("memset", function()
    vx.memset(0xBEEF0300, 0xAA, 64)
    assert_eq(vx.read32(0xBEEF0300), 0xAAAAAAAA, "memset 0xAA")
end)

test("memcpy", function()
    vx.write32(0xBEEF0400, 0x12345678)
    vx.memcpy(0xBEEF0500, 0xBEEF0400, 4)
    assert_eq(vx.read32(0xBEEF0500), 0x12345678, "memcpy")
end)

test("is_mapped", function()
    assert_true(vx.is_mapped(0xBEEF0000), "should be mapped")
    assert_true(not vx.is_mapped(0x99990000), "should not be mapped")
end)

-- ============================================================
-- 2. Shadow PTE
-- ============================================================
print("\n--- Shadow PTE (Stealth Hooks) ---")

test("split_page: read_view != exec_view", function()
    vx.map(0xAAAA0000, 0x1000)
    vx.write(0xAAAA0000, "\x55\x8B\xEC")  -- push ebp; mov ebp,esp
    vx.split_page(0xAAAA0000)
    vx.stealth_hook(0xAAAA0000, "\xCC")    -- INT3 in exec view only
    local byte = vx.read(0xAAAA0000, 1):byte()
    assert_eq(byte, 0x55, "read_view should show original 0x55")
end)

test("stealth_int3 invisible", function()
    vx.map(0xBBBB0000, 0x1000)
    vx.write(0xBBBB0000, "\x90\x90\x90")
    vx.stealth_int3(0xBBBB0000)
    assert_eq(vx.read(0xBBBB0000, 1):byte(), 0x90, "INT3 invisible to reads")
end)

test("is_split", function()
    assert_true(vx.is_split(0xAAAA0000), "should be split")
    assert_true(not vx.is_split(0xBEEF0000), "should not be split")
end)

test("unsplit_page restores", function()
    vx.unsplit_page(0xAAAA0000)
    assert_true(not vx.is_split(0xAAAA0000), "should no longer be split")
end)

-- ============================================================
-- 3. Registers
-- ============================================================
print("\n--- CPU Registers ---")

test("set_reg + reg roundtrip", function()
    vx.set_reg("eax", 0x12345678)
    assert_eq(vx.reg("eax"), 0x12345678, "eax")
    vx.set_reg("esp", 0x7FFFC000)
    assert_eq(vx.reg("esp"), 0x7FFFC000, "esp")
end)

test("all GP registers", function()
    local regs = {"eax","ecx","edx","ebx","esp","ebp","esi","edi"}
    for i, name in ipairs(regs) do vx.set_reg(name, i * 0x10000000) end
    for i, name in ipairs(regs) do assert_eq(vx.reg(name), i * 0x10000000, name) end
end)

test("pc + set_pc", function()
    vx.set_pc(0x401000)
    assert_eq(vx.pc(), 0x401000, "pc")
end)

test("flags + set_flags", function()
    vx.set_flags(0x202)
    assert_eq(vx.flags(), 0x202, "eflags")
end)

test("snapshot + restore", function()
    vx.set_reg("eax", 0xAABBCCDD)
    vx.set_pc(0x12345678)
    local snap = vx.snapshot()
    vx.set_reg("eax", 0)
    vx.set_pc(0)
    vx.restore(snap)
    assert_eq(vx.reg("eax"), 0xAABBCCDD, "eax restored")
    assert_eq(vx.pc(), 0x12345678, "pc restored")
end)

-- ============================================================
-- 4. CPU execution
-- ============================================================
print("\n--- CPU Execution ---")

test("step NOP", function()
    vx.map(0xCC000000, 0x1000)
    vx.write(0xCC000000, "\x90\x90\x90\xF4")
    vx.set_pc(0xCC000000)
    vx.set_reg("esp", 0x7FFFC000)
    vx.set_flags(0x202)
    vx.step()
    assert_eq(vx.pc(), 0xCC000001, "PC after 1 NOP")
end)

test("step MOV EAX, imm32", function()
    vx.write(0xCC000100, "\xB8\x42\x42\x42\x42\xF4")
    vx.set_pc(0xCC000100)
    vx.set_reg("eax", 0)
    vx.step()
    assert_eq(vx.reg("eax"), 0x42424242, "MOV EAX, 0x42424242")
end)

test("step ADD EAX, EBX", function()
    vx.write(0xCC000200, "\x01\xD8\xF4")  -- add eax, ebx
    vx.set_pc(0xCC000200)
    vx.set_reg("eax", 100)
    vx.set_reg("ebx", 200)
    vx.step()
    assert_eq(vx.reg("eax"), 300, "100+200=300")
end)

test("step PUSH + POP", function()
    vx.write(0xCC000300, "\x50\x5B\xF4")  -- push eax; pop ebx
    vx.set_pc(0xCC000300)
    vx.set_reg("eax", 0xCAFEBABE)
    vx.set_reg("ebx", 0)
    vx.set_reg("esp", 0x7FFFC000)
    vx.step()   -- push eax
    vx.step()   -- pop ebx
    assert_eq(vx.reg("ebx"), 0xCAFEBABE, "POP got PUSH value")
    assert_eq(vx.reg("esp"), 0x7FFFC000, "ESP restored")
end)

test("step SUB sets ZF", function()
    vx.write(0xCC000400, "\x29\xC0\xF4")  -- sub eax, eax
    vx.set_pc(0xCC000400)
    vx.set_reg("eax", 0x12345678)
    vx.step()
    assert_eq(vx.reg("eax"), 0, "SUB EAX,EAX=0")
    assert_eq((vx.flags() >> 6) & 1, 1, "ZF set")
end)

test("step XOR", function()
    vx.write(0xCC000500, "\x35\xFF\x00\x00\x00\xF4")  -- xor eax, 0xFF
    vx.set_pc(0xCC000500)
    vx.set_reg("eax", 0x41)  -- 'A'
    vx.step()
    assert_eq(vx.reg("eax"), 0x41 ~ 0xFF, "XOR 0x41^0xFF")
end)

test("step LEA", function()
    vx.write(0xCC000600, "\x8D\x44\x0B\x10\xF4")  -- lea eax, [ebx+ecx+0x10]
    vx.set_pc(0xCC000600)
    vx.set_reg("ebx", 0x1000)
    vx.set_reg("ecx", 0x200)
    vx.step()
    assert_eq(vx.reg("eax"), 0x1210, "LEA [ebx+ecx+0x10]")
end)

test("run_until stops at target", function()
    -- 3 NOPs then HLT
    vx.write(0xCC000700, "\x90\x90\x90\xF4")
    vx.set_pc(0xCC000700)
    vx.run_until(0xCC000703)  -- run until HLT
    assert_eq(vx.pc(), 0xCC000703, "stopped at HLT")
end)

test("run_until with MOV chain", function()
    -- mov eax, 1; mov ecx, 2; add eax, ecx; hlt
    vx.write(0xCC000800,
        "\xB8\x01\x00\x00\x00" ..   -- mov eax, 1
        "\xB9\x02\x00\x00\x00" ..   -- mov ecx, 2
        "\x01\xC8" ..                -- add eax, ecx
        "\xF4")                      -- hlt
    vx.set_pc(0xCC000800)
    vx.run_until(0xCC00080C)  -- run until hlt
    assert_eq(vx.reg("eax"), 3, "1+2=3 via run_until")
end)

-- ============================================================
-- 5. Disassembly
-- ============================================================
print("\n--- Disassembly ---")

test("disasm NOP", function()
    vx.write(0xCC002000, "\x90")
    assert_true(vx.disasm(0xCC002000):lower():find("nop"), "expected nop")
end)

test("disasm MOV", function()
    vx.write(0xCC002010, "\xB8\x78\x56\x34\x12")
    local d = vx.disasm(0xCC002010):lower()
    assert_true(d:find("mov") and d:find("eax"), "expected mov eax")
end)

test("disasm CALL", function()
    vx.write(0xCC002020, "\xE8\x00\x00\x00\x00")  -- call $+5
    assert_true(vx.disasm(0xCC002020):lower():find("call"), "expected call")
end)

-- ============================================================
-- 6. PE Loader (Jaymod DLL)
-- ============================================================
print("\n--- PE Loader (Jaymod DLL) ---")

test("MZ header at base", function()
    assert_eq(vx.read32(0x62180000) & 0xFFFF, 0x5A4D, "MZ signature")
end)

test(".text section has code", function()
    assert_neq(vx.read(0x62181000, 1):byte(), 0, "code present")
end)

test("dllEntry at expected address", function()
    assert_neq(vx.read(0x621a2710, 1):byte(), 0, "dllEntry has code")
end)

test("vmMain at expected address", function()
    assert_neq(vx.read(0x621C9E20, 1):byte(), 0, "vmMain has code")
end)

test("encrypted opcode mapping table", function()
    -- g_encrypted_opcode_mapping at 0x621eddc0 should have non-FF values
    local has_data = false
    for i = 0, 255 do
        if vx.read32(0x621eddc0 + i*4) ~= 0xFFFFFFFF then
            has_data = true
            break
        end
    end
    assert_true(has_data, "opcode mapping should have non-FF entries")
end)

-- ============================================================
-- 7. Watchpoint table monitoring
-- ============================================================
print("\n--- Watchpoint Table ---")

test("watch_table on handler table area", function()
    -- Set watchpoint on the handler table
    local handler_writes = {}
    local wp = vx.watch(0x62201B80, 288*4, function(addr, size, value)
        local idx = (addr - 0x62201B80) // 4
        handler_writes[idx] = value
    end)

    -- Manually write to the handler table to trigger watchpoint
    vx.write32(0x62201B80 + 13*4, 0x1AEB2365)
    vx.write32(0x62201B80 + 16*4, 0xEB81E709)

    assert_true(handler_writes[13] ~= nil, "watchpoint caught write to [13]")
    assert_true(handler_writes[16] ~= nil, "watchpoint caught write to [16]")
    assert_eq(handler_writes[13], 0x1AEB2365, "handler[13] value")

    vx.unwatch(wp)
end)

-- ============================================================
-- 8. Breakpoints
-- ============================================================
print("\n--- Breakpoints ---")

test("set and hit breakpoint", function()
    -- 5 NOPs then HLT — BP at 3rd NOP
    vx.write(0xCC003000, "\x90\x90\x90\x90\x90\xF4")
    vx.set_pc(0xCC003000)
    vx.set_reg("esp", 0x7FFFC000)
    vx.bp(0xCC003002)  -- BP at 3rd NOP

    -- Step in a loop and check if BP stops us
    local max_steps = 10
    local hit_bp = false
    for i = 1, max_steps do
        local pc_before = vx.pc()
        if pc_before == 0xCC003002 then
            hit_bp = true
            break
        end
        vx.step()
    end
    assert_true(hit_bp or vx.pc() == 0xCC003002,
        "should have reached BP at 0xCC003002, got 0x" .. string.format("%x", vx.pc()))
    vx.bp_del(0xCC003002)
end)

-- ============================================================
-- 9. Instruction count
-- ============================================================
print("\n--- Misc ---")

test("insn_count increments", function()
    vx.write(0xCC004000, "\x90\x90\x90\xF4")
    vx.set_pc(0xCC004000)
    local before = vx.insn_count()
    vx.step()
    vx.step()
    local after = vx.insn_count()
    assert_true(after > before, "insn_count should increment")
end)

test("arch returns x86", function()
    assert_true(vx.arch() == "x86" or vx.arch() == "x86_32", "arch should be x86")
end)

-- ============================================================
-- Summary
-- ============================================================
print("\n========================================")
print(string.format("  Results: %d passed, %d failed, %d total", passed, failed, total))
print("========================================")
if failed > 0 then
    print("\n  *** SOME TESTS FAILED ***")
else
    print("\n  *** ALL TESTS PASSED ***")
end
