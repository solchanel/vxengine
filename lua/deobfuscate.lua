-- VXEngine Deobfuscation Helpers
-- Constant folding, opaque predicate detection, and pattern matching.

vx.log("Loading deobfuscation helpers...")

-- ============================================================
-- Opaque predicate scanner
-- Scans a range for conditional jumps and classifies each
-- ============================================================
function scan_predicates(start_addr, size)
    local results = {}
    local addr = start_addr
    local end_addr = start_addr + size

    while addr < end_addr do
        local dis = vx.disasm(addr)
        if dis == nil or dis == "" then
            addr = addr + 1
        else
            -- Check if this is a conditional jump
            local mnemonic = string.match(dis, "^(%w+)")
            if mnemonic and mnemonic:sub(1,1) == "j" and mnemonic ~= "jmp" then
                local result = "unknown"
                -- Use Z3 solver if available
                if vx.solve_predicate then
                    result = vx.solve_predicate(addr)
                end
                table.insert(results, {
                    addr = addr,
                    disasm = dis,
                    result = result
                })
                if result == "always_true" or result == "always_false" then
                    vx.log(string.format("  OPAQUE @ 0x%08X: %s -> %s",
                        addr, dis, result))
                end
            end
            addr = addr + 1 -- Simplified; real impl would parse instruction length
        end
    end

    vx.log(string.format("Scanned 0x%X bytes: %d conditional jumps found",
        size, #results))
    return results
end

-- ============================================================
-- Constant folding: detect push+arithmetic+pop patterns
-- ============================================================
function detect_const_fold(addr, max_insns)
    max_insns = max_insns or 20
    local insns = {}
    local cur = addr

    -- Collect instructions
    for i = 1, max_insns do
        local dis = vx.disasm(cur)
        if dis == nil or dis == "" then break end
        table.insert(insns, { addr = cur, disasm = dis })
        cur = cur + 1 -- Simplified
    end

    -- Pattern: look for sequences that push, do arithmetic, then pop
    -- These often compute a constant value in an obfuscated way
    local patterns_found = {}

    for i, insn in ipairs(insns) do
        local m = string.match(insn.disasm, "^push%s+(%w+)")
        if m then
            -- Found a push; look for matching pop
            for j = i + 1, math.min(i + 10, #insns) do
                local pop_reg = string.match(insns[j].disasm, "^pop%s+(%w+)")
                if pop_reg then
                    table.insert(patterns_found, {
                        start_addr = insn.addr,
                        end_addr = insns[j].addr,
                        push_reg = m,
                        pop_reg = pop_reg,
                        insn_count = j - i + 1
                    })
                    break
                end
            end
        end
    end

    return patterns_found
end

-- ============================================================
-- Dead code elimination: find unreachable code after opaque predicates
-- ============================================================
function find_dead_code(start_addr, size)
    local predicates = scan_predicates(start_addr, size)
    local dead_ranges = {}

    for _, pred in ipairs(predicates) do
        if pred.result == "always_true" then
            -- The fall-through path is dead
            vx.log(string.format("  Dead fall-through after 0x%08X", pred.addr))
            table.insert(dead_ranges, {
                addr = pred.addr,
                type = "dead_fallthrough",
                reason = "opaque_always_true"
            })
        elseif pred.result == "always_false" then
            -- The jump target is dead
            vx.log(string.format("  Dead jump target from 0x%08X", pred.addr))
            table.insert(dead_ranges, {
                addr = pred.addr,
                type = "dead_target",
                reason = "opaque_always_false"
            })
        end
    end

    vx.log(string.format("Found %d dead code regions", #dead_ranges))
    return dead_ranges
end

-- ============================================================
-- Pattern matcher: detect common obfuscation patterns
-- ============================================================
local patterns = {
    -- XOR self-decryption loop
    {
        name = "xor_decrypt_loop",
        desc = "XOR decryption loop",
        match = function(insns)
            for i = 1, #insns - 2 do
                local m1 = string.match(insns[i].disasm, "^xor%s+byte")
                local m2 = string.match(insns[i+1].disasm, "^inc%s") or
                           string.match(insns[i+1].disasm, "^add%s")
                local m3 = string.match(insns[i+2].disasm, "^loop") or
                           string.match(insns[i+2].disasm, "^j")
                if m1 and m2 and m3 then
                    return insns[i].addr
                end
            end
            return nil
        end
    },

    -- Stack-based constant computation
    {
        name = "stack_const",
        desc = "Stack-based constant obfuscation",
        match = function(insns)
            local push_count = 0
            for i = 1, math.min(#insns, 8) do
                if string.match(insns[i].disasm, "^push%s") then
                    push_count = push_count + 1
                end
            end
            return push_count >= 3 and insns[1].addr or nil
        end
    },

    -- Junk instruction insertion (NOPs, redundant moves)
    {
        name = "junk_insns",
        desc = "Junk instruction padding",
        match = function(insns)
            local junk_count = 0
            for _, insn in ipairs(insns) do
                local dis = insn.disasm
                if dis == "nop" or
                   string.match(dis, "^mov%s+(%w+),%s*(%1)$") or
                   string.match(dis, "^lea%s+(%w+),%s*%[%1%]") or
                   string.match(dis, "^xchg%s+(%w+),%s*(%1)$") then
                    junk_count = junk_count + 1
                end
            end
            return junk_count >= 3 and insns[1].addr or nil
        end
    },
}

function detect_patterns(addr, max_insns)
    max_insns = max_insns or 50
    local insns = {}
    local cur = addr

    for i = 1, max_insns do
        local dis = vx.disasm(cur)
        if dis == nil or dis == "" then break end
        table.insert(insns, { addr = cur, disasm = dis })
        cur = cur + 1
    end

    local found = {}
    for _, pattern in ipairs(patterns) do
        local match_addr = pattern.match(insns)
        if match_addr then
            table.insert(found, {
                addr = match_addr,
                name = pattern.name,
                desc = pattern.desc
            })
            vx.log(string.format("  Pattern '%s' at 0x%08X: %s",
                pattern.name, match_addr, pattern.desc))
        end
    end

    return found
end

vx.log("Deobfuscation helpers loaded")
