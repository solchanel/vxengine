# VXEngine

**Virtual Execution Engine for Obfuscated Binary Analysis**

[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Architectures](https://img.shields.io/badge/arch-x86%20|%20x64%20|%20ARM-green.svg)](#architecture-support)
[![Lua](https://img.shields.io/badge/scripting-Lua%205.4%20%2B%20sol2-purple.svg)](#lua-scripting)

VXEngine is a **pure C++17 binary analysis framework** designed to tackle the hardest reverse engineering targets: VM-protected, packed, and heavily obfuscated executables. It provides a custom CPU emulator with **invisible memory hooks**, **Z3-powered deobfuscation**, **full Windows/Linux environment emulation**, and a **Lua scripting engine** — all controllable by AI via a built-in **MCP server**.

---

## Highlights

- **Shadow PTE Memory** — EPT-style split-view pages where CPU instruction fetches see hooked code while data reads return original bytes. Hooks are completely invisible to integrity checks, CRC validation, and self-reading code.
- **Custom CPU Engine** — No Unicorn dependency. Full x86/x64/ARM interpreter with proper segment registers, FPU/SSE, anti-anti-debug, and overlapping instruction support. No Python marshalling bugs, no 32-bit counter overflow, no callback crashes.
- **390+ Emulated Windows APIs** — kernel32 (A/W/Ex variants), ntdll (NtQuery*, Rtl*, Ldr*), ntoskrnl (ExAllocatePool, IoCreateDevice, Ke*), CRT, syscall interception, and DeviceIoControl — all extensible via Lua plugins.
- **Z3 Solver Integration** — Automatic opaque predicate detection, constant folding for obfuscated computations (`push IMM; add [esp],IMM; pop eax; sub eax,IMM` → single concrete value), and encrypted blob decryption with symbolic key recovery.
- **AI-Driven Debugging** — Built-in MCP (Model Context Protocol) server exposes 16 tools that let Claude or any AI agent load binaries, set breakpoints, trace execution, install stealth hooks, and run Z3 deobfuscation — all through natural language.
- **Lua Scripting (sol2)** — 88+ API functions exposed to Lua. Write custom API stubs, analysis passes, VM handler extractors, and unpackers without recompiling. Full plugin system with event hooks and REPL commands.

---

## Quick Example

### Interactive REPL
```
$ vxengine -a x86 target.dll
VXEngine v1.0 [x86-32]

vx> vx.load("target.dll")
[+] Loaded at 0x10000000 (5 sections, 42 imports)

vx> vx.step()
vx> vx.disasm(vx.pc())
"push ebp"

vx> vx.set_reg("eax", 0x42)
vx> vx.run_until(0x10001050)
[*] Stopped at 0x10001050 (1337 instructions)

vx> regs()
  EAX=00000042  ECX=00000000  EDX=00000000  EBX=00000000
  ESP=7FFFC000  EBP=7FFFC200  ESI=00000000  EDI=00000000
```

### Stealth Hooks (Invisible to Target)
```lua
-- Split a code page into execute-view and read-view
vx.split_page(0x401000)

-- Install a JMP hook that the target can't see
vx.stealth_hook(0x401000, "\xE9\x00\x10\x00\x00")

-- Target reading its own code sees original bytes:
assert(vx.read(0x401000, 1):byte() == 0x55)  -- Still shows 'push ebp'
-- But CPU executing at 0x401000 takes the JMP hook!
```

### VM Handler Table Extraction
```lua
-- Watch a dispatch table for writes during initialization
local handlers = {}
vx.watch(0x62201B80, 288 * 4, function(addr, size, value)
    local idx = (addr - 0x62201B80) // 4
    handlers[idx] = value
    vx.log(string.format("handler[%d] = 0x%08x", idx, value))
end)

-- Run DLL initialization
vx.run_init()
-- All 288 handler registrations captured via watchpoint!
```

### Z3 Deobfuscation
```lua
-- Detect opaque predicates
local result = vx.solve_predicate(0x621c8de7)
-- Returns: "always_true" → dead branch, can be NOPed

-- Simplify obfuscated constant computation
-- push 0xA0F908DE; add [esp],0x40B5F50D; pop eax; sub eax,0x7F92610B
local value = vx.fold_constant(0x621c9cc0)
-- Resolves to: eax = 0x621C9CE0
```

### Kernel Driver Analysis
```lua
-- Load a Windows kernel driver
local mod = vx.load("rootkit.sys")

-- Set up kernel environment (DRIVER_OBJECT, DEVICE_OBJECT)
-- Call DriverEntry and capture the IRP dispatch table
vx.run_driver_entry()

-- Send a fake IOCTL to the driver
vx.dispatch_ioctl(0x222003, input_buf, input_size)
```

### AI-Driven Debugging (MCP)
```
$ vxengine -a x86 -m -p 13370 target.dll
[*] MCP server on port 13370 — connect Claude Code or any MCP client
```

Then from Claude:
```
Claude: Let me load the binary and extract the VM handlers...
[calls vx_load("target.dll")]
[calls vx_watch(0x62201B80, 1152)]
[calls vx_run_until(0xDEAD0000)]
[calls vx_dump_table(0x62201B80, 288)]
→ All 288 handler entries captured
[calls vx_deobfuscate(handler_addr)]
→ Simplified logic for each handler
```

---

## Architecture Support

| Architecture | Mode | Decoder | Instructions | FPU/SIMD | Status |
|:-------------|:-----|:--------|:-------------|:---------|:-------|
| **x86** | 32-bit | Capstone | 200+ (full GP, string, bit, CMOVcc, SETcc) | x87 + SSE/SSE2
| **x64** | 64-bit | Capstone | x86 + MOVSXD, SYSCALL, RIP-relative, R8-R15 | x87 + 16×XMM
| **ARM** | ARM + Thumb | Capstone | Data processing, multiply, load/store, block, branch, VFP | VFP S0-S31/D0-D31

---

## Core Features

### Shadow PTE — Invisible Memory Hooks

Inspired by Intel EPT (Extended Page Tables), VXEngine implements dual-view memory pages:

| Operation | What Target Sees | What CPU Executes |
|:----------|:-----------------|:------------------|
| `vx.read(addr)` | Original bytes ✓ | — |
| Instruction fetch | — | Hooked code (JMP, INT3, etc.) |
| CRC/hash check | Passes ✓ (reads original) | — |
| `VirtualQuery` | Fake attributes ✓ | — |

This defeats all common integrity checks: code CRC, IAT verification, self-hash validation, and `VirtualQuery`-based protection detection.

### Custom CPU Engine — No Unicorn

| Feature | Unicorn | VXEngine |
|:--------|:--------|:---------|
| Memory hooks | Crash on 64-bit Python | Native C++ — zero bugs |
| Segment registers | Broken (SS, FS, GS) | Full GDT/LDT support |
| Instruction counter | 32-bit overflow | 64-bit native |
| Overlapping instructions | IR lifting fails | Byte-level fetch at PC |
| Per-instruction hooks | 10× slowdown | Block-level, near-zero cost |
| `push ss; pop ss` | Exception/crash | Correct behavior + TF suppression |
| FPU state in hooks | Clobbered | First-class, never lost |
| Thread support | None | Full thread manager |

### Windows Environment Emulation

- **TEB/PEB** with realistic values (BeingDebugged=0, NtGlobalFlag=0)
- **GDT** with FS→TEB for `mov eax, fs:[0x18]` self-pointer
- **Process heap** with bump allocator
- **PEB_LDR_DATA** with linked module list
- **SEH/VEH** exception chain walking
- **Thread manager** with cooperative/preemptive scheduling

### API Coverage (~390 functions)

| Module | Count | Key Functions |
|:-------|:------|:-------------|
| kernel32.dll | ~250 | All A/W/Ex variants, memory, thread, sync, file, string, atom, environment |
| ntdll.dll | ~40 | NtQuery*, NtAllocate*, Rtl*, Ldr*, anti-debug bypass |
| ntoskrnl.exe | ~70 | ExAllocatePool, IoCreateDevice, KeWaitFor*, Zw*, process/thread |
| msvcrt | ~20 | malloc, memcpy, strlen, sprintf, atoi |
| Syscalls | 7+ | NtAllocateVirtualMemory, NtClose, NtCreateFile... |
| IOCTL | Extensible | DeviceIoControl with METHOD_BUFFERED/DIRECT |

Plus **unlimited custom stubs** via Lua:
```lua
vx.api("MyCustomDLL.dll", "SecretFunction", function(arg1, arg2)
    return 42
end)
```

### Exception-Driven Execution

Full SEH/VEH emulation for VM protectors that transfer control via exceptions:

- INT3 breakpoint → handler dispatches next VM opcode
- Access violation on guard pages → handler unpacks code
- Division by zero → handler computes alternative result
- Invalid opcode → handler emulates custom instruction
- Single-step (TF) → handler advances VM state

### Lua Plugin System

```lua
vx.plugin.register({
    name = "my_analyzer",
    version = "1.0",
    init = function() vx.log("Ready!") end,
})

-- Custom API stubs
vx.plugin.api("kernel32.dll", "GetTickCount", function() return 100000 end)

-- Event hooks
vx.plugin.on("breakpoint", function(addr) vx.log("Hit: " .. vx.hex(addr)) end)

-- REPL commands
vx.plugin.command("scan", "Scan for pattern", function(args) --[[ ... ]] end)
```

### MCP Server — AI as Debugger

The built-in MCP server exposes **16 debugging tools** over HTTP/JSON-RPC:

| Tool | Description |
|:-----|:-----------|
| `vx_load` | Load PE/ELF binary |
| `vx_step` | Single-step, returns register + memory delta |
| `vx_run_until` | Run to address with full trace |
| `vx_regs` | Dump all registers |
| `vx_mem_read` / `vx_mem_write` | Read/write emulated memory |
| `vx_disasm` | Disassemble at address |
| `vx_breakpoint` | Set/remove breakpoints |
| `vx_watch` | Monitor memory range for writes |
| `vx_trace` | Trace N instructions with state |
| `vx_deobfuscate` | Z3 constant folding + opaque predicate removal |
| `vx_solve` | Solve symbolic constraints |
| `vx_split_page` | Create invisible hook page |
| `vx_stealth_hook` | Install hook invisible to target |
| `vx_lua` | Execute arbitrary Lua in engine context |
| `vx_dump_table` | Watch + dump function pointer table |

Connect any MCP-compatible AI (Claude Code, etc.) to `http://localhost:13370/mcp` and let it drive the entire analysis session.

---

## Building

### Prerequisites

- **CMake** 3.20+
- **C++17 compiler** (MSVC 2019+, GCC 9+, Clang 10+)

### Clone & Build

```bash
git clone https://github.com/user/vxengine.git
cd vxengine

# Clone dependencies
cd third_party
git clone --depth 1 https://github.com/capstone-engine/capstone.git
git clone --depth 1 --branch v5.4.6 https://github.com/lua/lua.git
git clone --depth 1 --branch v3.3.0 https://github.com/ThePhD/sol2.git
git clone --depth 1 https://github.com/yhirose/cpp-httplib.git
cd ..

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release -j8
```

### Build Options

| Option | Default | Description |
|:-------|:--------|:-----------|
| `VX_ENABLE_Z3` | `ON` | Enable Z3 SMT solver for deobfuscation |
| `VX_BUILD_MCP` | `ON` | Build MCP server for AI integration |
| `VX_BUILD_TESTS` | `ON` | Build unit tests |
| `VX_ENABLE_JIT` | `OFF` | Enable JIT compiler (experimental) |

### Optional: Z3 Solver

```bash
cd third_party
git clone --depth 1 --branch z3-4.13.0 https://github.com/Z3Prover/z3.git
cd ..
cmake .. -DVX_ENABLE_Z3=ON
```

---

## Usage

### Command Line

```bash
# Interactive REPL
vxengine -a x86 target.dll

# Run a Lua analysis script
vxengine -a x86 -s analyze.lua target.dll

# With MCP server for AI debugging
vxengine -a x86 -m -p 13370 target.dll

# ARM binary
vxengine -a arm firmware.elf
```

### As a C++ Library

```cpp
#include <vxengine/vxengine.h>
#include <vxengine/engine.h>

vx::VXEngine engine(vx::Arch::X86_32);
auto mod = engine.load("target.dll");
engine.run_dll_init(mod);

// Set watchpoint on handler table
engine.watch_table(0x62201B80, 288);

// Step through code
auto result = engine.cpu().step();
printf("EIP: 0x%08x  EAX: 0x%08x\n", result.addr, engine.cpu().reg(vx::X86_EAX));
```
---

## Contributing

Contributions are welcome! Areas of interest:

- **JIT compiler** for 50-100× speedup on straight-line code
- **ARM64 (AArch64)** backend
- **Linux environment** emulation (libc, ld.so, /proc)
- **Additional API stubs** (user32, advapi32, ws2_32, etc.)
- **IDA Pro plugin** for seamless integration
- **Ghidra bridge** for P-Code correlation

---

## License

VXEngine is released under the **BSD 3-Clause License**. See [LICENSE](LICENSE) for details.

Third-party components:
- [Capstone](https://github.com/capstone-engine/capstone) — BSD License
- [Lua](https://www.lua.org/) — MIT License
- [sol2](https://github.com/ThePhD/sol2) — MIT License
- [cpp-httplib](https://github.com/yhirose/cpp-httplib) — MIT License
- [Z3](https://github.com/Z3Prover/z3) — MIT License (optional)
