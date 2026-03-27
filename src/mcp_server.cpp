/**
 * VXEngine MCP (Model Context Protocol) Server
 *
 * HTTP server exposing engine tools via JSON-RPC for AI-driven debugging.
 * Uses cpp-httplib (single header HTTP library).
 *
 * Endpoints:
 *   POST /mcp/tools/list  -> return tool manifest
 *   POST /mcp/tools/call  -> dispatch to tool handler
 *
 * Tools:
 *   vx_load, vx_step, vx_run_until, vx_regs, vx_mem_read, vx_mem_write,
 *   vx_disasm, vx_breakpoint, vx_watch, vx_trace, vx_deobfuscate,
 *   vx_solve, vx_split_page, vx_stealth_hook, vx_lua, vx_dump_table
 */

#ifdef VX_MCP_SERVER

#include <httplib.h>
#endif

#include "vxengine/engine.h"
#include "vxengine/tracer.h"
#include "vxengine/cpu/x86/x86_cpu.h"
#ifdef VX_ENABLE_Z3
#include "vxengine/solver.h"
#endif

#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <mutex>
#include <iostream>
#include <functional>
#include <map>
#include <vector>

namespace vx {

// ============================================================
// Minimal JSON helpers (no external dependency)
// ============================================================

static std::string json_string(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    out += "\"";
    return out;
}

static std::string json_num(uint64_t val) {
    return std::to_string(val);
}

static std::string json_hex(uint64_t val) {
    std::ostringstream ss;
    ss << "\"0x" << std::hex << val << "\"";
    return ss.str();
}

static std::string json_bool(bool val) {
    return val ? "true" : "false";
}

// Simple JSON value extraction (key from {"key": value, ...} flat object)
static std::string json_get_string(const std::string& json, const std::string& key) {
    std::string needle = "\"" + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return "";

    // Skip whitespace
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;

    if (pos >= json.size()) return "";

    if (json[pos] == '"') {
        // String value
        auto end = json.find('"', pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    }

    // Number or other value
    auto end = json.find_first_of(",} \t\n\r", pos);
    if (end == std::string::npos) end = json.size();
    return json.substr(pos, end - pos);
}

static uint64_t json_get_uint64(const std::string& json, const std::string& key) {
    std::string val = json_get_string(json, key);
    if (val.empty()) return 0;
    if (val.substr(0, 2) == "0x" || val.substr(0, 2) == "0X") {
        return std::stoull(val, nullptr, 16);
    }
    return std::stoull(val, nullptr, 0);
}

static int json_get_int(const std::string& json, const std::string& key) {
    std::string val = json_get_string(json, key);
    if (val.empty()) return 0;
    return std::stoi(val, nullptr, 0);
}

// ============================================================
// Tool manifest
// ============================================================

static std::string build_tool_manifest() {
    std::ostringstream ss;
    ss << "{\"tools\":[";

    auto tool = [&](const std::string& name, const std::string& desc,
                    const std::string& params, bool last = false) {
        ss << "{\"name\":" << json_string(name)
           << ",\"description\":" << json_string(desc)
           << ",\"inputSchema\":{\"type\":\"object\",\"properties\":{"
           << params << "}}}";
        if (!last) ss << ",";
    };

    tool("vx_load", "Load a PE/ELF binary into the emulator",
         "\"path\":{\"type\":\"string\",\"description\":\"File path to load\"}");

    tool("vx_step", "Single-step one instruction",
         "\"count\":{\"type\":\"integer\",\"description\":\"Number of steps (default 1)\"}");

    tool("vx_run_until", "Run until a specific address",
         "\"addr\":{\"type\":\"string\",\"description\":\"Target address (hex)\"},"
         "\"max_insns\":{\"type\":\"integer\",\"description\":\"Max instructions\"}");

    tool("vx_regs", "Get all CPU register values", "");

    tool("vx_mem_read", "Read memory bytes",
         "\"addr\":{\"type\":\"string\",\"description\":\"Address (hex)\"},"
         "\"size\":{\"type\":\"integer\",\"description\":\"Bytes to read\"}");

    tool("vx_mem_write", "Write memory bytes",
         "\"addr\":{\"type\":\"string\",\"description\":\"Address (hex)\"},"
         "\"data\":{\"type\":\"string\",\"description\":\"Hex bytes to write\"}");

    tool("vx_disasm", "Disassemble at address",
         "\"addr\":{\"type\":\"string\",\"description\":\"Address (hex)\"},"
         "\"count\":{\"type\":\"integer\",\"description\":\"Number of instructions\"}");

    tool("vx_breakpoint", "Set or remove a breakpoint",
         "\"addr\":{\"type\":\"string\",\"description\":\"Address (hex)\"},"
         "\"remove\":{\"type\":\"boolean\",\"description\":\"Remove if true\"}");

    tool("vx_watch", "Set a memory watchpoint",
         "\"addr\":{\"type\":\"string\",\"description\":\"Address (hex)\"},"
         "\"size\":{\"type\":\"integer\",\"description\":\"Watch size in bytes\"}");

    tool("vx_trace", "Trace execution and return instruction log",
         "\"addr\":{\"type\":\"string\",\"description\":\"Run until address\"},"
         "\"max_insns\":{\"type\":\"integer\",\"description\":\"Max instructions\"}");

    tool("vx_deobfuscate", "Analyze opaque predicates in address range",
         "\"addr\":{\"type\":\"string\",\"description\":\"Start address\"},"
         "\"size\":{\"type\":\"integer\",\"description\":\"Range size\"}");

    tool("vx_solve", "Solve for encrypted value or opaque predicate",
         "\"type\":{\"type\":\"string\",\"description\":\"predicate|handler|blob\"},"
         "\"addr\":{\"type\":\"string\",\"description\":\"Target address\"}");

    tool("vx_split_page", "Create shadow PTE split-view page",
         "\"addr\":{\"type\":\"string\",\"description\":\"Page address\"}");

    tool("vx_stealth_hook", "Install invisible stealth hook",
         "\"addr\":{\"type\":\"string\",\"description\":\"Hook address\"},"
         "\"bytes\":{\"type\":\"string\",\"description\":\"Hook bytes (hex)\"}");

    tool("vx_lua", "Execute Lua code in the engine",
         "\"code\":{\"type\":\"string\",\"description\":\"Lua code to execute\"}");

    tool("vx_dump_table", "Read a table of values from memory",
         "\"addr\":{\"type\":\"string\",\"description\":\"Table address\"},"
         "\"count\":{\"type\":\"integer\",\"description\":\"Entry count\"},"
         "\"entry_size\":{\"type\":\"integer\",\"description\":\"Entry size (4 or 8)\"}",
         true /* last */);

    ss << "]}";
    return ss.str();
}

// ============================================================
// Tool dispatch
// ============================================================

using ToolHandler = std::function<std::string(VXEngine& engine,
                                               const std::string& params)>;

static std::map<std::string, ToolHandler>& tool_handlers() {
    static std::map<std::string, ToolHandler> handlers;
    return handlers;
}

static void register_tool(const std::string& name, ToolHandler handler) {
    tool_handlers()[name] = std::move(handler);
}

static void register_all_tools() {
    // vx_load
    register_tool("vx_load", [](VXEngine& engine, const std::string& params) {
        std::string path = json_get_string(params, "path");
        if (path.empty()) {
            return std::string("{\"error\":\"Missing path parameter\"}");
        }
        try {
            LoadedModule mod = engine.load(path);
            std::ostringstream ss;
            ss << "{\"name\":" << json_string(mod.name)
               << ",\"base\":" << json_hex(mod.base)
               << ",\"size\":" << json_hex(mod.size)
               << ",\"entry\":" << json_hex(mod.entry_point)
               << ",\"sections\":" << json_num(mod.sections.size())
               << ",\"imports\":" << json_num(mod.imports.size())
               << ",\"exports\":" << json_num(mod.exports.size())
               << "}";
            return ss.str();
        } catch (const std::exception& e) {
            return std::string("{\"error\":") + json_string(e.what()) + "}";
        }
    });

    // vx_step
    register_tool("vx_step", [](VXEngine& engine, const std::string& params) {
        int count = json_get_int(params, "count");
        if (count <= 0) count = 1;

        std::ostringstream ss;
        ss << "{\"steps\":[";
        for (int i = 0; i < count; ++i) {
            if (i > 0) ss << ",";
            StepResult r = engine.step();
            ss << "{\"addr\":" << json_hex(r.addr)
               << ",\"disasm\":" << json_string(r.disasm)
               << ",\"reason\":" << json_num(static_cast<int>(r.reason))
               << "}";
        }
        ss << "]}";
        return ss.str();
    });

    // vx_run_until
    register_tool("vx_run_until", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        uint64_t max_insns = json_get_uint64(params, "max_insns");

        RunResult r = engine.run_until(addr, max_insns);

        std::ostringstream ss;
        ss << "{\"reason\":" << json_num(static_cast<int>(r.reason))
           << ",\"stop_addr\":" << json_hex(r.stop_addr)
           << ",\"insn_count\":" << json_num(r.insn_count)
           << "}";
        return ss.str();
    });

    // vx_regs
    register_tool("vx_regs", [](VXEngine& engine, const std::string&) {
        RegSnapshot snap = engine.cpu().snapshot();
        std::ostringstream ss;
        ss << "{\"eax\":" << json_hex(snap.rax)
           << ",\"ecx\":" << json_hex(snap.rcx)
           << ",\"edx\":" << json_hex(snap.rdx)
           << ",\"ebx\":" << json_hex(snap.rbx)
           << ",\"esp\":" << json_hex(snap.rsp)
           << ",\"ebp\":" << json_hex(snap.rbp)
           << ",\"esi\":" << json_hex(snap.rsi)
           << ",\"edi\":" << json_hex(snap.rdi)
           << ",\"eip\":" << json_hex(snap.rip)
           << ",\"eflags\":" << json_hex(snap.eflags)
           << "}";
        return ss.str();
    });

    // vx_mem_read
    register_tool("vx_mem_read", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        int size = json_get_int(params, "size");
        if (size <= 0) size = 16;
        if (size > 4096) size = 4096;

        std::string buf(size, '\0');
        bool ok = engine.memory().read(addr, buf.data(), size);
        if (!ok) {
            return std::string("{\"error\":\"Read failed\"}");
        }

        std::ostringstream ss;
        ss << "{\"addr\":" << json_hex(addr) << ",\"hex\":\"";
        for (int i = 0; i < size; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0')
               << (static_cast<unsigned>(buf[i]) & 0xFF);
        }
        ss << "\",\"ascii\":\"";
        for (int i = 0; i < size; ++i) {
            char c = buf[i];
            if (c >= 32 && c < 127) ss << c;
            else ss << '.';
        }
        ss << "\"}";
        return ss.str();
    });

    // vx_mem_write
    register_tool("vx_mem_write", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        std::string hex_data = json_get_string(params, "data");

        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex_data.size(); i += 2) {
            bytes.push_back(static_cast<uint8_t>(
                std::stoul(hex_data.substr(i, 2), nullptr, 16)));
        }

        bool ok = engine.memory().write(addr, bytes.data(), bytes.size());
        return std::string("{\"success\":") + json_bool(ok) + "}";
    });

    // vx_disasm
    register_tool("vx_disasm", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        int count = json_get_int(params, "count");
        if (count <= 0) count = 10;
        if (count > 100) count = 100;

        if (addr == 0) addr = engine.cpu().pc();

        std::ostringstream ss;
        ss << "{\"instructions\":[";
        uint64_t cur = addr;
        for (int i = 0; i < count; ++i) {
            if (i > 0) ss << ",";
            std::string dis = engine.cpu().disasm(cur);
            ss << "{\"addr\":" << json_hex(cur)
               << ",\"disasm\":" << json_string(dis) << "}";
            // Advance by estimated instruction size (simplified)
            cur += 1; // In a real impl, we'd parse instruction length
        }
        ss << "]}";
        return ss.str();
    });

    // vx_breakpoint
    register_tool("vx_breakpoint", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        std::string remove_str = json_get_string(params, "remove");
        bool remove = (remove_str == "true");

        if (remove) {
            engine.cpu().remove_breakpoint(addr);
        } else {
            engine.cpu().add_breakpoint(addr);
        }
        return std::string("{\"success\":true,\"addr\":") + json_hex(addr) + "}";
    });

    // vx_watch
    register_tool("vx_watch", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        int size = json_get_int(params, "size");
        if (size <= 0) size = 4;

        HookID id = engine.memory().add_watchpoint(addr, size,
            [addr](uint64_t a, uint32_t s, uint64_t val, AccessType type) -> bool {
                std::cout << "[watch] 0x" << std::hex << a
                          << " = 0x" << val << "\n";
                return true;
            }, AccessType::WRITE);

        return std::string("{\"watchpoint_id\":") + json_num(id) + "}";
    });

    // vx_trace
    register_tool("vx_trace", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        uint64_t max_insns = json_get_uint64(params, "max_insns");
        if (max_insns == 0) max_insns = 1000;

        auto entries = engine.tracer().run_until(addr, max_insns);

        std::ostringstream ss;
        ss << "{\"count\":" << json_num(entries.size()) << ",\"trace\":[";
        for (size_t i = 0; i < entries.size() && i < 200; ++i) {
            if (i > 0) ss << ",";
            ss << "{\"addr\":" << json_hex(entries[i].addr)
               << ",\"disasm\":" << json_string(entries[i].disasm);
            if (!entries[i].simplified.empty()) {
                ss << ",\"simplified\":" << json_string(entries[i].simplified);
            }
            if (!entries[i].predicate_note.empty()) {
                ss << ",\"predicate\":" << json_string(entries[i].predicate_note);
            }
            ss << "}";
        }
        ss << "]}";
        return ss.str();
    });

    // vx_deobfuscate
    register_tool("vx_deobfuscate", [](VXEngine& engine, const std::string& params) {
#ifdef VX_ENABLE_Z3
        uint64_t addr = json_get_uint64(params, "addr");
        // Analyze opaque predicate at the given address
        PredicateResult pr = engine.solver().solve_opaque_predicate(addr);
        std::string result;
        switch (pr) {
            case PredicateResult::ALWAYS_TRUE:  result = "always_true"; break;
            case PredicateResult::ALWAYS_FALSE: result = "always_false"; break;
            case PredicateResult::INPUT_DEPENDENT: result = "input_dependent"; break;
            case PredicateResult::UNKNOWN:      result = "unknown"; break;
        }
        return std::string("{\"addr\":") + json_hex(addr) +
               ",\"result\":" + json_string(result) + "}";
#else
        return std::string("{\"error\":\"Z3 solver not enabled\"}");
#endif
    });

    // vx_solve
    register_tool("vx_solve", [](VXEngine& engine, const std::string& params) {
#ifdef VX_ENABLE_Z3
        std::string type = json_get_string(params, "type");
        uint64_t addr = json_get_uint64(params, "addr");

        if (type == "predicate") {
            PredicateResult pr = engine.solver().solve_opaque_predicate(addr);
            std::string r;
            switch (pr) {
                case PredicateResult::ALWAYS_TRUE:  r = "always_true"; break;
                case PredicateResult::ALWAYS_FALSE: r = "always_false"; break;
                case PredicateResult::INPUT_DEPENDENT: r = "input_dependent"; break;
                case PredicateResult::UNKNOWN:      r = "unknown"; break;
            }
            return std::string("{\"type\":\"predicate\",\"result\":") +
                   json_string(r) + "}";
        }

        return std::string("{\"error\":\"Unknown solve type: ") + type + "\"}";
#else
        return std::string("{\"error\":\"Z3 solver not enabled\"}");
#endif
    });

    // vx_split_page
    register_tool("vx_split_page", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        bool ok = engine.memory().split_page(addr);
        return std::string("{\"success\":") + json_bool(ok) +
               ",\"addr\":" + json_hex(addr) + "}";
    });

    // vx_stealth_hook
    register_tool("vx_stealth_hook", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        std::string hex_bytes = json_get_string(params, "bytes");

        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex_bytes.size(); i += 2) {
            bytes.push_back(static_cast<uint8_t>(
                std::stoul(hex_bytes.substr(i, 2), nullptr, 16)));
        }

        bool ok = engine.memory().install_stealth_hook(addr, bytes);
        return std::string("{\"success\":") + json_bool(ok) + "}";
    });

    // vx_lua
    register_tool("vx_lua", [](VXEngine& engine, const std::string& params) {
        std::string code = json_get_string(params, "code");
        if (code.empty()) {
            return std::string("{\"error\":\"Missing code parameter\"}");
        }

        try {
            auto result = engine.lua().safe_script(code, sol::script_pass_on_error);
            if (!result.valid()) {
                sol::error err = result;
                return std::string("{\"error\":") + json_string(err.what()) + "}";
            }

            // Try to extract result
            if (result.return_count() > 0) {
                sol::object obj = result.get<sol::object>(0);
                if (obj.is<std::string>()) {
                    return std::string("{\"result\":") +
                           json_string(obj.as<std::string>()) + "}";
                } else if (obj.is<uint64_t>()) {
                    return std::string("{\"result\":") +
                           json_num(obj.as<uint64_t>()) + "}";
                } else if (obj.is<bool>()) {
                    return std::string("{\"result\":") +
                           json_bool(obj.as<bool>()) + "}";
                }
            }
            return std::string("{\"result\":null}");
        } catch (const std::exception& e) {
            return std::string("{\"error\":") + json_string(e.what()) + "}";
        }
    });

    // vx_dump_table
    register_tool("vx_dump_table", [](VXEngine& engine, const std::string& params) {
        uint64_t addr = json_get_uint64(params, "addr");
        int count = json_get_int(params, "count");
        int entry_size = json_get_int(params, "entry_size");
        if (count <= 0) count = 16;
        if (entry_size != 8) entry_size = 4;

        std::ostringstream ss;
        ss << "{\"addr\":" << json_hex(addr)
           << ",\"count\":" << json_num(count)
           << ",\"entries\":[";
        for (int i = 0; i < count; ++i) {
            if (i > 0) ss << ",";
            uint64_t val = 0;
            if (entry_size == 4) {
                val = engine.memory().read32(addr + i * 4);
            } else {
                val = engine.memory().read64(addr + i * 8);
            }
            ss << json_hex(val);
        }
        ss << "]}";
        return ss.str();
    });
}

// ============================================================
// MCP Server entry point
// ============================================================

#ifdef VX_MCP_SERVER

static std::mutex engine_mutex;

void start_mcp_server(VXEngine& engine, int port) {
    register_all_tools();

    auto server = std::make_shared<httplib::Server>();

    // CORS headers for browser-based clients
    server->set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "POST, GET, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"},
    });

    // OPTIONS preflight
    server->Options(".*", [](const httplib::Request&, httplib::Response& res) {
        res.status = 204;
    });

    // Tool listing
    server->Post("/mcp/tools/list", [](const httplib::Request&,
                                        httplib::Response& res) {
        res.set_content(build_tool_manifest(), "application/json");
    });

    // Tool dispatch
    server->Post("/mcp/tools/call", [&engine](const httplib::Request& req,
                                               httplib::Response& res) {
        std::string body = req.body;
        std::string tool_name = json_get_string(body, "name");

        // Extract params sub-object (simplified: just pass the whole body)
        std::string params_str = body; // In a real impl, extract "params" field

        auto& handlers = tool_handlers();
        auto it = handlers.find(tool_name);
        if (it == handlers.end()) {
            res.set_content("{\"error\":\"Unknown tool: " + tool_name + "\"}",
                           "application/json");
            return;
        }

        std::lock_guard<std::mutex> lock(engine_mutex);
        try {
            std::string result = it->second(engine, params_str);
            res.set_content(result, "application/json");
        } catch (const std::exception& e) {
            std::string err = "{\"error\":" + json_string(e.what()) + "}";
            res.set_content(err, "application/json");
        }
    });

    // Health check
    server->Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("{\"status\":\"ok\",\"engine\":\"vxengine\","
                        "\"version\":\"1.0.0\"}", "application/json");
    });

    // Run server in background thread
    std::thread([server, port]() {
        std::cout << "[mcp] Server listening on http://localhost:" << port << "\n";
        std::cout << "[mcp] Tools endpoint: POST /mcp/tools/call\n";
        server->listen("0.0.0.0", port);
    }).detach();
}

#else // !VX_MCP_SERVER

void start_mcp_server(VXEngine& /*engine*/, int /*port*/) {
    std::cerr << "[mcp] MCP server not compiled (VX_MCP_SERVER not defined)\n";
    std::cerr << "[mcp] Rebuild with -DVX_MCP_SERVER=1 to enable\n";
}

#endif // VX_MCP_SERVER

} // namespace vx
