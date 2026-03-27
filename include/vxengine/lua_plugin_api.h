#pragma once
/**
 * VXEngine Lua Plugin API
 *
 * Unified API for registering Lua plugins/extensions.
 * All plugins go through this API to register:
 *   - Custom API stubs (Windows/Linux/custom)
 *   - Analysis passes (deobfuscation, VM detection, etc.)
 *   - Event handlers (on_step, on_breakpoint, on_load, etc.)
 *   - Custom commands for the REPL
 *
 * Plugins are .lua files in the lua/ directory.
 * They are loaded via vx.plugin.load("name") or auto-loaded from lua/init.lua.
 *
 * Usage from Lua:
 *   -- Register a plugin
 *   vx.plugin.register({
 *       name = "my_plugin",
 *       version = "1.0",
 *       description = "Does cool stuff",
 *       author = "me",
 *       init = function() ... end,     -- Called on plugin load
 *       shutdown = function() ... end,  -- Called on plugin unload
 *   })
 *
 *   -- Register an API stub
 *   vx.plugin.api("kernel32.dll", "MyFunction", function(arg1, arg2)
 *       return 0
 *   end)
 *
 *   -- Register an event handler
 *   vx.plugin.on("step", function(addr, disasm)
 *       if addr == 0x401000 then vx.log("Hit target!") end
 *   end)
 *
 *   -- Register a REPL command
 *   vx.plugin.command("dump_handlers", "Dump all VM handler entries", function(args)
 *       for i = 0, 287 do
 *           local val = vx.read32(0x62201B80 + i * 4)
 *           if val ~= 0xFFFFFFFF then
 *               vx.log(string.format("  handler[%d] = 0x%08x", i, val))
 *           end
 *       end
 *   end)
 */

#include "vxengine.h"
#include <string>
#include <vector>
#include <functional>
#include <map>

// Forward declare sol types to avoid including sol2 in the header
namespace sol { class state; }

namespace vx {

// Plugin metadata
struct PluginInfo {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    bool loaded = false;
};

// Event types that plugins can subscribe to
enum class PluginEvent : uint8_t {
    ON_LOAD,           // Binary loaded
    ON_STEP,           // Instruction stepped (addr, disasm)
    ON_BREAKPOINT,     // Breakpoint hit (addr)
    ON_WATCHPOINT,     // Watchpoint fired (addr, size, value)
    ON_API_CALL,       // API stub called (name, args)
    ON_EXCEPTION,      // CPU exception (type, addr)
    ON_BRANCH,         // Conditional branch (addr, taken)
    ON_MEM_MAP,        // Memory mapped (addr, size)
    ON_DLL_LOAD,       // DLL loaded (name, base)
    ON_INIT_COMPLETE,  // DLL init completed
};

// API stub definition for the unified registration system
struct APIStubDef {
    std::string dll_name;        // e.g., "kernel32.dll"
    std::string func_name;       // e.g., "GetTickCount"
    std::string calling_conv;    // "stdcall", "cdecl", "thiscall"
    int arg_count;               // Number of arguments (-1 = variadic)
    // The actual handler is stored as a Lua function in the sol::state
};

// REPL command definition
struct CommandDef {
    std::string name;
    std::string description;
    std::string usage;
    // Handler is a Lua function
};

class PluginManager {
public:
    PluginManager() = default;

    /// Initialize the plugin system with a Lua state
    void init(sol::state& lua);

    /// Load a plugin from a .lua file
    bool load_plugin(const std::string& path);

    /// Unload a plugin by name
    bool unload_plugin(const std::string& name);

    /// Get list of loaded plugins
    std::vector<PluginInfo> list_plugins() const;

    /// Register an API stub (called from Lua via vx.plugin.api)
    void register_api_stub(const std::string& dll, const std::string& func,
                           int arg_count = -1, const std::string& conv = "stdcall");

    /// Register an event handler (called from Lua via vx.plugin.on)
    void register_event(PluginEvent event, const std::string& plugin_name);

    /// Register a REPL command (called from Lua via vx.plugin.command)
    void register_command(const std::string& name, const std::string& desc,
                          const std::string& usage = "");

    /// Fire an event to all registered handlers
    void fire_event(PluginEvent event, const std::vector<uint64_t>& args = {});

    /// Execute a registered command
    bool execute_command(const std::string& name, const std::string& args);

    /// Get all registered API stubs
    const std::vector<APIStubDef>& api_stubs() const { return api_stubs_; }

    /// Get all registered commands
    const std::vector<CommandDef>& commands() const { return commands_; }

    /// Auto-discover and load plugins from a directory
    int load_directory(const std::string& dir);

private:
    sol::state* lua_ = nullptr;
    std::vector<PluginInfo> plugins_;
    std::vector<APIStubDef> api_stubs_;
    std::vector<CommandDef> commands_;
    std::map<PluginEvent, std::vector<std::string>> event_handlers_;

    /// Register the vx.plugin table in Lua
    void bind_plugin_api();
};

} // namespace vx
