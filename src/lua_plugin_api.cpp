/**
 * VXEngine Lua Plugin API — Implementation
 *
 * Unified plugin registration system. All Lua extensions go through this API.
 */

#include "vxengine/lua_plugin_api.h"

#define SOL_ALL_SAFETIES_ON 1
#include <sol/sol.hpp>
#include <filesystem>
#include <iostream>
#include <algorithm>

namespace vx {

namespace fs = std::filesystem;

// ============================================================
// Plugin Manager Implementation
// ============================================================

void PluginManager::init(sol::state& lua) {
    lua_ = &lua;
    bind_plugin_api();
}

bool PluginManager::load_plugin(const std::string& path) {
    if (!lua_) return false;

    try {
        // Execute the Lua file
        auto result = lua_->script_file(path);
        if (!result.valid()) {
            std::cerr << "[plugin] Failed to load " << path << std::endl;
            return false;
        }

        // The plugin should have called vx.plugin.register() during load
        // which populates plugins_ via the bound Lua function
        std::cout << "[plugin] Loaded: " << path << std::endl;
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[plugin] Error loading " << path << ": " << e.what() << std::endl;
        return false;
    }
}

bool PluginManager::unload_plugin(const std::string& name) {
    auto it = std::find_if(plugins_.begin(), plugins_.end(),
        [&](const PluginInfo& p) { return p.name == name; });
    if (it == plugins_.end()) return false;

    // Fire shutdown handler
    fire_event(PluginEvent::ON_LOAD, {}); // TODO: specific shutdown event

    it->loaded = false;
    plugins_.erase(it);

    // Remove event handlers for this plugin
    for (auto& [event, handlers] : event_handlers_) {
        handlers.erase(
            std::remove(handlers.begin(), handlers.end(), name),
            handlers.end()
        );
    }

    return true;
}

std::vector<PluginInfo> PluginManager::list_plugins() const {
    return plugins_;
}

void PluginManager::register_api_stub(const std::string& dll, const std::string& func,
                                       int arg_count, const std::string& conv) {
    api_stubs_.push_back({dll, func, conv, arg_count});
}

void PluginManager::register_event(PluginEvent event, const std::string& plugin_name) {
    event_handlers_[event].push_back(plugin_name);
}

void PluginManager::register_command(const std::string& name, const std::string& desc,
                                      const std::string& usage) {
    commands_.push_back({name, desc, usage});
}

void PluginManager::fire_event(PluginEvent event, const std::vector<uint64_t>& args) {
    if (!lua_) return;

    auto it = event_handlers_.find(event);
    if (it == event_handlers_.end()) return;

    // Event name mapping for Lua callback lookup
    static const std::map<PluginEvent, std::string> event_names = {
        {PluginEvent::ON_LOAD, "load"},
        {PluginEvent::ON_STEP, "step"},
        {PluginEvent::ON_BREAKPOINT, "breakpoint"},
        {PluginEvent::ON_WATCHPOINT, "watchpoint"},
        {PluginEvent::ON_API_CALL, "api_call"},
        {PluginEvent::ON_EXCEPTION, "exception"},
        {PluginEvent::ON_BRANCH, "branch"},
        {PluginEvent::ON_MEM_MAP, "mem_map"},
        {PluginEvent::ON_DLL_LOAD, "dll_load"},
        {PluginEvent::ON_INIT_COMPLETE, "init_complete"},
    };

    auto name_it = event_names.find(event);
    if (name_it == event_names.end()) return;

    // Call each registered handler
    for (const auto& plugin_name : it->second) {
        try {
            // Look up the handler: vx._event_handlers[plugin_name][event_name]
            sol::table handlers = (*lua_)["vx"]["_event_handlers"];
            if (handlers.valid()) {
                sol::table plugin_handlers = handlers[plugin_name];
                if (plugin_handlers.valid()) {
                    sol::function handler = plugin_handlers[name_it->second];
                    if (handler.valid()) {
                        // Pass args as individual parameters
                        switch (args.size()) {
                            case 0: handler(); break;
                            case 1: handler(args[0]); break;
                            case 2: handler(args[0], args[1]); break;
                            case 3: handler(args[0], args[1], args[2]); break;
                            default: handler(args[0], args[1], args[2]); break;
                        }
                    }
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[plugin:" << plugin_name << "] Event handler error: "
                      << e.what() << std::endl;
        }
    }
}

bool PluginManager::execute_command(const std::string& name, const std::string& args) {
    if (!lua_) return false;

    try {
        sol::table cmds = (*lua_)["vx"]["_commands"];
        if (cmds.valid()) {
            sol::function handler = cmds[name];
            if (handler.valid()) {
                handler(args);
                return true;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[command:" << name << "] Error: " << e.what() << std::endl;
    }
    return false;
}

int PluginManager::load_directory(const std::string& dir) {
    int count = 0;
    try {
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.path().extension() == ".lua" &&
                entry.path().filename() != "init.lua") {
                if (load_plugin(entry.path().string())) {
                    count++;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[plugin] Error scanning " << dir << ": " << e.what() << std::endl;
    }
    return count;
}

void PluginManager::bind_plugin_api() {
    if (!lua_) return;

    // Create vx.plugin table
    sol::table vx = (*lua_)["vx"];
    if (!vx.valid()) {
        (*lua_)["vx"] = lua_->create_table();
        vx = (*lua_)["vx"];
    }

    sol::table plugin = lua_->create_table();
    vx["plugin"] = plugin;

    // Internal storage tables
    vx["_event_handlers"] = lua_->create_table();
    vx["_commands"] = lua_->create_table();
    vx["_plugins"] = lua_->create_table();

    // vx.plugin.register(info_table)
    plugin["register"] = [this](sol::table info) {
        PluginInfo pi;
        pi.name = info.get_or<std::string>("name", "unnamed");
        pi.version = info.get_or<std::string>("version", "0.0");
        pi.description = info.get_or<std::string>("description", "");
        pi.author = info.get_or<std::string>("author", "");
        pi.loaded = true;
        plugins_.push_back(pi);

        // Store plugin table for later reference
        sol::table plugins_table = (*lua_)["vx"]["_plugins"];
        plugins_table[pi.name] = info;

        // Call init() if provided
        sol::function init_fn = info["init"];
        if (init_fn.valid()) {
            try { init_fn(); }
            catch (const std::exception& e) {
                std::cerr << "[plugin:" << pi.name << "] init error: " << e.what() << std::endl;
            }
        }

        std::cout << "[plugin] Registered: " << pi.name << " v" << pi.version << std::endl;
    };

    // vx.plugin.api(dll, func, handler, [nargs], [conv])
    plugin["api"] = [this](const std::string& dll, const std::string& func,
                           sol::function handler, sol::optional<int> nargs,
                           sol::optional<std::string> conv) {
        int n = nargs.value_or(-1);
        std::string c = conv.value_or("stdcall");
        register_api_stub(dll, func, n, c);

        // Store the handler so APIDispatcher can find it
        // Key: "dll!func" -> handler function
        sol::table api_table = (*lua_)["vx"]["_api_handlers"];
        if (!api_table.valid()) {
            (*lua_)["vx"]["_api_handlers"] = lua_->create_table();
            api_table = (*lua_)["vx"]["_api_handlers"];
        }
        std::string key = dll + "!" + func;
        api_table[key] = handler;
    };

    // vx.plugin.on(event_name, handler)
    plugin["on"] = [this](const std::string& event_name, sol::function handler) {
        // Map string to enum
        static const std::map<std::string, PluginEvent> name_to_event = {
            {"load", PluginEvent::ON_LOAD},
            {"step", PluginEvent::ON_STEP},
            {"breakpoint", PluginEvent::ON_BREAKPOINT},
            {"watchpoint", PluginEvent::ON_WATCHPOINT},
            {"api_call", PluginEvent::ON_API_CALL},
            {"exception", PluginEvent::ON_EXCEPTION},
            {"branch", PluginEvent::ON_BRANCH},
            {"mem_map", PluginEvent::ON_MEM_MAP},
            {"dll_load", PluginEvent::ON_DLL_LOAD},
            {"init_complete", PluginEvent::ON_INIT_COMPLETE},
        };

        auto it = name_to_event.find(event_name);
        if (it == name_to_event.end()) {
            std::cerr << "[plugin] Unknown event: " << event_name << std::endl;
            return;
        }

        // Use the most recently registered plugin name
        std::string plugin_name = plugins_.empty() ? "_global" : plugins_.back().name;

        // Store handler
        sol::table handlers = (*lua_)["vx"]["_event_handlers"];
        sol::table ph = handlers[plugin_name];
        if (!ph.valid()) {
            handlers[plugin_name] = lua_->create_table();
            ph = handlers[plugin_name];
        }
        ph[event_name] = handler;

        register_event(it->second, plugin_name);
    };

    // vx.plugin.command(name, description, handler, [usage])
    plugin["command"] = [this](const std::string& name, const std::string& desc,
                               sol::function handler, sol::optional<std::string> usage) {
        register_command(name, desc, usage.value_or(""));

        sol::table cmds = (*lua_)["vx"]["_commands"];
        cmds[name] = handler;
    };

    // vx.plugin.list() -> table of plugin info
    plugin["list"] = [this]() -> std::vector<PluginInfo> {
        return list_plugins();
    };

    // vx.plugin.load(path)
    plugin["load"] = [this](const std::string& path) -> bool {
        return load_plugin(path);
    };

    // vx.plugin.unload(name)
    plugin["unload"] = [this](const std::string& name) -> bool {
        return unload_plugin(name);
    };
}

} // namespace vx
