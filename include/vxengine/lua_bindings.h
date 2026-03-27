#pragma once
/**
 * VXEngine sol2 Lua Bindings
 *
 * Exposes the entire engine API to Lua scripts via the "vx" global table.
 * Binds: memory, CPU, loader, tracer, stealth hooks, watchpoints,
 *        disassembly, API stubs, and (optionally) Z3 solver.
 */

#include "vxengine.h"
#include <string>

// Forward declare sol::state to avoid pulling in sol2 everywhere
namespace sol { class state; }

namespace vx {

// Forward declarations
class VXEngine;
class ICpuBackend;
class VirtualMemory;
class Tracer;
class PELoader;
class ThreadManager;
#ifdef VX_ENABLE_Z3
class Solver;
#endif

/// Initialize all VXEngine Lua bindings on the given sol::state.
/// Creates the global "vx" table with all engine functions.
///
/// @param lua    The sol2 Lua state to bind into
/// @param engine Pointer to the owning VXEngine instance
void register_lua_bindings(sol::state& lua, VXEngine* engine);

/// Register only the core memory/CPU bindings (no engine dependency)
void register_lua_core(sol::state& lua, ICpuBackend* cpu, VirtualMemory* vmem);

/// Register tracer bindings
void register_lua_tracer(sol::state& lua, Tracer* tracer);

/// Register thread manager bindings
void register_lua_threads(sol::state& lua, ThreadManager* tmgr);

#ifdef VX_ENABLE_Z3
/// Register Z3 solver bindings
void register_lua_solver(sol::state& lua, Solver* solver);
#endif

} // namespace vx
