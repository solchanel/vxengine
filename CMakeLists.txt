cmake_minimum_required(VERSION 3.20)
project(vxengine VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ============================================================
# Options
# ============================================================
option(VX_BUILD_TESTS    "Build unit tests"          ON)
option(VX_BUILD_MCP      "Build MCP server plugin"   ON)
option(VX_ENABLE_JIT     "Enable JIT compiler"       ON)
option(VX_ENABLE_Z3      "Enable Z3 solver"          ON)

# ============================================================
# Third-party dependencies
# ============================================================

# Capstone — x86/x64/ARM disassembler
find_package(capstone QUIET)
if(NOT capstone_FOUND)
    add_subdirectory(third_party/capstone EXCLUDE_FROM_ALL)
endif()

# Keystone — assembler
find_package(keystone QUIET)
if(NOT keystone_FOUND)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/keystone/CMakeLists.txt)
        add_subdirectory(third_party/keystone EXCLUDE_FROM_ALL)
    endif()
endif()

# Z3 — SMT solver
if(VX_ENABLE_Z3)
    find_package(Z3 QUIET)
    if(Z3_FOUND)
        message(STATUS "Found Z3: ${Z3_VERSION}")
    else()
        message(WARNING "Z3 not found — solver features disabled")
        set(VX_ENABLE_Z3 OFF)
    endif()
endif()

# Lua 5.4
find_package(Lua QUIET)
if(NOT LUA_FOUND)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/CMakeLists.txt)
        add_subdirectory(third_party/lua EXCLUDE_FROM_ALL)
    else()
        # Build Lua from source (handle both src/ and root layouts)
        if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/src/lua.h)
            set(_LUA_SRC_DIR third_party/lua/src)
        else()
            set(_LUA_SRC_DIR third_party/lua)
        endif()
        file(GLOB LUA_SOURCES ${_LUA_SRC_DIR}/*.c)
        list(FILTER LUA_SOURCES EXCLUDE REGEX "lua\\.c$|luac\\.c$|ltests\\.c$|onelua\\.c$")
        add_library(lua_static STATIC ${LUA_SOURCES})
        target_include_directories(lua_static PUBLIC ${_LUA_SRC_DIR})
        target_compile_definitions(lua_static PRIVATE LUA_USE_APICHECK)
        if(UNIX)
            target_compile_definitions(lua_static PUBLIC LUA_USE_POSIX LUA_USE_DLOPEN)
            target_link_libraries(lua_static PUBLIC dl m)
        endif()
        set(LUA_LIBRARIES lua_static)
        set(LUA_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${_LUA_SRC_DIR})
    endif()
endif()

# sol2 — header-only Lua C++ binding
set(SOL2_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sol2/include)

# cpp-httplib — header-only HTTP server (for MCP)
set(HTTPLIB_INCLUDE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/cpp-httplib)

# ============================================================
# VXEngine Core Library
# ============================================================
set(VX_CORE_SOURCES
    src/engine.cpp
    src/memory.cpp
    src/pe_loader.cpp
    src/win_env.cpp
    src/win_api.cpp
    src/tracer.cpp
    src/lua_bindings.cpp
    src/lua_plugin_api.cpp
    src/cpu/x86/x86_cpu.cpp
    src/cpu/x86/x86_insns.cpp
    src/cpu/x86/x86_fpu.cpp
    src/cpu/x64/x64_cpu.cpp
    src/cpu/x64/x64_insns.cpp
    src/cpu/arm/arm_cpu.cpp
    src/cpu/arm/arm_insns.cpp
    src/elf_loader.cpp
    src/exception_handler.cpp
    src/thread_manager.cpp
    src/kernel_env.cpp
    src/win_api_ntoskrnl.cpp
    src/win_api_extended.cpp
    src/win_api_ntdll.cpp
)

# JIT is Phase 2 — stub file not yet implemented
# if(VX_ENABLE_JIT)
#     list(APPEND VX_CORE_SOURCES src/cpu/x86/x86_jit.cpp)
# endif()

if(VX_ENABLE_Z3)
    list(APPEND VX_CORE_SOURCES src/solver.cpp)
endif()

add_library(vxengine_core STATIC ${VX_CORE_SOURCES})

target_include_directories(vxengine_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${SOL2_INCLUDE}
    ${LUA_INCLUDE_DIR}
)

target_link_libraries(vxengine_core PUBLIC
    capstone
    ${LUA_LIBRARIES}
)

# Capstone v6 ARM compatibility macros (must be defined before capstone includes)
target_compile_definitions(vxengine_core PUBLIC CAPSTONE_ARM_COMPAT_HEADER=1)

if(VX_ENABLE_Z3 AND Z3_FOUND)
    target_link_libraries(vxengine_core PUBLIC z3::libz3)
    target_compile_definitions(vxengine_core PUBLIC VX_ENABLE_Z3=1)
endif()

if(VX_ENABLE_JIT)
    target_compile_definitions(vxengine_core PUBLIC VX_ENABLE_JIT=1)
endif()

# Platform-specific
if(WIN32)
    target_compile_definitions(vxengine_core PUBLIC VX_PLATFORM_WINDOWS=1)
else()
    target_compile_definitions(vxengine_core PUBLIC VX_PLATFORM_LINUX=1)
endif()

# ============================================================
# VXEngine CLI Executable
# ============================================================
add_executable(vxengine src/main.cpp)
target_link_libraries(vxengine PRIVATE vxengine_core)

# ============================================================
# MCP Server Plugin
# ============================================================
if(VX_BUILD_MCP)
    add_executable(vxengine_mcp src/mcp_server.cpp)
    target_include_directories(vxengine_mcp PRIVATE ${HTTPLIB_INCLUDE})
    target_link_libraries(vxengine_mcp PRIVATE vxengine_core)
    target_compile_definitions(vxengine_mcp PRIVATE VX_MCP_SERVER=1)
endif()

# ============================================================
# Tests
# ============================================================
if(VX_BUILD_TESTS)
    enable_testing()
    add_executable(vx_test_memory tests/test_memory.cpp)
    target_link_libraries(vx_test_memory PRIVATE vxengine_core)
    add_test(NAME test_memory COMMAND vx_test_memory)

    add_executable(vx_test_cpu tests/test_cpu.cpp)
    target_link_libraries(vx_test_cpu PRIVATE vxengine_core)
    add_test(NAME test_cpu COMMAND vx_test_cpu)
endif()

# ============================================================
# Install
# ============================================================
install(TARGETS vxengine DESTINATION bin)
install(DIRECTORY lua/ DESTINATION share/vxengine/lua)
install(DIRECTORY include/vxengine/ DESTINATION include/vxengine)
