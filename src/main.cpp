/**
 * VXEngine CLI Entry Point
 *
 * Usage:
 *   vxengine [options] [file.dll]
 *
 * Options:
 *   -a x86|x64|arm    Architecture (default: x86)
 *   -s script.lua      Run Lua script
 *   -m                 Enable MCP server
 *   -p PORT            MCP server port (default: 9742)
 *   -v                 Verbose output
 *   -h, --help         Show help
 */

#include "vxengine/engine.h"

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>

// Forward declaration for MCP server (defined in mcp_server.cpp)
namespace vx {
#ifdef VX_MCP_SERVER
    void start_mcp_server(VXEngine& engine, int port);
#endif
}

static void print_banner() {
    std::cout << R"(
 __     ____  ______             _
 \ \   / /\ \/ / ____|_ __   __ _(_)_ __   ___
  \ \ / /  \  /|  _| | '_ \ / _` | | '_ \ / _ \
   \ V /   /  \| |___| | | | (_| | | | | |  __/
    \_/   /_/\_\_____|_| |_|\__, |_|_| |_|\___|
                             |___/
)" << "\n";
    std::cout << "  Virtual Execution Engine for Obfuscated Binary Analysis\n";
    std::cout << "  Version 1.0.0\n\n";
}

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options] [file.dll|file.exe]\n\n"
              << "Options:\n"
              << "  -a ARCH       Architecture: x86, x64, arm, arm64 (default: x86)\n"
              << "  -s SCRIPT     Run Lua script file\n"
              << "  -m            Enable MCP server for AI-driven debugging\n"
              << "  -p PORT       MCP server port (default: 9742)\n"
              << "  -v            Verbose output\n"
              << "  -h, --help    Show this help\n\n"
              << "If no script is provided, starts interactive Lua REPL.\n"
              << "If a file is provided, it is loaded before script/REPL.\n";
}

static vx::Arch parse_arch(const std::string& s) {
    if (s == "x86" || s == "x86_32" || s == "i386")  return vx::Arch::X86_32;
    if (s == "x64" || s == "x86_64" || s == "amd64") return vx::Arch::X86_64;
    if (s == "arm" || s == "arm32")                   return vx::Arch::ARM_32;
    if (s == "arm64" || s == "aarch64")               return vx::Arch::ARM_64;

    std::cerr << "Unknown architecture: " << s << "\n";
    std::exit(1);
}

int main(int argc, char* argv[]) {
    vx::Arch arch = vx::Arch::X86_32;
    std::string script_path;
    std::string input_file;
    bool enable_mcp = false;
    int mcp_port = 9742;
    bool verbose = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            print_banner();
            print_usage(argv[0]);
            return 0;
        }
        else if (arg == "-a" && i + 1 < argc) {
            arch = parse_arch(argv[++i]);
        }
        else if (arg == "-s" && i + 1 < argc) {
            script_path = argv[++i];
        }
        else if (arg == "-m") {
            enable_mcp = true;
        }
        else if (arg == "-p" && i + 1 < argc) {
            mcp_port = std::atoi(argv[++i]);
        }
        else if (arg == "-v") {
            verbose = true;
        }
        else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
        else {
            // Positional argument: input file
            input_file = arg;
        }
    }

    print_banner();

    if (verbose) {
        const char* arch_names[] = {"x86", "x64", "ARM32", "ARM64"};
        std::cout << "[*] Architecture: " << arch_names[static_cast<int>(arch)] << "\n";
    }

    try {
        // Create engine
        vx::VXEngine engine(arch);

        if (verbose) {
            std::cout << "[*] Engine initialized\n";
        }

        // Load input file if provided
        if (!input_file.empty()) {
            if (verbose) {
                std::cout << "[*] Loading: " << input_file << "\n";
            }
            vx::LoadedModule mod = engine.load(input_file);
            std::cout << "[+] Loaded: " << mod.name
                      << " @ 0x" << std::hex << mod.base
                      << " (size: 0x" << mod.size << ")\n"
                      << "    Entry: 0x" << mod.entry_point << "\n"
                      << "    Sections: " << std::dec << mod.sections.size() << "\n"
                      << "    Imports: " << mod.imports.size() << "\n"
                      << "    Exports: " << mod.exports.size() << "\n";
        }

        // Start MCP server if requested
        if (enable_mcp) {
#ifdef VX_MCP_SERVER
            std::cout << "[*] Starting MCP server on port " << mcp_port << "\n";
            vx::start_mcp_server(engine, mcp_port);
#else
            std::cerr << "[!] MCP server not compiled in (build with -DVX_BUILD_MCP=ON)\n";
#endif
        }

        // Run script or REPL
        if (!script_path.empty()) {
            if (verbose) {
                std::cout << "[*] Running script: " << script_path << "\n";
            }
            engine.run_script(script_path);
        } else {
            engine.lua_repl();
        }

    } catch (const std::exception& e) {
        std::cerr << "[!] Fatal error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
