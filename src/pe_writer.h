#pragma once
/**
 * VXEngine PE Writer
 *
 * Writes memory-resident PE images to disk as valid PE files.
 * Used for:
 *   - Exporting unpacked binaries for analysis in x64dbg/IDA
 *   - Reconstructing import tables from sentinel addresses
 *   - Creating standalone debuggable executables
 */

#include "vxengine/vxengine.h"
#include "vxengine/memory.h"
#include "vxengine/pe_loader.h"

#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace vx {

class PEWriter {
public:
    /// Write a memory-resident PE to disk as a valid PE file.
    /// If oep == 0, uses the original entry point from the module.
    /// Scans code for sentinel references to reconstruct imports.
    static bool write(const std::string& output_path,
                      VirtualMemory& vmem,
                      const LoadedModule& mod,
                      uint64_t oep,
                      const PELoader::SentinelMap& sentinels);

private:
    /// Scan code sections for references to sentinel addresses.
    /// Returns: dll_name -> [(func_name, reference_address), ...]
    static std::map<std::string, std::vector<std::pair<std::string, uint64_t>>>
        scan_sentinel_refs(VirtualMemory& vmem,
                          const LoadedModule& mod,
                          const PELoader::SentinelMap& sentinels);

    /// Align value up to alignment boundary
    static uint32_t align_up(uint32_t value, uint32_t alignment);
};

} // namespace vx
