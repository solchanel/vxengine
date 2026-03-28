/**
 * VXEngine CNG (Cryptography Next Generation) and CI (Code Integrity) Stubs
 *
 * Implements stub handlers for BCrypt* CNG functions and CI verification
 * functions used by kernel drivers and modern malware.
 *
 * Registration function: register_cng_apis(APIDispatcher&)
 */

#include "vxengine/engine.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <string>
#include <cstdlib>
#include <iostream>

namespace vx {

// ============================================================
// Helpers
// ============================================================

static std::string read_guest_wstring(VirtualMemory& vmem, uint64_t addr,
                                       size_t max_chars = 512) {
    std::string result;
    for (size_t i = 0; i < max_chars; ++i) {
        uint16_t wch = 0;
        vmem.read(addr + i * 2, &wch, 2);
        if (wch == 0) break;
        result += static_cast<char>(wch & 0xFF);
    }
    return result;
}

// Scratch memory allocator
static uint32_t s_scratch_base = 0x0A500000;
static uint32_t s_scratch_ptr  = 0x0A500000;
static bool     s_scratch_mapped = false;

static uint32_t alloc_scratch(VirtualMemory& vmem, uint32_t size) {
    if (!s_scratch_mapped) {
        vmem.map(s_scratch_base, 0x00100000, 0x06); // RW
        s_scratch_mapped = true;
    }
    uint32_t addr = s_scratch_ptr;
    s_scratch_ptr += (size + 15) & ~15;
    return addr;
}

// Simple LCG for pseudo-random bytes
static uint32_t s_lcg_seed = 42;

static uint8_t lcg_next_byte() {
    s_lcg_seed = s_lcg_seed * 1103515245 + 12345;
    return static_cast<uint8_t>((s_lcg_seed >> 16) & 0xFF);
}

// NTSTATUS codes
static constexpr uint32_t STATUS_SUCCESS              = 0x00000000;
static constexpr uint32_t STATUS_OBJECT_NAME_NOT_FOUND = 0xC0000034;

// Fake handle values
static constexpr uint32_t FAKE_BCRYPT_ALG   = 0xBC00;
static constexpr uint32_t FAKE_BCRYPT_HASH  = 0xBC10;

static uint32_t s_next_hash_handle = FAKE_BCRYPT_HASH;

// ============================================================
// Registration
// ============================================================

void register_cng_apis(APIDispatcher& api) {

    // ---- BCryptOpenAlgorithmProvider (4 args, 16 bytes) ----
    api.register_api("BCryptOpenAlgorithmProvider",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t phAlgorithm = vmem.read32(esp + 4);
            // pszAlgId (esp+8), pszImplementation (esp+12), dwFlags (esp+16)

            if (phAlgorithm != 0) {
                vmem.write32(phAlgorithm, FAKE_BCRYPT_ALG);
            }

            // Log the algorithm ID if available
            uint32_t pszAlgId = vmem.read32(esp + 8);
            if (pszAlgId != 0) {
                std::string alg = read_guest_wstring(vmem, pszAlgId);
                std::cerr << "[cng] BCryptOpenAlgorithmProvider: " << alg << std::endl;
            }

            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- BCryptCloseAlgorithmProvider (2 args, 8 bytes) ----
    api.register_api("BCryptCloseAlgorithmProvider",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return STATUS_SUCCESS;
        });

    // ---- BCryptGenRandom (4 args, 16 bytes) ----
    api.register_api("BCryptGenRandom",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hAlgorithm (esp+4)
            uint32_t pbBuffer = vmem.read32(esp + 8);
            uint32_t cbBuffer = vmem.read32(esp + 12);
            // dwFlags (esp+16)

            for (uint32_t i = 0; i < cbBuffer; ++i) {
                uint8_t b = lcg_next_byte();
                vmem.write(pbBuffer + i, &b, 1);
            }

            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- BCryptCreateHash (6 args, 24 bytes) ----
    api.register_api("BCryptCreateHash",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hAlgorithm (esp+4)
            uint32_t phHash = vmem.read32(esp + 8);
            // pbHashObject (esp+12), cbHashObject (esp+16),
            // pbSecret (esp+20), cbSecret (esp+24)

            if (phHash != 0) {
                vmem.write32(phHash, s_next_hash_handle++);
            }

            cpu.set_sp(cpu.sp() + 24);
            return STATUS_SUCCESS;
        });

    // ---- BCryptHashData (4 args, 16 bytes) ----
    api.register_api("BCryptHashData",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            // hHash (esp+4), pbInput (esp+8), cbInput (esp+12), dwFlags (esp+16)
            // No-op
            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- BCryptFinishHash (4 args, 16 bytes) ----
    api.register_api("BCryptFinishHash",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hHash (esp+4)
            uint32_t pbOutput = vmem.read32(esp + 8);
            uint32_t cbOutput = vmem.read32(esp + 12);
            // dwFlags (esp+16)

            // Write 0xAA repeated as fake hash output
            if (pbOutput != 0 && cbOutput > 0) {
                for (uint32_t i = 0; i < cbOutput; ++i) {
                    uint8_t val = 0xAA;
                    vmem.write(pbOutput + i, &val, 1);
                }
            }

            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- BCryptDestroyHash (1 arg, 4 bytes) ----
    api.register_api("BCryptDestroyHash",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return STATUS_SUCCESS;
        });

    // ---- BCryptGetProperty (6 args, 24 bytes) ----
    api.register_api("BCryptGetProperty",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 24);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        });

    // ---- BCryptSetProperty (5 args, 20 bytes) ----
    api.register_api("BCryptSetProperty",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 20);
            return STATUS_SUCCESS;
        });

    // ---- BCryptDeriveKeyPBKDF2 (9 args, 36 bytes) ----
    api.register_api("BCryptDeriveKeyPBKDF2",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hPrf (esp+4), pbPassword (esp+8), cbPassword (esp+12),
            // pbSalt (esp+16), cbSalt (esp+20), cIterations (esp+24),
            // pbDerivedKey (esp+28), cbDerivedKey (esp+32), dwFlags (esp+36)
            uint32_t pbDerivedKey = vmem.read32(esp + 28);
            uint32_t cbDerivedKey = vmem.read32(esp + 32);

            // Fill output with 0xBB
            if (pbDerivedKey != 0 && cbDerivedKey > 0) {
                for (uint32_t i = 0; i < cbDerivedKey; ++i) {
                    uint8_t val = 0xBB;
                    vmem.write(pbDerivedKey + i, &val, 1);
                }
            }

            cpu.set_sp(cpu.sp() + 36);
            return STATUS_SUCCESS;
        });

    // ---- CiCheckSignedFile (4 args, 16 bytes) ----
    api.register_api("CiCheckSignedFile",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });

    // ---- CiVerifyHashInCatalog (4 args, 16 bytes) ----
    api.register_api("CiVerifyHashInCatalog",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return STATUS_SUCCESS;
        });
}

} // namespace vx
