/**
 * VXEngine crypt32.dll / CryptoAPI Stubs
 *
 * Implements stub handlers for common CryptoAPI functions used by malware
 * for encryption, hashing, and certificate operations.
 *
 * Registration function: register_crypt32_apis(APIDispatcher&)
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

static std::string read_guest_string(VirtualMemory& vmem, uint64_t addr,
                                      size_t max_len = 1024) {
    std::string result;
    for (size_t i = 0; i < max_len; ++i) {
        uint8_t ch = 0;
        vmem.read(addr + i, &ch, 1);
        if (ch == 0) break;
        result += static_cast<char>(ch);
    }
    return result;
}

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
static uint32_t s_scratch_base = 0x0A100000;
static uint32_t s_scratch_ptr  = 0x0A100000;
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
static uint32_t s_lcg_seed = 1;

static uint8_t lcg_next_byte() {
    s_lcg_seed = s_lcg_seed * 1103515245 + 12345;
    return static_cast<uint8_t>((s_lcg_seed >> 16) & 0xFF);
}

// Fake handle values
static constexpr uint32_t FAKE_HCRYPTPROV  = 0xC000;
static constexpr uint32_t FAKE_HCRYPTHASH  = 0xC010;
static constexpr uint32_t FAKE_HCRYPTKEY   = 0xC020;
static constexpr uint32_t FAKE_CERT_STORE  = 0xC100;

static uint32_t s_next_hash_handle = FAKE_HCRYPTHASH;
static uint32_t s_next_key_handle  = FAKE_HCRYPTKEY;

// ============================================================
// Registration
// ============================================================

void register_crypt32_apis(APIDispatcher& api) {

    // ---- CryptAcquireContextA (5 args, 20 bytes) ----
    api.register_api("CryptAcquireContextA",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t phProv     = vmem.read32(esp + 4);
            // szContainer (esp+8), szProvider (esp+12), dwProvType (esp+16), dwFlags (esp+20)

            if (phProv != 0) {
                vmem.write32(phProv, FAKE_HCRYPTPROV);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- CryptAcquireContextW (5 args, 20 bytes) ----
    api.register_api("CryptAcquireContextW",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t phProv = vmem.read32(esp + 4);

            if (phProv != 0) {
                vmem.write32(phProv, FAKE_HCRYPTPROV);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- CryptReleaseContext (2 args, 8 bytes) ----
    api.register_api("CryptReleaseContext",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- CryptGenRandom (3 args, 12 bytes) ----
    api.register_api("CryptGenRandom",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hProv (esp+4)
            uint32_t dwLen   = vmem.read32(esp + 8);
            uint32_t pbBuffer = vmem.read32(esp + 12);

            for (uint32_t i = 0; i < dwLen; ++i) {
                uint8_t b = lcg_next_byte();
                vmem.write(pbBuffer + i, &b, 1);
            }

            cpu.set_sp(cpu.sp() + 12);
            return 1; // TRUE
        });

    // ---- CryptCreateHash (5 args, 20 bytes) ----
    api.register_api("CryptCreateHash",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hProv (esp+4), Algid (esp+8), hKey (esp+12), dwFlags (esp+16)
            uint32_t phHash = vmem.read32(esp + 20);

            if (phHash != 0) {
                vmem.write32(phHash, s_next_hash_handle++);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- CryptHashData (4 args, 16 bytes) ----
    api.register_api("CryptHashData",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 16);
            return 1; // TRUE
        });

    // ---- CryptGetHashParam (5 args, 20 bytes) ----
    api.register_api("CryptGetHashParam",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hHash (esp+4), dwParam (esp+8)
            uint32_t pbData    = vmem.read32(esp + 12);
            uint32_t pdwDataLen = vmem.read32(esp + 16);
            // dwFlags (esp+20)

            // Write fake 20-byte SHA-1 hash
            if (pbData != 0) {
                uint8_t fake_hash[20];
                for (int i = 0; i < 20; ++i)
                    fake_hash[i] = static_cast<uint8_t>(0xA0 + i);
                vmem.write(pbData, fake_hash, 20);
            }
            if (pdwDataLen != 0) {
                vmem.write32(pdwDataLen, 20);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- CryptDestroyHash (1 arg, 4 bytes) ----
    api.register_api("CryptDestroyHash",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ---- CryptDeriveKey (5 args, 20 bytes) ----
    api.register_api("CryptDeriveKey",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            // hProv (esp+4), Algid (esp+8), hBaseData (esp+12), dwFlags (esp+16)
            uint32_t phKey = vmem.read32(esp + 20);

            if (phKey != 0) {
                vmem.write32(phKey, s_next_key_handle++);
            }

            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- CryptDestroyKey (1 arg, 4 bytes) ----
    api.register_api("CryptDestroyKey",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });

    // ---- CryptDecrypt (6 args, 24 bytes) ----
    api.register_api("CryptDecrypt",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            // hKey (esp+4), hHash (esp+8), Final (esp+12), dwFlags (esp+16),
            // pbData (esp+20), pdwDataLen (esp+24)
            // No-op: data left unchanged
            cpu.set_sp(cpu.sp() + 24);
            return 1; // TRUE
        });

    // ---- CryptEncrypt (7 args, 28 bytes) ----
    api.register_api("CryptEncrypt",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            // hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen
            // No-op: data left unchanged
            cpu.set_sp(cpu.sp() + 28);
            return 1; // TRUE
        });

    // ---- CertOpenStore (5 args, 20 bytes) ----
    api.register_api("CertOpenStore",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 20);
            return FAKE_CERT_STORE;
        });

    // ---- CertFindCertificateInStore (6 args, 24 bytes) ----
    api.register_api("CertFindCertificateInStore",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 24);
            return 0; // Not found
        });

    // ---- CertCloseStore (2 args, 8 bytes) ----
    api.register_api("CertCloseStore",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 1; // TRUE
        });

    // ---- CertFreeCertificateContext (1 arg, 4 bytes) ----
    api.register_api("CertFreeCertificateContext",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE
        });
}

} // namespace vx
