/**
 * VXEngine HAL (Hardware Abstraction Layer) API Stubs
 *
 * Implements stub handlers for HAL bus data, spin locks, fast mutexes,
 * performance counters, and execution stalling used in kernel drivers.
 *
 * Registration function: register_hal_apis(APIDispatcher&)
 */

#include "vxengine/engine.h"
#include "vxengine/memory.h"
#include "vxengine/cpu/icpu.h"
#include <string>
#include <cstdlib>
#include <iostream>

namespace vx {

// ============================================================
// State
// ============================================================

static uint64_t s_perf_counter = 1000000;

// ============================================================
// Registration
// ============================================================

void register_hal_apis(APIDispatcher& api) {

    // ---- HalGetBusData (5 args, 20 bytes) ----
    api.register_api("HalGetBusData",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 20);
            return 0;
        });

    // ---- HalGetBusDataByOffset (6 args, 24 bytes) ----
    api.register_api("HalGetBusDataByOffset",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 24);
            return 0;
        });

    // ---- HalTranslateBusAddress (5 args, 20 bytes) ----
    api.register_api("HalTranslateBusAddress",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 20);
            return 1; // TRUE
        });

    // ---- ExAcquireFastMutex (1 arg, 4 bytes) ----
    api.register_api("ExAcquireFastMutex",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0;
        });

    // ---- ExReleaseFastMutex (1 arg, 4 bytes) ----
    api.register_api("ExReleaseFastMutex",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0;
        });

    // ---- ExTryToAcquireFastMutex (1 arg, 4 bytes) ----
    api.register_api("ExTryToAcquireFastMutex",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 1; // TRUE — always succeeds
        });

    // ---- KeQueryPerformanceCounter (1 arg, 4 bytes) ----
    api.register_api("KeQueryPerformanceCounter",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            uint32_t esp = static_cast<uint32_t>(cpu.sp());
            uint32_t pFrequency = vmem.read32(esp + 4);

            // If PerformanceFrequency pointer is non-null, write 10 MHz
            if (pFrequency != 0) {
                // LARGE_INTEGER: LowPart at +0, HighPart at +4
                vmem.write32(pFrequency, 10000000);  // 10 MHz
                vmem.write32(pFrequency + 4, 0);
            }

            s_perf_counter += 1000; // Increment by ~1000 ticks each call

            cpu.set_sp(cpu.sp() + 4);
            return static_cast<uint64_t>(s_perf_counter);
        });

    // ---- KeStallExecutionProcessor (1 arg, 4 bytes) ----
    api.register_api("KeStallExecutionProcessor",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            // MicroSeconds (esp+4) — just ignore
            cpu.set_sp(cpu.sp() + 4);
            return 0;
        });

    // ---- KfAcquireSpinLock (1 arg, 4 bytes) ----
    api.register_api("KfAcquireSpinLock",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 4);
            return 0; // Old IRQL
        });

    // ---- KfReleaseSpinLock (2 args, 8 bytes) ----
    api.register_api("KfReleaseSpinLock",
        [](ICpuBackend& cpu, VirtualMemory& vmem) -> uint64_t {
            cpu.set_sp(cpu.sp() + 8);
            return 0;
        });
}

} // namespace vx
