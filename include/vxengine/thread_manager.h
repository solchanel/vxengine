#pragma once
/**
 * VXEngine Thread Manager — Multi-thread Emulation
 *
 * Provides cooperative (and optional preemptive) thread scheduling:
 *   - Multiple emulated threads, each with own register state + stack
 *   - Thread creation via CreateThread/NtCreateThreadEx stubs
 *   - Thread switching (round-robin scheduler)
 *   - Thread-local storage (TLS) per thread
 *   - Per-thread TEB
 *   - Thread suspend/resume
 *   - WaitForSingleObject on thread handles
 */

#include "vxengine.h"
#include "memory.h"
#include "cpu/icpu.h"
#include <map>
#include <vector>
#include <cstdint>

namespace vx {

// ============================================================
// Emulated Thread State
// ============================================================

struct EmulatedThread {
    uint32_t id;
    uint32_t handle;           // Fake handle for WaitForSingleObject
    RegSnapshot saved_state;   // Saved registers when not running
    uint64_t stack_base;       // Bottom of stack allocation
    uint64_t stack_size;       // Stack size
    uint64_t teb_addr;         // Per-thread TEB
    uint64_t entry_point;      // Thread start function
    uint64_t parameter;        // Thread parameter (lpParameter)

    enum State { RUNNING, READY, SUSPENDED, TERMINATED, WAITING };
    State state = READY;
    uint32_t exit_code = 0;
    uint32_t suspend_count = 0;

    // TLS slots for this thread
    std::map<uint32_t, uint64_t> tls_slots;

    // Wait state
    uint32_t wait_handle = 0;  // Handle being waited on
};

// ============================================================
// Thread Manager
// ============================================================

class ThreadManager {
public:
    ThreadManager(ICpuBackend& cpu, VirtualMemory& vmem);
    ~ThreadManager() = default;

    ThreadManager(const ThreadManager&) = delete;
    ThreadManager& operator=(const ThreadManager&) = delete;

    // ===== Initialization =====

    /// Create the initial/main thread from current CPU state
    void init_main_thread(uint64_t teb_addr);

    // ===== Thread Creation =====

    /// Create a new thread (called by CreateThread stub)
    /// Returns thread handle
    uint32_t create_thread(uint64_t start_addr, uint64_t parameter,
                           uint64_t stack_size = 0x100000,
                           bool suspended = false);

    // ===== Thread Operations =====

    bool suspend_thread(uint32_t handle);
    bool resume_thread(uint32_t handle);
    bool terminate_thread(uint32_t handle, uint32_t exit_code);
    uint32_t get_exit_code(uint32_t handle) const;

    // ===== Thread Queries =====

    uint32_t current_id() const { return current_thread_id_; }
    uint32_t current_handle() const;
    EmulatedThread* current_thread();
    const EmulatedThread* current_thread() const;
    EmulatedThread* thread_by_handle(uint32_t handle);
    EmulatedThread* thread_by_id(uint32_t id);

    // ===== Thread Switching =====

    /// Should the scheduler switch threads? (preemptive mode check)
    bool should_switch() const;

    /// Save current thread state and load next READY thread (round-robin)
    void switch_to_next();

    /// Switch to a specific thread by ID
    void switch_to(uint32_t thread_id);

    // ===== TLS Operations (operate on current thread) =====

    uint32_t tls_alloc();
    uint64_t tls_get(uint32_t index) const;
    void tls_set(uint32_t index, uint64_t value);
    void tls_free(uint32_t index);

    // ===== Wait Operations =====

    /// Returns: 0=WAIT_OBJECT_0, 258=WAIT_TIMEOUT, 0xFFFFFFFF=WAIT_FAILED
    uint32_t wait_for_object(uint32_t handle, uint32_t timeout);

    // ===== Enumeration =====

    std::vector<EmulatedThread*> all_threads();
    size_t thread_count() const { return threads_.size(); }

    // ===== Scheduling Configuration =====

    void set_timeslice(uint64_t insns) { timeslice_ = insns; }
    void set_preemptive(bool enable) { preemptive_ = enable; }
    bool preemptive() const { return preemptive_; }

    /// Tick -- called after each instruction in preemptive mode
    void tick();

    // ===== State =====

    bool initialized() const { return !threads_.empty(); }

private:
    ICpuBackend& cpu_;
    VirtualMemory& vmem_;

    std::map<uint32_t, EmulatedThread> threads_;  // id -> thread
    uint32_t current_thread_id_ = 1;
    uint32_t next_thread_id_ = 2;
    uint32_t next_handle_ = 0x100;
    uint32_t next_tls_index_ = 0;

    // Scheduling
    uint64_t timeslice_ = 100000;  // Instructions per timeslice
    uint64_t current_slice_ = 0;
    bool preemptive_ = false;      // false = cooperative (only switch on API calls)

    // Sentinel return address for thread exit detection
    static constexpr uint32_t THREAD_EXIT_SENTINEL = 0xFEEDDEAD;

    // Internal helpers
    void save_current_state();
    void load_thread_state(EmulatedThread& t);
    uint64_t allocate_stack(uint64_t size);
    uint64_t allocate_teb(uint32_t thread_id);

    // Stack allocation tracking
    uint64_t next_stack_addr_ = 0x40000000;  // Thread stacks start here

    // TEB allocation tracking
    uint64_t next_teb_addr_ = 0x7FFD4000;   // After main TEB at 0x7FFD3000
};

} // namespace vx
