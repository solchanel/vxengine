/**
 * VXEngine Thread Manager Implementation
 *
 * Cooperative/preemptive multi-thread emulation with:
 *   - Per-thread register snapshots and stacks
 *   - Per-thread TEB allocation
 *   - Round-robin scheduling
 *   - TLS support per thread
 *   - WaitForSingleObject on thread handles
 */

#include "vxengine/thread_manager.h"
#include "vxengine/win_env.h"
#include "vxengine/cpu/x86/x86_cpu.h"
#include <cstring>
#include <algorithm>

namespace vx {

// ============================================================
// Constructor
// ============================================================

ThreadManager::ThreadManager(ICpuBackend& cpu, VirtualMemory& vmem)
    : cpu_(cpu)
    , vmem_(vmem)
{
}

// ============================================================
// Main thread initialization
// ============================================================

void ThreadManager::init_main_thread(uint64_t teb_addr) {
    EmulatedThread main_thread;
    main_thread.id = 1;
    main_thread.handle = next_handle_++;
    main_thread.saved_state = cpu_.snapshot();
    main_thread.stack_base = STACK_BASE;
    main_thread.stack_size = STACK_SIZE;
    main_thread.teb_addr = teb_addr;
    main_thread.entry_point = cpu_.pc();
    main_thread.parameter = 0;
    main_thread.state = EmulatedThread::RUNNING;

    current_thread_id_ = 1;
    threads_[1] = std::move(main_thread);
}

// ============================================================
// Thread creation
// ============================================================

uint32_t ThreadManager::create_thread(uint64_t start_addr, uint64_t parameter,
                                       uint64_t stack_size, bool suspended) {
    uint32_t id = next_thread_id_++;
    uint32_t handle = next_handle_++;

    EmulatedThread t;
    t.id = id;
    t.handle = handle;
    t.entry_point = start_addr;
    t.parameter = parameter;
    t.stack_size = stack_size;

    // Allocate stack
    t.stack_base = allocate_stack(stack_size);

    // Allocate TEB for this thread
    t.teb_addr = allocate_teb(id);

    // Set up initial register state
    // Start with a copy of current state as template for segment regs, flags, etc.
    t.saved_state = cpu_.snapshot();

    // Stack grows downward: ESP starts at top of allocated region
    uint64_t stack_top = t.stack_base + stack_size;

    // Set up the stack frame for the thread entry:
    //   [ESP]   = THREAD_EXIT_SENTINEL (return address — triggers thread exit)
    //   [ESP+4] = parameter (lpParameter, first arg to thread func)
    uint64_t esp = stack_top - 8;
    vmem_.write32(static_cast<uint32_t>(esp), THREAD_EXIT_SENTINEL);
    vmem_.write32(static_cast<uint32_t>(esp + 4), static_cast<uint32_t>(parameter));

    t.saved_state.rsp = esp;
    t.saved_state.rbp = esp;
    t.saved_state.rip = start_addr;

    // Set EAX to 0 (convention)
    t.saved_state.rax = 0;

    // Set state
    if (suspended) {
        t.state = EmulatedThread::SUSPENDED;
        t.suspend_count = 1;
    } else {
        t.state = EmulatedThread::READY;
    }

    threads_[id] = std::move(t);
    return handle;
}

// ============================================================
// Stack allocation
// ============================================================

uint64_t ThreadManager::allocate_stack(uint64_t size) {
    // Page-align the size
    uint64_t aligned = (size + PAGE_SIZE - 1) & PAGE_MASK;
    if (aligned == 0) aligned = PAGE_SIZE;

    uint64_t base = next_stack_addr_;
    next_stack_addr_ += aligned + PAGE_SIZE;  // +guard page gap

    vmem_.map(base, aligned, PERM_RW);
    vmem_.memset(static_cast<uint32_t>(base), 0, static_cast<size_t>(aligned));

    return base;
}

// ============================================================
// TEB allocation
// ============================================================

uint64_t ThreadManager::allocate_teb(uint32_t thread_id) {
    uint64_t teb_addr = next_teb_addr_;
    next_teb_addr_ += PAGE_SIZE;

    // Map TEB page
    vmem_.map(teb_addr, PAGE_SIZE, PERM_RW);

    // Copy the main TEB as a template
    uint8_t teb_data[PAGE_SIZE];
    std::memset(teb_data, 0, sizeof(teb_data));
    vmem_.read(TEB_ADDRESS, teb_data, PAGE_SIZE);

    // Write template to new TEB
    vmem_.write(teb_addr, teb_data, PAGE_SIZE);

    // Fixup thread-specific fields in the new TEB:
    // +0x18: Self pointer (fs:[0x18] = &TEB)
    vmem_.write32(static_cast<uint32_t>(teb_addr + 0x18),
                  static_cast<uint32_t>(teb_addr));

    // +0x24: ClientId.UniqueThread
    vmem_.write32(static_cast<uint32_t>(teb_addr + 0x24), thread_id);

    // +0x34: LastErrorValue = 0
    vmem_.write32(static_cast<uint32_t>(teb_addr + 0x34), 0);

    return teb_addr;
}

// ============================================================
// Thread operations
// ============================================================

bool ThreadManager::suspend_thread(uint32_t handle) {
    EmulatedThread* t = thread_by_handle(handle);
    if (!t) return false;

    t->suspend_count++;
    if (t->state == EmulatedThread::RUNNING || t->state == EmulatedThread::READY) {
        t->state = EmulatedThread::SUSPENDED;
    }
    return true;
}

bool ThreadManager::resume_thread(uint32_t handle) {
    EmulatedThread* t = thread_by_handle(handle);
    if (!t) return false;

    if (t->suspend_count > 0) {
        t->suspend_count--;
        if (t->suspend_count == 0 && t->state == EmulatedThread::SUSPENDED) {
            t->state = EmulatedThread::READY;
        }
    }
    return true;
}

bool ThreadManager::terminate_thread(uint32_t handle, uint32_t exit_code) {
    EmulatedThread* t = thread_by_handle(handle);
    if (!t) return false;

    t->state = EmulatedThread::TERMINATED;
    t->exit_code = exit_code;

    // If we're terminating the current thread, switch to next
    if (t->id == current_thread_id_) {
        // Find next runnable thread
        bool found = false;
        for (auto& [id, thread] : threads_) {
            if (id != current_thread_id_ &&
                (thread.state == EmulatedThread::READY ||
                 thread.state == EmulatedThread::RUNNING)) {
                found = true;
                break;
            }
        }
        if (found) {
            switch_to_next();
        }
    }

    // Wake any threads waiting on this handle
    for (auto& [id, thread] : threads_) {
        if (thread.state == EmulatedThread::WAITING &&
            thread.wait_handle == handle) {
            thread.state = EmulatedThread::READY;
            thread.wait_handle = 0;
        }
    }

    return true;
}

uint32_t ThreadManager::get_exit_code(uint32_t handle) const {
    for (const auto& [id, t] : threads_) {
        if (t.handle == handle) {
            if (t.state == EmulatedThread::TERMINATED) {
                return t.exit_code;
            }
            return 259;  // STILL_ACTIVE
        }
    }
    return 0xFFFFFFFF;  // Invalid handle
}

// ============================================================
// Thread queries
// ============================================================

uint32_t ThreadManager::current_handle() const {
    for (const auto& [id, t] : threads_) {
        if (id == current_thread_id_) {
            return t.handle;
        }
    }
    return 0;
}

EmulatedThread* ThreadManager::current_thread() {
    auto it = threads_.find(current_thread_id_);
    return (it != threads_.end()) ? &it->second : nullptr;
}

const EmulatedThread* ThreadManager::current_thread() const {
    auto it = threads_.find(current_thread_id_);
    return (it != threads_.end()) ? &it->second : nullptr;
}

EmulatedThread* ThreadManager::thread_by_handle(uint32_t handle) {
    for (auto& [id, t] : threads_) {
        if (t.handle == handle) return &t;
    }
    return nullptr;
}

EmulatedThread* ThreadManager::thread_by_id(uint32_t id) {
    auto it = threads_.find(id);
    return (it != threads_.end()) ? &it->second : nullptr;
}

// ============================================================
// Thread switching
// ============================================================

bool ThreadManager::should_switch() const {
    if (!preemptive_) return false;
    return current_slice_ >= timeslice_;
}

void ThreadManager::save_current_state() {
    EmulatedThread* t = current_thread();
    if (t) {
        t->saved_state = cpu_.snapshot();
    }
}

void ThreadManager::load_thread_state(EmulatedThread& t) {
    cpu_.restore(t.saved_state);

    // Update FS segment base to point to this thread's TEB
    // This requires updating the GDT entry for FS (index 4 typically)
    // The GDT entry base is set via X86Backend::setup_gdt()
    // For now, we update the FS GDT entry via the CPU state
    // The segment base resolution in effective_address() uses segment_base()
    // which reads from gdt_[seg_reg >> 3]. FS=0x53 -> index 0x53>>3 = 10.
    // But the actual FS selector used is 0x53, and gdt index = 0x53>>3 = 10.
    // However, looking at win_env.cpp, FS uses GDT index 4 with selector
    // value set during setup. Let's use the x86-specific API.

    // Cast to X86Backend to access setup_gdt and update FS base
    if (cpu_.arch() == Arch::X86_32) {
        auto& x86 = static_cast<X86Backend&>(cpu_);
        // Read current GDT, update the FS entry base to new TEB
        // FS selector is in state_.fs, GDT index = fs >> 3
        uint16_t fs_sel = static_cast<uint16_t>(cpu_.reg(X86_FS));
        uint16_t gdt_idx = fs_sel >> 3;
        if (gdt_idx > 0 && gdt_idx < 16) {
            // We need to update the GDT entry base.
            // Access the x86 state directly to read current GDT,
            // then call setup_gdt with modified entry.
            GDTEntry gdt[16];
            std::memset(gdt, 0, sizeof(gdt));

            // Copy existing GDT from x86 backend
            // Since we can't read GDT directly, we'll use py-style:
            // just set the FS entry and re-apply
            // Actually, the GDT is stored as gdt_[16] in X86Backend.
            // We don't have direct read access, but we know the layout
            // from win_env.cpp: setup_gdt fills entries 0-7.
            // The simplest approach: write TEB address to FS:[0x18] and
            // update the GDT FS entry base to the new teb_addr.

            // Build a minimal GDT update: we'll read the current state
            // and patch just the FS entry base.
            // For simplicity, reconstruct from known layout:
            gdt[0] = {0, 0, 0, 0};              // Null
            gdt[1] = {0, 0xFFFFF, 0x9B, 0xCF};  // CS ring 0
            gdt[2] = {0, 0xFFFFF, 0x93, 0xCF};  // DS ring 0
            gdt[3] = {0, 0xFFFFF, 0xFB, 0xCF};  // CS ring 3
            gdt[4] = {static_cast<uint32_t>(t.teb_addr), 0xFFF, 0xF3, 0x40}; // FS -> TEB
            gdt[5] = {0, 0xFFFFF, 0xF3, 0xCF};  // GS ring 3
            gdt[6] = {0, 0xFFFFF, 0xF3, 0xCF};  // SS ring 3
            gdt[7] = {0, 0, 0, 0};              // Reserved

            x86.setup_gdt(gdt, 8);
        }
    }
}

void ThreadManager::switch_to_next() {
    if (threads_.size() <= 1) return;

    // Save current thread state
    save_current_state();

    EmulatedThread* cur = current_thread();
    if (cur && cur->state == EmulatedThread::RUNNING) {
        cur->state = EmulatedThread::READY;
    }

    // Find next READY thread (round-robin from current_thread_id_ + 1)
    uint32_t start_id = current_thread_id_;
    auto it = threads_.upper_bound(current_thread_id_);

    while (true) {
        if (it == threads_.end()) {
            it = threads_.begin();
        }

        if (it->second.state == EmulatedThread::READY) {
            // Found a runnable thread
            current_thread_id_ = it->first;
            it->second.state = EmulatedThread::RUNNING;
            load_thread_state(it->second);
            current_slice_ = 0;
            return;
        }

        ++it;
        if (it != threads_.end() && it->first == start_id) {
            // Wrapped around, no other thread to run
            break;
        }
        if (it == threads_.end()) {
            it = threads_.begin();
            if (it->first == start_id) break;
        }
    }

    // No other runnable thread found; stay on current
    if (cur) {
        cur->state = EmulatedThread::RUNNING;
    }
}

void ThreadManager::switch_to(uint32_t thread_id) {
    if (thread_id == current_thread_id_) return;

    EmulatedThread* target = thread_by_id(thread_id);
    if (!target) return;
    if (target->state != EmulatedThread::READY &&
        target->state != EmulatedThread::RUNNING) return;

    // Save current state
    save_current_state();
    EmulatedThread* cur = current_thread();
    if (cur && cur->state == EmulatedThread::RUNNING) {
        cur->state = EmulatedThread::READY;
    }

    // Load target
    current_thread_id_ = thread_id;
    target->state = EmulatedThread::RUNNING;
    load_thread_state(*target);
    current_slice_ = 0;
}

// ============================================================
// TLS operations
// ============================================================

uint32_t ThreadManager::tls_alloc() {
    uint32_t idx = next_tls_index_++;
    // Initialize slot to 0 for all threads
    for (auto& [id, t] : threads_) {
        t.tls_slots[idx] = 0;
    }
    return idx;
}

uint64_t ThreadManager::tls_get(uint32_t index) const {
    const EmulatedThread* t = current_thread();
    if (!t) return 0;
    auto it = t->tls_slots.find(index);
    return (it != t->tls_slots.end()) ? it->second : 0;
}

void ThreadManager::tls_set(uint32_t index, uint64_t value) {
    EmulatedThread* t = current_thread();
    if (!t) return;
    t->tls_slots[index] = value;
}

void ThreadManager::tls_free(uint32_t index) {
    for (auto& [id, t] : threads_) {
        t.tls_slots.erase(index);
    }
}

// ============================================================
// Wait operations
// ============================================================

uint32_t ThreadManager::wait_for_object(uint32_t handle, uint32_t timeout) {
    // Check if handle is a thread handle
    EmulatedThread* target = thread_by_handle(handle);
    if (target) {
        // If the thread is already terminated, return immediately
        if (target->state == EmulatedThread::TERMINATED) {
            return 0;  // WAIT_OBJECT_0
        }

        // If timeout is 0, return immediately with timeout
        if (timeout == 0) {
            return 258;  // WAIT_TIMEOUT
        }

        // Set current thread to WAITING and switch
        EmulatedThread* cur = current_thread();
        if (cur) {
            cur->state = EmulatedThread::WAITING;
            cur->wait_handle = handle;
            switch_to_next();
            // When we resume, the target should be terminated
            return 0;  // WAIT_OBJECT_0
        }
    }

    // Unknown handle or not a thread handle
    return 0xFFFFFFFF;  // WAIT_FAILED
}

// ============================================================
// Enumeration
// ============================================================

std::vector<EmulatedThread*> ThreadManager::all_threads() {
    std::vector<EmulatedThread*> result;
    result.reserve(threads_.size());
    for (auto& [id, t] : threads_) {
        result.push_back(&t);
    }
    return result;
}

// ============================================================
// Preemptive tick
// ============================================================

void ThreadManager::tick() {
    if (!preemptive_) return;
    current_slice_++;
    if (current_slice_ >= timeslice_) {
        switch_to_next();
    }
}

} // namespace vx
