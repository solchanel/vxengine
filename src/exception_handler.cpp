/**
 * VXEngine Exception Handler — SEH/VEH Emulation Implementation
 *
 * Supports exception-driven execution flow used by VM protectors:
 *   - INT3 dispatch (breakpoint-driven VM)
 *   - Guard page unpacking
 *   - Division/invalid opcode handlers
 *   - Single-step driven VMs
 *   - Full SEH chain walking
 *   - VEH (vectored, called before SEH)
 */

#include "vxengine/exception_handler.h"
#include <iostream>
#include <cstring>
#include <algorithm>

namespace vx {

// ============================================================
// Construction
// ============================================================

ExceptionManager::ExceptionManager(ICpuBackend& cpu, VirtualMemory& vmem)
    : cpu_(cpu), vmem_(vmem) {}

// ============================================================
// VEH Management
// ============================================================

uint64_t ExceptionManager::add_veh(uint64_t handler_addr, bool first) {
    VEHEntry entry{handler_addr, first, false};
    if (first)
        veh_list_.insert(veh_list_.begin(), entry);
    else
        veh_list_.push_back(entry);
    return handler_addr; // Return as "handle"
}

bool ExceptionManager::remove_veh(uint64_t handler_addr) {
    auto it = std::remove_if(veh_list_.begin(), veh_list_.end(),
        [handler_addr](const VEHEntry& e) { return e.handler_addr == handler_addr; });
    if (it == veh_list_.end()) return false;
    veh_list_.erase(it, veh_list_.end());
    return true;
}

uint64_t ExceptionManager::add_vch(uint64_t handler_addr, bool first) {
    VEHEntry entry{handler_addr, first, true};
    if (first)
        vch_list_.insert(vch_list_.begin(), entry);
    else
        vch_list_.push_back(entry);
    return handler_addr;
}

bool ExceptionManager::remove_vch(uint64_t handler_addr) {
    auto it = std::remove_if(vch_list_.begin(), vch_list_.end(),
        [handler_addr](const VEHEntry& e) { return e.handler_addr == handler_addr; });
    if (it == vch_list_.end()) return false;
    vch_list_.erase(it, vch_list_.end());
    return true;
}

// ============================================================
// SEH Management
// ============================================================

std::vector<EXCEPTION_REGISTRATION32> ExceptionManager::read_seh_chain() const {
    std::vector<EXCEPTION_REGISTRATION32> chain;

    // Read fs:[0] — head of SEH chain
    // In our env, FS base points to TEB, and TEB[0] = ExceptionList
    uint32_t fs_base = 0;
    if (cpu_.arch() == Arch::X86_32) {
        // TEB is at the FS base address; ExceptionList is at offset 0
        // Read the FS base from GDT or direct TEB address
        fs_base = static_cast<uint32_t>(cpu_.reg(0)); // Placeholder
        // Actually read from the TEB address stored in our env
    }

    // Walk the chain from fs:[0]
    uint32_t head = vmem_.read32(0x7FFD3000); // TEB.ExceptionList at offset 0
    uint32_t current = head;

    while (current != 0 && current != 0xFFFFFFFF && chain.size() < 256) {
        EXCEPTION_REGISTRATION32 reg;
        reg.prev = vmem_.read32(current);
        reg.handler = vmem_.read32(current + 4);
        chain.push_back(reg);
        current = reg.prev;
    }
    return chain;
}

void ExceptionManager::push_seh_frame(uint64_t handler_addr, uint64_t prev) {
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());

    // Allocate space on stack for EXCEPTION_REGISTRATION
    esp -= 8;
    cpu_.set_sp(esp);

    // Read current head
    uint32_t old_head = vmem_.read32(0x7FFD3000); // TEB.ExceptionList

    // Write new registration record
    vmem_.write32(esp, old_head);                             // prev
    vmem_.write32(esp + 4, static_cast<uint32_t>(handler_addr)); // handler

    // Update fs:[0] (TEB.ExceptionList)
    vmem_.write32(0x7FFD3000, esp);
}

void ExceptionManager::pop_seh_frame() {
    uint32_t head = vmem_.read32(0x7FFD3000);
    if (head == 0 || head == 0xFFFFFFFF) return;

    // Read prev pointer and restore
    uint32_t prev = vmem_.read32(head);
    vmem_.write32(0x7FFD3000, prev);
}

// ============================================================
// Build Exception Structures in Emulated Memory
// ============================================================

uint64_t ExceptionManager::build_exception_record(ExceptionCode code, uint64_t addr,
                                                    uint32_t num_params,
                                                    const uint32_t* params) {
    // Allocate on stack
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    esp -= sizeof(EXCEPTION_RECORD32);
    esp &= ~0xF; // Align to 16 bytes

    EXCEPTION_RECORD32 rec{};
    rec.ExceptionCode = static_cast<uint32_t>(code);
    rec.ExceptionFlags = 0; // Continuable
    rec.ExceptionRecord = 0;
    rec.ExceptionAddress = static_cast<uint32_t>(addr);
    rec.NumberParameters = std::min(num_params, 15u);
    if (params && num_params > 0) {
        std::memcpy(rec.ExceptionInformation, params,
                    rec.NumberParameters * sizeof(uint32_t));
    }

    vmem_.write(esp, &rec, sizeof(rec));
    cpu_.set_sp(esp);
    return esp;
}

uint64_t ExceptionManager::build_context(RegSnapshot& snap) {
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    esp -= sizeof(CONTEXT32);
    esp &= ~0xF;

    CONTEXT32 ctx{};
    ctx.ContextFlags = 0x10001F; // CONTEXT_FULL
    ctx.Eax = static_cast<uint32_t>(snap.rax);
    ctx.Ecx = static_cast<uint32_t>(snap.rcx);
    ctx.Edx = static_cast<uint32_t>(snap.rdx);
    ctx.Ebx = static_cast<uint32_t>(snap.rbx);
    ctx.Esp = static_cast<uint32_t>(snap.rsp);
    ctx.Ebp = static_cast<uint32_t>(snap.rbp);
    ctx.Esi = static_cast<uint32_t>(snap.rsi);
    ctx.Edi = static_cast<uint32_t>(snap.rdi);
    ctx.Eip = static_cast<uint32_t>(snap.rip);
    ctx.EFlags = snap.eflags;
    ctx.SegCs = snap.cs;
    ctx.SegDs = snap.ds;
    ctx.SegEs = snap.es;
    ctx.SegFs = snap.fs;
    ctx.SegGs = snap.gs;
    ctx.SegSs = snap.ss;

    vmem_.write(esp, &ctx, sizeof(ctx));
    cpu_.set_sp(esp);
    return esp;
}

void ExceptionManager::restore_context(uint64_t context_addr) {
    CONTEXT32 ctx{};
    vmem_.read(context_addr, &ctx, sizeof(ctx));

    cpu_.set_reg(0, ctx.Eax);  // EAX
    cpu_.set_reg(1, ctx.Ecx);  // ECX
    cpu_.set_reg(2, ctx.Edx);  // EDX
    cpu_.set_reg(3, ctx.Ebx);  // EBX
    cpu_.set_reg(4, ctx.Esp);  // ESP
    cpu_.set_reg(5, ctx.Ebp);  // EBP
    cpu_.set_reg(6, ctx.Esi);  // ESI
    cpu_.set_reg(7, ctx.Edi);  // EDI
    cpu_.set_pc(ctx.Eip);
    cpu_.set_flags(ctx.EFlags);
}

// ============================================================
// Handler Invocation
// ============================================================

ExceptionDisposition ExceptionManager::call_handler(uint64_t handler_addr,
                                                      uint64_t exception_record_addr,
                                                      uint64_t context_addr,
                                                      bool is_veh) {
    // Save current state
    auto saved_snap = cpu_.snapshot();
    uint32_t saved_esp = static_cast<uint32_t>(cpu_.sp());

    // Allocate sentinel return address
    const uint32_t RETURN_SENTINEL = 0xDEADBEEF;

    if (is_veh) {
        // VEH handler signature: LONG CALLBACK handler(EXCEPTION_POINTERS* ep)
        // Build EXCEPTION_POINTERS on stack
        uint32_t esp = static_cast<uint32_t>(cpu_.sp());
        esp -= 8; // EXCEPTION_POINTERS
        vmem_.write32(esp, static_cast<uint32_t>(exception_record_addr));
        vmem_.write32(esp + 4, static_cast<uint32_t>(context_addr));

        // Push args for call: [esp] = return addr, [esp+4] = EXCEPTION_POINTERS*
        esp -= 8;
        vmem_.write32(esp, RETURN_SENTINEL);  // return address
        vmem_.write32(esp + 4, esp + 8);       // arg: ptr to EXCEPTION_POINTERS
        cpu_.set_sp(esp);
    } else {
        // SEH handler signature:
        // EXCEPTION_DISPOSITION handler(EXCEPTION_RECORD*, void* EstablisherFrame,
        //                               CONTEXT*, void* DispatcherContext)
        uint32_t esp = static_cast<uint32_t>(cpu_.sp());
        esp -= 20; // return addr + 4 args
        vmem_.write32(esp, RETURN_SENTINEL);
        vmem_.write32(esp + 4, static_cast<uint32_t>(exception_record_addr));
        vmem_.write32(esp + 8, 0);  // EstablisherFrame (SEH frame ptr)
        vmem_.write32(esp + 12, static_cast<uint32_t>(context_addr));
        vmem_.write32(esp + 16, 0); // DispatcherContext
        cpu_.set_sp(esp);
    }

    // Execute handler until it returns to sentinel
    cpu_.set_pc(handler_addr);
    auto result = cpu_.run_until(RETURN_SENTINEL, 10000000); // 10M insn limit

    // Read return value from EAX
    uint32_t disposition = static_cast<uint32_t>(cpu_.reg(0)); // EAX

    // If handler says CONTINUE_EXECUTION, restore context from the
    // (possibly modified) CONTEXT structure
    if (disposition == EXCEPTION_CONTINUE_EXECUTION) {
        restore_context(context_addr);
    } else {
        // Restore stack to pre-handler state (handler didn't handle it)
        cpu_.set_sp(saved_esp);
    }

    return static_cast<ExceptionDisposition>(disposition);
}

// ============================================================
// Dispatch Chain
// ============================================================

ExceptionDisposition ExceptionManager::dispatch_hooks(ExceptionCode code,
                                                        uint64_t addr,
                                                        RegSnapshot& ctx) {
    for (auto& [id, entry] : hooks_) {
        if (entry.all_codes || entry.code == code) {
            auto result = entry.hook(code, addr, ctx);
            if (result == EXCEPTION_CONTINUE_EXECUTION ||
                result == EXCEPTION_EXECUTE_HANDLER) {
                stats_.handled_by_hook++;
                return result;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

ExceptionDisposition ExceptionManager::dispatch_veh(uint64_t exception_ptrs_addr) {
    for (auto& veh : veh_list_) {
        // Call the VEH handler in emulated code
        auto result = call_handler(veh.handler_addr, exception_ptrs_addr,
                                    exception_ptrs_addr + 4, true);
        if (result == EXCEPTION_CONTINUE_EXECUTION) {
            stats_.handled_by_veh++;
            return result;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

ExceptionDisposition ExceptionManager::dispatch_seh(uint64_t exception_record_addr,
                                                      uint64_t context_addr) {
    auto chain = read_seh_chain();

    for (auto& frame : chain) {
        if (frame.handler == 0 || frame.handler == 0xFFFFFFFF) continue;

        auto result = call_handler(frame.handler, exception_record_addr,
                                    context_addr, false);
        if (result == EXCEPTION_CONTINUE_EXECUTION ||
            result == EXCEPTION_EXECUTE_HANDLER) {
            stats_.handled_by_seh++;
            return result;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// ============================================================
// Main Exception Dispatch Entry Point
// ============================================================

bool ExceptionManager::dispatch_exception(ExceptionCode code, uint64_t fault_addr,
                                            uint32_t num_params,
                                            const uint32_t* params) {
    if (!enabled_) return false;

    stats_.total_exceptions++;
    stats_.by_code[code]++;

    // Save current CPU state
    auto snap = cpu_.snapshot();

    // Log if enabled
    if (log_exceptions_) {
        ExceptionLogEntry log_entry;
        log_entry.code = code;
        log_entry.address = fault_addr;
        log_entry.handler_addr = 0;
        log_entry.handler_type = "pending";
        log_entry.context = snap;
        exception_log_.push_back(log_entry);

        std::cout << "[exception] Code=0x" << std::hex << static_cast<uint32_t>(code)
                  << " at 0x" << fault_addr << std::dec << std::endl;
    }

    // Phase 1: C++ hooks (analysis/interception, runs before emulated handlers)
    auto hook_result = dispatch_hooks(code, fault_addr, snap);
    if (hook_result == EXCEPTION_CONTINUE_EXECUTION) {
        if (log_exceptions_ && !exception_log_.empty()) {
            exception_log_.back().handler_type = "hook";
        }
        return true;
    }

    // Phase 2: Build exception structures in emulated memory
    uint32_t saved_esp = static_cast<uint32_t>(cpu_.sp());
    uint64_t exc_record = build_exception_record(code, fault_addr, num_params, params);
    uint64_t context = build_context(snap);

    // Phase 3: Vectored Exception Handlers (VEH — called before SEH)
    // Build EXCEPTION_POINTERS
    uint32_t esp = static_cast<uint32_t>(cpu_.sp());
    esp -= 8;
    vmem_.write32(esp, static_cast<uint32_t>(exc_record));
    vmem_.write32(esp + 4, static_cast<uint32_t>(context));
    cpu_.set_sp(esp);
    uint64_t exc_ptrs = esp;

    auto veh_result = dispatch_veh(exc_ptrs);
    if (veh_result == EXCEPTION_CONTINUE_EXECUTION) {
        if (log_exceptions_ && !exception_log_.empty()) {
            exception_log_.back().handler_type = "veh";
        }
        return true;
    }

    // Phase 4: Structured Exception Handlers (SEH chain from fs:[0])
    auto seh_result = dispatch_seh(exc_record, context);
    if (seh_result == EXCEPTION_CONTINUE_EXECUTION ||
        seh_result == EXCEPTION_EXECUTE_HANDLER) {
        if (log_exceptions_ && !exception_log_.empty()) {
            exception_log_.back().handler_type = "seh";
        }
        return true;
    }

    // Phase 5: Vectored Continue Handlers (VCH — called after SEH if CONTINUE_EXECUTION)
    for (auto& vch : vch_list_) {
        auto result = call_handler(vch.handler_addr, exc_ptrs, exc_ptrs + 4, true);
        if (result == EXCEPTION_CONTINUE_EXECUTION) {
            if (log_exceptions_ && !exception_log_.empty()) {
                exception_log_.back().handler_type = "vch";
            }
            return true;
        }
    }

    // Unhandled
    stats_.unhandled++;
    if (log_exceptions_ && !exception_log_.empty()) {
        exception_log_.back().handler_type = "unhandled";
    }

    // Restore original state (exception was not handled)
    cpu_.restore(snap);
    cpu_.set_sp(saved_esp);
    return false;
}

// ============================================================
// Convenience Exception Raisers
// ============================================================

bool ExceptionManager::raise_access_violation(uint64_t addr, bool is_write) {
    uint32_t params[2];
    params[0] = is_write ? 1 : 0;  // 0=read, 1=write, 8=execute
    params[1] = static_cast<uint32_t>(addr);
    return dispatch_exception(EXCEPTION_ACCESS_VIOLATION, cpu_.pc(), 2, params);
}

bool ExceptionManager::raise_breakpoint(uint64_t addr) {
    return dispatch_exception(EXCEPTION_BREAKPOINT, addr);
}

bool ExceptionManager::raise_single_step(uint64_t addr) {
    return dispatch_exception(EXCEPTION_SINGLE_STEP, addr);
}

bool ExceptionManager::raise_divide_by_zero(uint64_t addr) {
    return dispatch_exception(EXCEPTION_INT_DIVIDE_BY_ZERO, addr);
}

bool ExceptionManager::raise_illegal_instruction(uint64_t addr) {
    return dispatch_exception(EXCEPTION_ILLEGAL_INSTRUCTION, addr);
}

bool ExceptionManager::raise_privileged_instruction(uint64_t addr) {
    return dispatch_exception(EXCEPTION_PRIV_INSTRUCTION, addr);
}

bool ExceptionManager::raise_guard_page(uint64_t addr) {
    return dispatch_exception(EXCEPTION_GUARD_PAGE, addr);
}

// ============================================================
// C++ Exception Hooks
// ============================================================

HookID ExceptionManager::add_exception_hook(ExceptionCode code, ExceptionHook hook) {
    HookID id = next_hook_id_++;
    hooks_[id] = {code, std::move(hook), false};
    return id;
}

HookID ExceptionManager::add_exception_hook_all(ExceptionHook hook) {
    HookID id = next_hook_id_++;
    hooks_[id] = {static_cast<ExceptionCode>(0), std::move(hook), true};
    return id;
}

void ExceptionManager::remove_exception_hook(HookID id) {
    hooks_.erase(id);
}

} // namespace vx
