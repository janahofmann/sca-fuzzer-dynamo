///
/// File: Model Tracers (header)
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _TRACERS_HPP_
#define _TRACERS_HPP_

#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>

#include <dr_api.h>

// =================================================================================================
// Typedefs and defines

#define TRACE_BUFFER_ENTRIES (4096)

enum {
    ENTRY_EOT = 0, // end of trace (return instruction)
    ENTRY_PC = 1,
    ENTRY_READ = 2,
    ENTRY_WRITE = 3,
    ENTRY_REG_DUMP = 4,
} trace_entry_type_t;

typedef struct {
    uint64_t type; // see trace_entry_type_t
    uint64_t addr; // pc for instructions; address for memory accesses
    uint64_t size; // instruction size for instructions; memory access size for memory accesses
} trace_entry_t;

typedef struct {
    uint64_t xax;
    uint64_t xbx;
    uint64_t xcx;
    uint64_t xdx;
    uint64_t xsi;
    uint64_t xdi;
} dbg_trace_entry_t;

typedef struct {
    uint64_t code_base;
    uint64_t sandbox_base;
} offsets_t;

// =================================================================================================
// Classes

/// @brief Base class for all tracers
///
class Tracer
{
  public:
    Tracer();
    ~Tracer();

    /// @brief Instruments the instruction with calls to trace_instruction and trace_mem
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block to be instrumented
    /// @param instr The instruction to instrument
    dr_emit_flags_t instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr);

    /// @brief Prints the trace entries to stdout
    /// The default implementation does nothing; implemented by subclasses
    virtual void output_trace_entries(void){};

    /// @brief Starts the tracing process for a wrapped functions
    /// @param wrapcxt The machine context of the wrapped function
    /// @param __ Unused
    virtual void tracing_start(void *wrapcxt, OUT void **user_data);

    /// @brief Pauses the tracing process
    virtual void tracing_pause(void);

    /// @brief Finalizes the tracing process for a wrapped function
    /// @param wrapcxt The machine context of the wrapped function
    /// @param __ Unused
    virtual void tracing_finalize(void *wrapcxt, OUT void *user_data);

    /// @brief Clean call that logs the context of every instruction
    void dbg_log_instruction(void);

    /// @param If true, outputs the trace entries in raw binary format
    bool enable_bin_output = false;

    /// @param If true, the tracer will normalize trace values before printing them
    ///       (e.g., it will print the addresses of the instructions relative to the
    ///        address of the first instruction in the trace, and it will print the
    ///        addresses of the memory accesses relative to the address of the first
    ///        memory access in the trace)
    bool enable_trace_normalization = true;

    /// @param If true, the tracer will output the hash of the trace entries instead of the
    ///        trace entries themselves
    bool enable_hash_output = false;

    /// @param If true, the tracer will collect data for Revizor's model debug mode
    bool enable_dbg_trace = false;

  protected:
    /// @brief Traces an instruction
    /// This method is called for every instruction in the traced function
    /// The default implementation does nothing; implemented by subclasses
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block containing the instruction
    /// @param instr The instruction to trace (after SIMD and REP expansion)
    /// @param org_instr The original instruction (before SIMD and REP expansion)
    virtual void trace_instruction(void *drcontext, instrlist_t *bb, instr_t *instr,
                                   instr_t *org_instr){};

    /// @brief Traces a memory access. The default implementation does nothing, and the main
    /// functionality is implemented by subclasses.
    /// This method is called for every memory access in the traced function.
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block containing the instruction
    /// @param instr The instruction to trace (after SIMD and REP expansion)
    /// @param opnd The memory operand
    /// @param is_write True if this is a write access, false if this is a read access
    virtual void trace_mem(void *drcontext, instrlist_t *bb, instr_t *instr, opnd_t opnd,
                           bool is_write){};

    /// @brief A helper function to load the buffer pointer into a register
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block containing the instruction
    /// @param instr The instruction to trace (after SIMD and REP expansion)
    /// @param reg_buf_ptr A pointer to a list of registers available for the given instruction
    virtual void load_buffer_ptr(void *drcontext, instrlist_t *bb, instr_t *instr,
                                 reg_id_t reg_buf_ptr);

    /// @brief A helper function to increment and update the buffer pointer
    /// @param drcontext The drcontext of the current thread
    /// @param bb The basic block containing the instruction
    /// @param instr The instruction to trace (after SIMD and REP expansion)
    /// @param reg_buf_ptr A pointer to a list of registers available for the given instruction
    void update_buffer_ptr(void *drcontext, instrlist_t *bb, instr_t *instr, reg_id_t reg_buf_ptr);

    /// @brief If true, the tracer will instrument the instructions in the traced function
    bool tracing_on = false;

    trace_entry_t *trace_buffer = nullptr;
    trace_entry_t *trace_buf_ptr = nullptr;
    dbg_trace_entry_t *dbg_trace_buffer = nullptr;
    dbg_trace_entry_t *dbg_trace_buffer_ptr = nullptr;
    drvector_t *reg_allowed;
};

/// @brief "Constant-Time" (CT) Tracer
///         This tracer collects addresses of memory accesses and PCs of the executed instructions
///
class CTTracer : public Tracer
{
  public:
    CTTracer(){};
    ~CTTracer(){};

    /// @brief Records the address of the instruction into the contract trace
    void trace_instruction(void *drcontext, instrlist_t *bb, instr_t *instr,
                           instr_t *org_instr) override;

    /// @brief Records the address of the memory access into the contract trace
    void trace_mem(void *drcontext, instrlist_t *bb, instr_t *instr, opnd_t opnd,
                   bool is_write) override;

    virtual void output_trace_entries(void) override;

    /// @brief Prints all trace entries to stdout, as well as the dbg_trace entries
    void output_all_trace_entries(void);

    /// @brief Modify the trace to replace absolute addresses with relative offsets from the
    ///        first instruction (for PC) or the first memory access (for memory accesses)
    void normalize_trace_entries(void);

  protected:
    void tracing_finalize(void *wrapcxt, OUT void *user_data) override;

  private:
    offsets_t offsets = {0};
};

/// @brief "General-Purpose Register" (GPR) Tracer
///        This tracer is used for debugging. It collects the values of GPRs
///        at the end of the execution of the traced function.
class GPRTracer : public CTTracer
{
  public:
    GPRTracer();
    ~GPRTracer();

    /// @brief Prints the values of GPRs at the end of the execution of the traced function
    void output_trace_entries(void) override;
};

#endif /* _TRACERS_HPP_ */

// =================================================================================================
// Accessor

/// @brief Returns a pointer to a tracer object based on the given name
/// @param name The name of the tracer (e.g., "ct", "gpr")
/// @return A pointer to a tracer object
Tracer *get_tracer(std::string_view name);
