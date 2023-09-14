///
/// File: Model Tracers
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include <dr_api.h>
#include <drreg.h>
#include <drutil.h>

#include "include/dr_model.h"
#include "include/tracers.hpp"
#include "include/util.hpp"

/// A global tracer object; necessary for the tracer methods to be accessible in static callbacks
extern Tracer *tracer;

// =================================================================================================
// Abstract Tracer

Tracer::Tracer()
{
    trace_buffer = (trace_entry_t *)dr_global_alloc(TRACE_BUFFER_ENTRIES * sizeof(trace_entry_t));
    dbg_trace_buffer =
        (dbg_trace_entry_t *)dr_global_alloc(TRACE_BUFFER_ENTRIES * sizeof(dbg_trace_entry_t));
    if (!trace_buffer || !dbg_trace_buffer) {
        dr_printf("ERROR: failed to allocate the trace buffer\n");
        dr_abort();
    }
    trace_buf_ptr = trace_buffer;
    dbg_trace_buffer_ptr = dbg_trace_buffer;

    // Allowed instrumentation registers
    reg_allowed = (drvector_t *)dr_global_alloc(sizeof(drvector_t));
    drreg_init_and_fill_vector(reg_allowed, false);
    drreg_set_vector_entry(reg_allowed, DR_REG_R8, true);
    drreg_set_vector_entry(reg_allowed, DR_REG_R9, true);
    drreg_set_vector_entry(reg_allowed, DR_REG_R10, true);
    drreg_set_vector_entry(reg_allowed, DR_REG_R11, true);
    drreg_set_vector_entry(reg_allowed, DR_REG_R12, true);
}

Tracer::~Tracer()
{
    dr_global_free((void *)trace_buffer, TRACE_BUFFER_ENTRIES * sizeof(trace_entry_t));
    dr_global_free((void *)dbg_trace_buffer, TRACE_BUFFER_ENTRIES * sizeof(dbg_trace_entry_t));
    dr_global_free((void *)reg_allowed, sizeof(drvector_t));
}

void Tracer::tracing_start(void *wrapcxt, OUT void **user_data) { tracing_on = true; }

void Tracer::tracing_pause(void) { tracing_on = false; }

void Tracer::tracing_finalize(void *wrapcxt, OUT void *user_data) { output_trace_entries(); }

dr_emit_flags_t Tracer::instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr)
{
    if (!tracing_on) {
        return DR_EMIT_DEFAULT;
    }

    // Get the current application instruction and its operands;
    // this is necessary to properly handle instructions expanded by event_bb_app2app
    instr_t *org_instr = drmgr_orig_app_instr_for_fetch(drcontext);

    // Add PC tracing code to all application instructions
    if (org_instr != NULL) {
        this->trace_instruction(drcontext, bb, instr, org_instr);
    }

    // Add memory tracing code to all application instructions that load or store memory
    instr_t *operands = drmgr_orig_app_instr_for_operands(drcontext);
    // check with instr_{reads/writes}_memory excludes LEA and NOP
    if (operands != NULL && (instr_reads_memory(instr) || instr_writes_memory(instr))) {
        opnd_t opnd;
        for (int i = 0; i < instr_num_srcs(operands); i++) {
            opnd = instr_get_src(operands, i);
            if (opnd_is_memory_reference(opnd)) {
                trace_mem(drcontext, bb, instr, opnd, false);
            }
        }
        for (int i = 0; i < instr_num_dsts(operands); i++) {
            opnd = instr_get_dst(operands, i);
            if (opnd_is_memory_reference(opnd)) {
                trace_mem(drcontext, bb, instr, opnd, true);
            }
        }
    }
    return DR_EMIT_DEFAULT;
}

void Tracer::load_buffer_ptr(void *drcontext, instrlist_t *bb, instr_t *instr, reg_id_t reg_buf_ptr)
{
    opnd_t opnd1, opnd2;

    //   mov reg_tmp, [&trace_buf_ptr]
    opnd1 = opnd_create_reg(reg_buf_ptr);
    opnd2 = OPND_CREATE_ABSMEM(&trace_buf_ptr, OPSZ_PTR);
    INSERT_BEFORE(bb, instr, XINST_CREATE_load(drcontext, opnd1, opnd2));
}

void Tracer::update_buffer_ptr(void *drcontext, instrlist_t *bb, instr_t *instr,
                               reg_id_t reg_buf_ptr)
{
    opnd_t opnd1, opnd2;

    //   add reg_buf_ptr, sizeof(trace_entry_t)
    opnd1 = opnd_create_reg(reg_buf_ptr);
    opnd2 = OPND_CREATE_INT8(sizeof(trace_entry_t));
    INSERT_BEFORE(bb, instr, XINST_CREATE_add(drcontext, opnd1, opnd2));

    //   mov [&trace_buf_ptr], reg_buf_ptr
    opnd1 = OPND_CREATE_ABSMEM(&trace_buf_ptr, OPSZ_PTR);
    opnd2 = opnd_create_reg(reg_buf_ptr);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store(drcontext, opnd1, opnd2));
}

void Tracer::dbg_log_instruction(void)
{
    dr_mcontext_t mc = {sizeof(mc), DR_MC_ALL};
    dr_get_mcontext(dr_get_current_drcontext(), &mc);

    dbg_trace_entry_t *entry = dbg_trace_buffer_ptr;
    entry->xax = mc.xax;
    entry->xbx = mc.xbx;
    entry->xcx = mc.xcx;
    entry->xdx = mc.xdx;
    entry->xsi = mc.xsi;
    entry->xdi = mc.xdi;

    // dr_printf("x: %lx %lx %lx %lx %lx %lx\n", mc.xax, mc.xbx, mc.xcx, mc.xdx, mc.xsi,
    // mc.xdi);
    dbg_trace_buffer_ptr++;
}

// =================================================================================================
// CT Tracer

static void dbg_log_instruction_cb(void) { tracer->dbg_log_instruction(); }
static void trace_pause_cb(void) { tracer->tracing_pause(); }
static void trace_buffers_flush(void) { tracer->output_trace_entries(); }

void CTTracer::trace_instruction(void *drcontext, instrlist_t *bb, instr_t *instr,
                                 instr_t *org_instr)
{
    opnd_t opnd1, opnd2;
    int imm_opnd;

    if (enable_dbg_trace)
        dr_insert_clean_call(drcontext, bb, instr, (void *)&dbg_log_instruction_cb, false, 0);

    // dr_printf("pc: %lx\n", instr_get_app_pc(org_instr));
    // instr_disassemble(drcontext, org_instr, STDOUT);
    // dr_printf("\n");
    // fflush(stdout);

    // Reserve two registers
    reg_id_t reg_buf_ptr, reg_tmp;
    reserve_register_checked(drcontext, bb, instr, reg_allowed, &reg_buf_ptr);
    reserve_register_checked(drcontext, bb, instr, reg_allowed, &reg_tmp);
    reg_id_t reg_tmp_1byte = reg_resize_to_opsz(reg_tmp, OPSZ_1);
    // reg_id_t reg_tmp_2bytes = reg_resize_to_opsz(reg_tmp, OPSZ_2);

    load_buffer_ptr(drcontext, bb, instr, reg_buf_ptr);

    // Push the PC
    //   mov reg_tmp, PC
    //   mov [&reg_buf_ptr->addr], reg_tmp
    ptr_int_t pc = (ptr_int_t)instr_get_app_pc(org_instr);
    opnd2 = opnd_create_reg(reg_tmp);
    instrlist_insert_mov_immed_ptrsz(drcontext, pc, opnd2, bb, instr, nullptr, nullptr);

    opnd1 = OPND_CREATE_MEMPTR(reg_buf_ptr, offsetof(trace_entry_t, addr));
    opnd2 = opnd_create_reg(reg_tmp);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store(drcontext, opnd1, opnd2));

    // Push zero into the size field (it is irrelevant for PC tracing)
    //   mov reg_tmp, 0
    //   mov [&reg_buf_ptr->size], reg_tmp
    opnd1 = opnd_create_reg(reg_tmp_1byte);
    opnd2 = OPND_CREATE_INT8(0);
    INSERT_BEFORE(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd2));

    opnd1 = OPND_CREATE_MEM8(reg_buf_ptr, offsetof(trace_entry_t, size));
    opnd2 = opnd_create_reg(reg_tmp_1byte);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store_1byte(drcontext, opnd1, opnd2));

    // Push the PC entry type
    opnd1 = opnd_create_reg(reg_tmp_1byte);
    if (instr_is_return(instr)) {
        opnd2 = OPND_CREATE_INT8(ENTRY_EOT);
        dr_insert_clean_call(drcontext, bb, instr, (void *)&trace_pause_cb, false, 0);
    } else {
        opnd2 = OPND_CREATE_INT8(ENTRY_PC);
    }
    INSERT_BEFORE(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd2));

    opnd1 = OPND_CREATE_MEM8(reg_buf_ptr, offsetof(trace_entry_t, type));
    opnd2 = opnd_create_reg(reg_tmp_1byte);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store_1byte(drcontext, opnd1, opnd2));

    update_buffer_ptr(drcontext, bb, instr, reg_buf_ptr);

    // FIXME: implement a counter that would call the this function only once per N instructions
    dr_insert_clean_call(drcontext, bb, instr, (void *)&trace_buffers_flush, false, 0);

    // Release the registers
    unreserve_register_checked(drcontext, bb, instr, reg_buf_ptr);
    unreserve_register_checked(drcontext, bb, instr, reg_tmp);
}

void CTTracer::trace_mem(void *drcontext, instrlist_t *bb, instr_t *instr, opnd_t opnd,
                         bool is_write)
{
    opnd_t opnd1, opnd2;
    int imm_opnd;

    // Reserve two registers
    reg_id_t reg_buf_ptr, reg_tmp;
    reserve_register_checked(drcontext, bb, instr, nullptr, &reg_buf_ptr);
    reserve_register_checked(drcontext, bb, instr, nullptr, &reg_tmp);
    reg_id_t reg_tmp_1byte = reg_resize_to_opsz(reg_tmp, OPSZ_1);
    reg_id_t reg_tmp_2bytes = reg_resize_to_opsz(reg_tmp, OPSZ_2);

    // init
    load_buffer_ptr(drcontext, bb, instr, reg_buf_ptr);

    // Store the address
    //   mov reg_tmp, mem_addr
    //   mov [&reg_buf_ptr->addr], reg_tmp
    bool err = !drutil_insert_get_mem_addr(drcontext, bb, instr, opnd, reg_tmp, reg_buf_ptr);
    DR_ASSERT(!err);
    load_buffer_ptr(drcontext, bb, instr, reg_buf_ptr); // reg_buf_ptr was clobbered; reload it
    opnd1 = OPND_CREATE_MEMPTR(reg_buf_ptr, offsetof(trace_entry_t, addr));
    opnd2 = opnd_create_reg(reg_tmp);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store(drcontext, opnd1, opnd2));

    // Store the size
    opnd1 = opnd_create_reg(reg_tmp_2bytes);
    opnd2 = OPND_CREATE_INT16(drutil_opnd_mem_size_in_bytes(opnd, instr));
    INSERT_BEFORE(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd2));

    opnd1 = OPND_CREATE_MEM16(reg_buf_ptr, offsetof(trace_entry_t, size));
    opnd2 = opnd_create_reg(reg_tmp_2bytes);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store_2bytes(drcontext, opnd1, opnd2));

    // Store the type
    opnd1 = opnd_create_reg(reg_tmp_1byte);
    opnd2 = OPND_CREATE_INT8(is_write ? ENTRY_WRITE : ENTRY_READ);
    INSERT_BEFORE(bb, instr, XINST_CREATE_load_int(drcontext, opnd1, opnd2));

    opnd1 = OPND_CREATE_MEM8(reg_buf_ptr, offsetof(trace_entry_t, type));
    opnd2 = opnd_create_reg(reg_tmp_1byte);
    INSERT_BEFORE(bb, instr, XINST_CREATE_store_1byte(drcontext, opnd1, opnd2));

    // Release the registers
    update_buffer_ptr(drcontext, bb, instr, reg_buf_ptr);
    unreserve_register_checked(drcontext, bb, instr, reg_buf_ptr);
    unreserve_register_checked(drcontext, bb, instr, reg_tmp);
}

void CTTracer::output_trace_entries(void)
{
    if (trace_buf_ptr > trace_buffer + TRACE_BUFFER_ENTRIES) {
        dr_printf("ERROR: trace buffer overflow\n");
        dr_abort();
    }

    if (enable_trace_normalization)
        normalize_trace_entries();

    // Print full trace
    if (enable_dbg_trace || !enable_hash_output) {
        dbg_trace_entry_t *dbg_entry = dbg_trace_buffer;

        trace_entry_t *entry;
        for (entry = trace_buffer; entry < trace_buf_ptr; entry++) {
            if (enable_bin_output) {
                fwrite(entry, sizeof(trace_entry_t), 1, stdout);
                if (entry->type == ENTRY_PC && enable_dbg_trace) {
                    fwrite(dbg_entry, sizeof(dbg_trace_entry_t), 1, stdout);
                    dbg_entry++;
                }
            } else {
                fprintf(stdout, "%lx %lx %lx\n", entry->type, entry->addr, entry->size);
                if (entry->type == ENTRY_PC && enable_dbg_trace) {
                    fprintf(stdout, "%x %lx %lx %lx %lx %lx %lx\n", ENTRY_REG_DUMP, dbg_entry->xax,
                            dbg_entry->xbx, dbg_entry->xcx, dbg_entry->xdx, dbg_entry->xsi,
                            dbg_entry->xdi);
                    dbg_entry++;
                }
            }
        }
        dbg_trace_buffer_ptr = dbg_trace_buffer;
    }

    // Print the trace hash
    if (enable_hash_output) {
        uint64_t hash_ = hash((unsigned char *)trace_buffer,
                              (trace_buf_ptr - trace_buffer) * sizeof(trace_entry_t));
        if (enable_bin_output) {
            fwrite(&hash_, sizeof(uint64_t), 1, stdout);
        } else {
            fprintf(stdout, "%lu\n", hash_);
        }
        fflush(stdout);
    }

    // Reset the trace buffer
    trace_buf_ptr = trace_buffer;
}

void CTTracer::tracing_finalize(void *wrapcxt, OUT void *user_data)
{
    output_trace_entries();

    if (enable_dbg_trace || !enable_hash_output) {
        // print EOT marker
        trace_entry_t eot = {ENTRY_EOT, 0, 0};
        if (enable_bin_output)
            fwrite(&eot, sizeof(trace_entry_t), 1, stdout);
        else
            fprintf(stdout, "%lx %lx %lx\n", eot.type, eot.addr, eot.size);
    }
}

void CTTracer::normalize_trace_entries(void)
{
    if (offsets.code_base == 0) {
        DR_ASSERT(trace_buffer[0].type == ENTRY_PC);
        offsets.code_base = trace_buffer[0].addr;

        dr_printf("type: %lx\n", trace_buffer[1].type);
        DR_ASSERT(trace_buffer[1].type == ENTRY_READ);

        offsets.sandbox_base = trace_buffer[1].addr;
    }
    for (trace_entry_t *entry = trace_buffer; entry < trace_buf_ptr; entry++) {
        if (entry->type == ENTRY_EOT) {
            trace_buf_ptr = entry;
            break;
        }

        if (entry->type == ENTRY_PC) {
            entry->addr = entry->addr - offsets.code_base;
        } else {
            entry->addr = entry->addr - offsets.sandbox_base;
        }
    }
}

// =================================================================================================
// GPR Tracer

GPRTracer::GPRTracer()
{
    // GPR tracer will use some of the info collected by the debug tracer, so dbg mode has to be
    // always enabled
    enable_dbg_trace = true;
}

GPRTracer::~GPRTracer() {}

void GPRTracer::output_trace_entries(void)
{
    if (dbg_trace_buffer_ptr == dbg_trace_buffer) {
        dr_printf("ERROR: GPR traces collected\n");
        dr_abort();
    }
    dbg_trace_entry_t *gpr_state = dbg_trace_buffer_ptr - 1;

    CTTracer::output_trace_entries();

    fwrite(gpr_state, sizeof(dbg_trace_entry_t), 1, stdout);
}

// =================================================================================================
// Accessor
Tracer *get_tracer(std::string_view name)
{
    static const std::unordered_map<std::string_view, std::function<Tracer *()>> tracers = {
        {"ct", [] { return new CTTracer; }},
        {"gpr", [] { return new GPRTracer; }},
    };

    if (auto found = tracers.find(name); found != tracers.end()) {
        return found->second();
    } else {
        return nullptr;
    }
}
