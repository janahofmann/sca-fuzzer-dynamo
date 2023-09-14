///
/// File: Model Interface and its implementations
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dr_api.h>
#include <drmgr.h>
#include <droption.h>
#include <drreg.h>
#include <drsyms.h>
#include <drutil.h>
#include <drwrap.h>
#include <drx.h>

#include "include/dr_model.h"
#include "include/tracers.hpp"

static void event_exit(void);
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                                        bool translating);
static dr_emit_flags_t event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb,
                                                instr_t *instr, bool for_trace, bool translating,
                                                void *user_data);
static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded);
static void wrapper_pre_func_callback(void *wrapcxt, OUT void **user_data);
static void wrapper_post_func_callback(void *wrapcxt, void *user_data);

Tracer *tracer = nullptr;

/// CLI options
///
static droption_t<bool> cli_debug_trace(DROPTION_SCOPE_CLIENT, "debug-trace", false,
                                        "Collect detailed trace for debugging with Revizor",
                                        "Collect detailed trace for debugging with Revizor");
static droption_t<bool> cli_bin_output(DROPTION_SCOPE_CLIENT, "bin-output", false,
                                       "Print results in raw binary format.",
                                       "Print results in raw binary format.");
static droption_t<std::string> cli_tracer_name(DROPTION_SCOPE_CLIENT, "tracer", "ct",
                                               "Observation labels.", "Observation labels.");
static droption_t<bool> cli_normalization(DROPTION_SCOPE_CLIENT, "disable-normalization", false,
                                          "Enable trace normalization.",
                                          "Enable trace normalization.");

/// Model entry point
///
DR_EXPORT void dr_client_main(client_id_t _, int argc, const char *argv[])
{
    // CLI
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL)) {
        dr_printf("ERROR: failed to parse CLI arguments\n");
        dr_abort();
    }

    // Create a tracerp
    auto tracer_name = cli_tracer_name.get_value();
    tracer = get_tracer(tracer_name);
    if (tracer == nullptr) {
        dr_printf("ERROR: unknown tracer name\n");
        dr_abort();
    }
    tracer->enable_dbg_trace = cli_debug_trace.get_value();
    tracer->enable_bin_output = cli_bin_output.get_value();
    tracer->enable_trace_normalization = !cli_normalization.get_value();

    // Start DR extensions
    bool err = false;
    err |= !drmgr_init();
    err |= !drutil_init();
    err |= !drx_init();
    err |= !drwrap_init();
    err |= (drsym_init(0) != DRSYM_SUCCESS);
    if (err) {
        dr_printf("ERROR: failed to start an extension\n");
        dr_abort();
    }

    // Configure register allocator
    drreg_options_t drreg_ops = {sizeof(drreg_options_t), 3, false};
    if (drreg_init(&drreg_ops) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to start drreg\n");
        dr_abort();
    }

    // Register callbacks
    dr_register_exit_event(event_exit);
    err |= !drmgr_register_module_load_event(module_load_event);
    err |= !drmgr_register_bb_app2app_event(event_bb_app2app, NULL);
    err |= !drmgr_register_bb_instrumentation_event(NULL, event_bb_instrumentation, NULL);
    if (err) {
        dr_printf("ERROR: failed to register a callback\n");
        dr_abort();
    }
}

/// Model exit point
///
static void event_exit(void)
{
    // Make sure we've sent all the collected data
    fflush(stdout);

    // Unregister callbacks
    bool err = false;
    err |= !drmgr_unregister_module_load_event(module_load_event);
    err |= !drmgr_unregister_bb_app2app_event(event_bb_app2app);
    err |= !drmgr_unregister_bb_insertion_event(event_bb_instrumentation);
    if (err) {
        dr_printf("ERROR: failed to unregister a callback\n");
        dr_abort();
    }

    // Close extensions
    if (drreg_exit() != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to close drreg\n");
        dr_abort();
    }
    drsym_exit();
    drwrap_exit();
    drx_exit();
    drutil_exit();
    drmgr_exit();
}

// =================================================================================================
// Event callbacks

/// @brief Callback for loading modules
/// Wraps revizor_test_case with a tracing_start and tracing_finalize calls
/// @param drcontext The drcontext of the current thread
/// @param mod
/// @param loaded
static void module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    size_t modoffs;
    drsym_error_t sym_res =
        drsym_lookup_symbol(mod->full_path, "revizor_test_case", &modoffs, DRSYM_DEMANGLE);
    if (sym_res == DRSYM_SUCCESS) {
        app_pc towrap = mod->start + modoffs;
        drwrap_wrap(towrap, wrapper_pre_func_callback, wrapper_post_func_callback);
    }
}

/// @brief Callback for the transformation stage
/// Expands string ops and scatter/gather into a sequence of normal memory references
/// @param drcontext The drcontext of the current thread
/// @param tag
/// @param bb
/// @param for_trace
/// @param translating
/// @return BB emitted state (dr_emit_flags_t)
static dr_emit_flags_t event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb, bool for_trace,
                                        bool translating)
{
    bool err = false;
    err |= !drutil_expand_rep_string(drcontext, bb);
    err |= !drx_expand_scatter_gather(drcontext, bb, NULL);
    if (err) {
        dr_printf("ERROR: failed to expand string ops or scatter/gather\n");
        dr_abort();
    }
    return DR_EMIT_DEFAULT;
}

/// @brief Callback for the instrumentation stage
/// Connects the tracer to the instruction stream
/// @param drcontext The drcontext of the current thread
/// @param tag
/// @param bb
/// @param instr
/// @param for_trace
/// @param translating
/// @param user_data
/// @return BB emitted state (dr_emit_flags_t)
static dr_emit_flags_t event_bb_instrumentation(void *drcontext, void *tag, instrlist_t *bb,
                                                instr_t *instr, bool for_trace, bool translating,
                                                void *user_data)
{
    dr_emit_flags_t ret = tracer->instrument_instruction(drcontext, bb, instr);
    return ret;
}

static void wrapper_pre_func_callback(void *wrapcxt, OUT void **user_data)
{
    tracer->tracing_start(wrapcxt, user_data);
}

static void wrapper_post_func_callback(void *wrapcxt, void *user_data)
{
    tracer->tracing_finalize(wrapcxt, user_data);
}
