///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#include "include/util.hpp"

#include <drmgr.h>
#include <droption.h>
#include <drsyms.h>
#include <drutil.h>
#include <drwrap.h>
#include <drx.h>
#include <dr_ir_macros_x86.h>


/// A wrapper around drreg_reserve_register that aborts on failure
///
void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, OUT reg_id_t *reg)
{
    if (drreg_reserve_register(drcontext, ilist, where, permitted, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to reserve a register\n");
        dr_abort();
    }
}

/// A wrapper around drreg_reserve_register that aborts on failure
///
void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg)
{
    if (drreg_unreserve_register(drcontext, ilist, where, reg) != DRREG_SUCCESS) {
        dr_printf("ERROR: failed to unreserve a register\n");
        dr_abort();
    }
}

/// An implementation of djb2 hash function
///
unsigned long hash(unsigned char *buf, size_t size)
{
    unsigned long hash = 5381;

    for (int i = 0; i < size; i++)
        hash = ((hash << 5) + hash) + buf[i]; /* hash * 33 + c */

    return hash;
}
