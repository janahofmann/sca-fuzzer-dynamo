///
/// File: Helper functions for DR model
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

#ifndef _UTIL_HPP_
#define _UTIL_HPP_

#include <dr_api.h>
#include <drreg.h>

#define INSERT_BEFORE instrlist_meta_preinsert


void reserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where,
                              drvector_t *permitted, OUT reg_id_t *reg);
void unreserve_register_checked(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg);
unsigned long hash(unsigned char *buf, size_t size);

#endif /* _UTIL_HPP_ */
