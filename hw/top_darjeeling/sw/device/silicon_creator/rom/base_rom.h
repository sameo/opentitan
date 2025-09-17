// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_HW_TOP_DARJEELING_SW_DEVICE_SILICON_CREATOR_ROM_BASE_ROM_H_
#define OPENTITAN_HW_TOP_DARJEELING_SW_DEVICE_SILICON_CREATOR_ROM_BASE_ROM_H_

#include <stdnoreturn.h>

#include "sw/device/silicon_creator/lib/error.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * ROM states run callbacks.
 */
static OT_WARN_UNUSED_RESULT rom_error_t
base_rom_state_init(void *arg, uint32_t *next_state);
/* static OT_WARN_UNUSED_RESULT rom_error_t */
/* rom_state_bootstrap_check(void *arg, uint32_t *next_state); */
/* static OT_WARN_UNUSED_RESULT rom_error_t */
/* rom_state_bootstrap(void *arg, uint32_t *next_state); */
static OT_WARN_UNUSED_RESULT rom_error_t
base_rom_state_boot_second_rom(void *arg, uint32_t *next_state);

/**
 * The first C function executed by the base ROM (defined in `base_rom.c`)
 */
noreturn void base_rom_main(void);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_HW_TOP_DARJEELING_SW_DEVICE_SILICON_CREATOR_ROM_BASE_ROM_H_
