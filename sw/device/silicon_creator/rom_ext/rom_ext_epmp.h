// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_EXT_ROM_EXT_EPMP_H_
#define OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_EXT_ROM_EXT_EPMP_H_

#include <stdint.h>

#include "sw/lib/sw/device/silicon_creator/epmp_state.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * ROM_EXT ROM enhanced Physical Memory Protection (ePMP) library.
 *
 * The ePMP configuration is managed in two parts:
 *
 *   1. The actual hardware configuration held in CSRs
 *   2. The in-memory copy of register values in `epmp_state_t` that is used
 *      to verify the CSRs
 *
 * Every time the hardware configuration is updated the in-memory copy
 * must also be updated. The hardware configuration is usually interacted
 * with directly using the CSR library or assembly whereas the in-memory
 * copy of the state should normally be modified using configuration functions
 * from the silicon creator ePMP library.
 *
 * This separation of concerns allows the hardware configuration to be
 * updated efficiently as needed (including before the C runtime is
 * initialized) with the in-memory copy of the state used to double check the
 * configuration as required.
 */

/**
 * Initialise the ePMP in-memory copy of the register state to reflect the
 * hardware configuration expected at entry to the ROM C code.
 *
 * The actual hardware configuration is performed separately, either by reset
 * logic or in assembly. This code must be kept in sync with any changes
 * to the hardware configuration.
 */
void rom_ext_epmp_state_init(void);

/**
 * Unlocks the provided Silicon Owner image regions.
 *
 * Silicon Owner image is loaded into owner_stage_lma region (i.e. CTN RAM) and
 * it is expected that a remap has been configured from there to
 * owner_stage_virtual region.
 *
 * This function will configure the following PMP rules:
 * - owner_stage_text region: read-execute
 * - owner_stage_virtual region: read-only
 * - owner_stage_lma region: read-only
 * It will also ensure that owner_stage_text region is contained into
 * owner_stage_virtual region.
 *
 * The provided ePMP state is also updated to reflect the changes made to the
 * hardware configuration.
 * The physical region size must be power of 2 as this function uses NAPOT
 * (Naturally-Aligned-Power-Of-Two) addressing mode.
 *
 * @param owner_stage_text Region in the Silicon Owner image to receive
 *                         read-execute permission (VMA).
 * @param owner_stage_lma Region in the Silicon Owner image to receive
 *                        read-only permission (LMA).
 */
void rom_ext_epmp_unlock_owner_stage(epmp_region_t owner_text,
                                     epmp_region_t owner_stage_lma);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_DEVICE_SILICON_CREATOR_ROM_EXT_ROM_EXT_EPMP_H_
