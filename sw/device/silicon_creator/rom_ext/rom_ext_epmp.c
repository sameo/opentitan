// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom_ext/rom_ext_epmp.h"

#include "sw/lib/sw/device/base/bitfield.h"
#include "sw/lib/sw/device/base/csr.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"

// Symbols defined in linker script.
extern char _owner_stage_virtual_start[];  // Start of Silicon Owner image (VMA)
extern char _owner_stage_virtual_size[];   // Size of Silicon Owner image (VMA)

void rom_ext_epmp_state_init(void) {
  // Update the hardware configuration (CSRs).
  //
  //            32           24             16             8             0
  //             +-------------+-------------+-------------+-------------+
  // `pmpcfg1` = | `pmp7cfg` | `pmp6cfg` | `pmp5cfg` | `pmp4cfg` |
  //             +-------------+-------------+-------------+-------------+
  CSR_CLEAR_BITS(CSR_REG_PMPCFG1, 0xffffffff);
  CSR_WRITE(CSR_REG_PMPADDR4, 0);
  CSR_WRITE(CSR_REG_PMPADDR5, 0);
  CSR_WRITE(CSR_REG_PMPADDR6, 0);
  CSR_WRITE(CSR_REG_PMPADDR7, 0);
  // Update in-memory copy of ePMP register state
  epmp_state_unconfigure(4);
  epmp_state_unconfigure(5);
  epmp_state_unconfigure(6);
  epmp_state_unconfigure(7);
}

void rom_ext_epmp_unlock_owner_stage(epmp_region_t owner_stage_text,
                                     epmp_region_t owner_stage_lma) {
  const epmp_region_t owner_stage_vma = {
      .start = (uintptr_t)_owner_stage_virtual_start,
      .end = (uintptr_t)_owner_stage_virtual_start +
             (uintptr_t)_owner_stage_virtual_size};
  // Make sure owner_stage_text is a subset of owner_stage_vma
  HARDENED_CHECK_GE(owner_stage_text.start, owner_stage_vma.start);
  HARDENED_CHECK_LE(owner_stage_text.end, owner_stage_vma.end);
  // Update the hardware configuration (CSRs).
  //
  //            32          24          16           8           0
  //             +-----------+-----------+-----------+-----------+
  // `pmpcfg1` = | `pmp7cfg` | `pmp6cfg` | `pmp5cfg` | `pmp4cfg` |
  //             +-----------+-----------+-----------+-----------+
  CSR_WRITE(CSR_REG_PMPADDR4, owner_stage_text.start >> 2);
  CSR_WRITE(CSR_REG_PMPADDR5, owner_stage_text.end >> 2);
  CSR_WRITE(CSR_REG_PMPADDR6,
            owner_stage_vma.start >> 2 |
                (owner_stage_vma.end - owner_stage_vma.start - 1) >> 3);
  CSR_WRITE(CSR_REG_PMPADDR7,
            owner_stage_lma.start >> 2 |
                (owner_stage_lma.end - owner_stage_lma.start - 1) >> 3);
  CSR_CLEAR_BITS(CSR_REG_PMPCFG1, 0xffffffff);
  CSR_SET_BITS(CSR_REG_PMPCFG1,
               ((kEpmpModeNapot | kEpmpPermLockedReadOnly) << 24) |
                   ((kEpmpModeNapot | kEpmpPermLockedReadOnly) << 16) |
                   ((kEpmpModeTor | kEpmpPermLockedReadExecute) << 8));
  // Update the in-memory copy of ePMP register state.
  epmp_state_configure_tor(5, owner_stage_text, kEpmpPermLockedReadExecute);
  epmp_state_configure_napot(6, owner_stage_vma, kEpmpPermLockedReadOnly);
  epmp_state_configure_napot(7, owner_stage_lma, kEpmpPermLockedReadOnly);
}
