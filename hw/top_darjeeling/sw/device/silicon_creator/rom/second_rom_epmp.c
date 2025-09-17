// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "hw/top_darjeeling/sw/device/silicon_creator/rom/second_rom_epmp.h"

#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/csr.h"
#include "sw/device/lib/base/memory.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"

// Symbols defined in linker script.
extern char _text_start[];  // Start of executable code.
extern char _text_end[];    // End of executable code.

// Note: Hardcoding these values since the way we generate this range is not
// very robust at the moment. See #14345 and #14336.
static_assert(TOP_DARJEELING_MMIO_BASE_ADDR == 0x21100000,
              "MMIO region changed, update ePMP configuration if needed");
static_assert(TOP_DARJEELING_MMIO_SIZE_BYTES == 0xF501000,
              "MMIO region changed, update ePMP configuration if needed");

static_assert(TOP_DARJEELING_SRAM_CTRL_RET_AON_RAM_BASE_ADDR >=
                      TOP_DARJEELING_MMIO_BASE_ADDR &&
                  TOP_DARJEELING_SRAM_CTRL_RET_AON_RAM_BASE_ADDR +
                          TOP_DARJEELING_SRAM_CTRL_RET_AON_RAM_SIZE_BYTES <=
                      TOP_DARJEELING_MMIO_BASE_ADDR +
                          TOP_DARJEELING_MMIO_SIZE_BYTES,
              "Retention SRAM must be in the MMIO address space.");

void second_rom_epmp_state_init(void) {
  // Bring in-memory copy in line with the changes done in second_rom_start.S
  //
  // Note that the ePMP registers and their in-memory copy are carried over
  // from the Base ROM.
  const epmp_region_t second_rom_text = {.start = (uintptr_t)_text_start,
                                         .end = (uintptr_t)_text_end};
  epmp_state_clear(0);
  epmp_state_clear(1);
  epmp_state_clear(2);
  epmp_state_configure_tor(5, second_rom_text, kEpmpPermLockedReadExecute);

  // Open Mailbox RAM and CTN and update Debug ROM access.
  const epmp_region_t ram_mbox = {.start = TOP_DARJEELING_RAM_MBOX_BASE_ADDR,
                                  .end = TOP_DARJEELING_RAM_MBOX_BASE_ADDR +
                                         TOP_DARJEELING_RAM_MBOX_SIZE_BYTES};
  const epmp_region_t ctn = {
      .start = TOP_DARJEELING_CTN_BASE_ADDR,
      .end = TOP_DARJEELING_CTN_BASE_ADDR + TOP_DARJEELING_CTN_SIZE_BYTES};
  // Update the hardware configuration (CSRs).
  //
  //            32           24             16             8             0
  //             +-------------+-------------+-------------+-------------+
  // `pmpcfg2` = | `pmp11cfg`  | `pmp10cfg`  | `pmp9cfg`   | `pmp8cfg`   |
  //             +-------------+-------------+-------------+-------------+
  CSR_WRITE(CSR_REG_PMPADDR9,
            ram_mbox.start >> 2 | (ram_mbox.end - ram_mbox.start - 1) >> 3);
  CSR_WRITE(CSR_REG_PMPADDR10, ctn.start >> 2 | (ctn.end - ctn.start - 1) >> 3);
  CSR_CLEAR_BITS(CSR_REG_PMPCFG2, 0xffff << 8);
  CSR_SET_BITS(CSR_REG_PMPCFG2,
               ((kEpmpModeNapot | kEpmpPermLockedReadWrite) << 8) |
                   ((kEpmpModeNapot | kEpmpPermLockedReadWrite) << 16));
  // Update in-memory copy of ePMP register state
  epmp_state_configure_napot(9, ram_mbox, kEpmpPermLockedReadWrite);
  epmp_state_configure_napot(10, ctn, kEpmpPermLockedReadWrite);
}
