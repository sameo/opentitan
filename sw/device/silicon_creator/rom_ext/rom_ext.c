// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom_ext/rom_ext.h"

#include "sw/device/silicon_creator/lib/drivers/flash_ctrl.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/ibex.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/drivers/otp.h"
#include "sw/device/silicon_creator/lib/drivers/pinmux.h"
#include "sw/device/silicon_creator/lib/drivers/spi_host.h"
#include "sw/device/silicon_creator/lib/drivers/uart.h"
#include "sw/device/silicon_creator/rom_ext/rom_ext_epmp.h"
#include "sw/device/silicon_creator/rom_ext/sigverify_keys.h"
#include "sw/lib/sw/device/arch/device.h"
#include "sw/lib/sw/device/base/csr.h"
#include "sw/lib/sw/device/base/macros.h"
#include "sw/lib/sw/device/base/stdasm.h"
#include "sw/lib/sw/device/runtime/hart.h"
#include "sw/lib/sw/device/silicon_creator/base/chip.h"
#include "sw/lib/sw/device/silicon_creator/base/sec_mmio.h"
#include "sw/lib/sw/device/silicon_creator/epmp_state.h"
#include "sw/lib/sw/device/silicon_creator/ext_flash.h"
#include "sw/lib/sw/device/silicon_creator/rom_print.h"
#include "sw/lib/sw/device/silicon_creator/shutdown.h"
#include "sw/lib/sw/device/silicon_creator/sigverify/sigverify.h"
#include "sw/lib/sw/device/silicon_creator/spi_nor_flash.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"  // Generated.

/**
 * Type alias for the first owner boot stage entry point.
 *
 * The entry point address obtained from the first owner boot stage manifest
 * must be cast to a pointer to this type before being called.
 */
typedef void owner_stage_entry_point(void);

// Life cycle state of the chip.
lifecycle_state_t lc_state = kLcStateProd;

OT_WARN_UNUSED_RESULT
static rom_error_t rom_ext_irq_error(void) {
  uint32_t mcause;
  CSR_READ(CSR_REG_MCAUSE, &mcause);
  // Shuffle the mcause bits into the uppermost byte of the word and report
  // the cause as kErrorInterrupt.
  // Based on the ibex verilog, it appears that the most significant bit
  // indicates whether the cause is an exception (0) or external interrupt (1),
  // and the 5 least significant bits indicate which exception/interrupt.
  //
  // Preserve the MSB and shift the 7 LSBs into the upper byte.
  // (we preserve 7 instead of 5 because the verilog hardcodes the unused bits
  // as zero and those would be the next bits used should the number of
  // interrupt causes increase).
  mcause = (mcause & 0x80000000) | ((mcause & 0x7f) << 24);
  return kErrorInterrupt + mcause;
}

OT_WARN_UNUSED_RESULT
static rom_error_t rom_ext_init(void) {
  sec_mmio_next_stage_init();

  pinmux_init();
  // Configure UART0 as stdout.
  uart_init(kUartNCOValue);

  lc_state = lifecycle_state_get();

  HARDENED_RETURN_IF_ERROR(epmp_state_check());
  rom_ext_epmp_state_init();

  return kErrorOk;
}

/* These symbols are defined in
 * `opentitan/sw/device/silicon_creator/rom_ext/rom_ext.ld`, and describe the
 * location of the flash header.
 */
extern char _owner_stage_load_start[];
extern char _owner_stage_virtual_start[];
extern char _owner_stage_virtual_size[];

OT_WARN_UNUSED_RESULT
static rom_error_t rom_ext_try_boot(void) {
  const int kSpiCsid = 0; // Flash is at chip select 0

  // Initialize SPI_HOST controller
  spi_host_init(kSpiHostDivValue);

  // Initialize SPI Flash memory
  uint32_t jedec_id;
  HARDENED_RETURN_IF_ERROR(spi_nor_flash_init(kSpiCsid, &jedec_id));
  OT_DISCARD(rom_printf("Detected Flash, JEDEC ID is %x\r\n", jedec_id));

  // Find partition for OTPF bundle
  part_desc_t part = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_lookup_partition(kSpiCsid, PARTITION_PLATFORM_FIRMWARES_IDENTIFIER, kPartTypeBundle, &part));

  // Find Asset for OTB0 firmware
  asset_manifest_t asset = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_lookup_asset(kSpiCsid, &part, ASSET_BL0_IDENTIFIER, kAssetTypeFirmware, &asset));

  // Load and verify firmware
  firmware_desc_t fw = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_load_firmware(kSpiCsid, &asset, (uintptr_t)_owner_stage_load_start, (uintptr_t)_owner_stage_virtual_start, (uintptr_t)_owner_stage_virtual_size, &fw));

  // Remap the ROM ext virtual region to shared SRAM.
  // TODO: Use a reserved remapper, that must not be used by ROM patches.
  HARDENED_RETURN_IF_ERROR(
      ibex_addr_remap_set(0, (uintptr_t)_owner_stage_virtual_start, (uintptr_t)_owner_stage_load_start,
                          (size_t)_owner_stage_virtual_size));

  HARDENED_RETURN_IF_ERROR(epmp_state_check());
  rom_ext_epmp_unlock_owner_stage(
      (epmp_region_t){.start = fw.code_start,
                      .end = fw.code_end},
      (epmp_region_t){.start = (uintptr_t)_owner_stage_load_start,
                      .end = (uintptr_t)_owner_stage_load_start + (uintptr_t)_owner_stage_virtual_size});
  OT_DISCARD(rom_printf("Jumping to BL0 entry point at 0x%x\r\n",
                        (unsigned)fw.entry_point));
  ((owner_stage_entry_point *)fw.entry_point)();

  // `rom_ext_boot()` should never return `kErrorOk`, but if it does
  // we must shut down the chip instead of trying the next ROM_EXT.
  return kErrorRomBootFailed;
}

void rom_ext_main(void) {
  SHUTDOWN_IF_ERROR(rom_ext_init());
  OT_DISCARD(rom_printf("Starting ROM_EXT\r\n"));
  shutdown_finalize(rom_ext_try_boot());
}

void rom_ext_interrupt_handler(void) { shutdown_finalize(rom_ext_irq_error()); }

// We only need a single handler for all ROM_EXT interrupts, but we want to
// keep distinct symbols to make writing tests easier.  In the ROM_EXT,
// alias all interrupt handler symbols to the single handler.
OT_ALIAS("rom_ext_interrupt_handler")
void rom_ext_exception_handler(void);

OT_ALIAS("rom_ext_interrupt_handler")
void rom_ext_nmi_handler(void);
