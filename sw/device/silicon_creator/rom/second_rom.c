// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/device/silicon_creator/rom/second_rom.h"

#include <stdbool.h>
#include <stdint.h>

#include "sw/device/silicon_creator/lib/drivers/alert.h"
#include "sw/device/silicon_creator/lib/drivers/ast.h"
#include "sw/device/silicon_creator/lib/drivers/flash_ctrl.h"
#include "sw/device/silicon_creator/lib/drivers/ibex.h"
#include "sw/device/silicon_creator/lib/drivers/keymgr.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/drivers/otp.h"
#include "sw/device/silicon_creator/lib/drivers/pinmux.h"
#include "sw/device/silicon_creator/lib/drivers/pwrmgr.h"
#include "sw/device/silicon_creator/lib/drivers/retention_sram.h"
#include "sw/device/silicon_creator/lib/drivers/rnd.h"
#include "sw/device/silicon_creator/lib/drivers/rstmgr.h"
#include "sw/device/silicon_creator/lib/drivers/spi_host.h"
#include "sw/device/silicon_creator/lib/drivers/uart.h"
#include "sw/device/silicon_creator/lib/drivers/watchdog.h"
#include "sw/device/silicon_creator/rom/bootstrap.h"
#include "sw/device/silicon_creator/rom/second_rom_epmp.h"
#include "sw/device/silicon_creator/rom/sigverify_keys_rsa.h"
#include "sw/device/silicon_creator/rom/sigverify_keys_spx.h"
#include "sw/lib/sw/device/arch/device.h"
#include "sw/lib/sw/device/base/bitfield.h"
#include "sw/lib/sw/device/base/csr.h"
#include "sw/lib/sw/device/base/hardened.h"
#include "sw/lib/sw/device/base/macros.h"
#include "sw/lib/sw/device/base/memory.h"
#include "sw/lib/sw/device/base/stdasm.h"
#include "sw/lib/sw/device/silicon_creator/base/boot_measurements.h"
#include "sw/lib/sw/device/silicon_creator/base/sec_mmio.h"
#include "sw/lib/sw/device/silicon_creator/base/static_critical_version.h"
#include "sw/lib/sw/device/silicon_creator/cfi.h"
#include "sw/lib/sw/device/silicon_creator/epmp_state.h"
#include "sw/lib/sw/device/silicon_creator/error.h"
#include "sw/lib/sw/device/silicon_creator/ext_flash.h"
#include "sw/lib/sw/device/silicon_creator/rom_print.h"
#include "sw/lib/sw/device/silicon_creator/shutdown.h"
#include "sw/lib/sw/device/silicon_creator/sigverify/sigverify.h"
#include "sw/lib/sw/device/silicon_creator/spi_nor_flash.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"
#include "otp_ctrl_regs.h"

/**
 * Type alias for the ROM_EXT entry point.
 *
 * The entry point address obtained from the ROM_EXT manifest must be cast to a
 * pointer to this type before being called.
 */
typedef void rom_ext_entry_point(void);

/**
 * Table of forward branch Control Flow Integrity (CFI) counters.
 *
 * Columns: Name, Initital Value.
 *
 * Each counter is indexed by Name. The Initial Value is used to initialize the
 * counters with unique values with a good hamming distance. The values are
 * restricted to 11-bit to be able use immediate load instructions.

 * Encoding generated with
 * $ ./util/design/sparse-fsm-encode.py -d 6 -m 6 -n 11 \
 *     -s 1630646358 --language=c
 *
 * Minimum Hamming distance: 6
 * Maximum Hamming distance: 8
 * Minimum Hamming weight: 5
 * Maximum Hamming weight: 8
 */
// clang-format off
#define ROM_CFI_FUNC_COUNTERS_TABLE(X) \
  X(kCfiRomMain,         0x14b) \
  X(kCfiRomInit,         0x7dc) \
  X(kCfiRomVerify,       0x5a7) \
  X(kCfiRomTryBoot,      0x235) \
  X(kCfiRomPreBootCheck, 0x43a) \
  X(kCfiRomBoot,         0x2e2)
// clang-format on

// Define counters and constant values required by the CFI counter macros.
CFI_DEFINE_COUNTERS(rom_counters, ROM_CFI_FUNC_COUNTERS_TABLE);

// Life cycle state of the chip.
lifecycle_state_t lc_state = (lifecycle_state_t)0;

OT_ALWAYS_INLINE
OT_WARN_UNUSED_RESULT
static rom_error_t rom_irq_error(void) {
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

/**
 * Prints a status message indicating that the ROM is entering bootstrap mode.
 */
static void rom_bootstrap_message(void) {
  uart_putchar('b');
  uart_putchar('o');
  uart_putchar('o');
  uart_putchar('t');
  uart_putchar('s');
  uart_putchar('t');
  uart_putchar('r');
  uart_putchar('a');
  uart_putchar('p');
  uart_putchar(':');
  uart_putchar('1');
  uart_putchar('\r');
  uart_putchar('\n');
}

/**
 * Performs once-per-boot initialization of ROM modules and peripherals.
 */
OT_WARN_UNUSED_RESULT
static rom_error_t rom_init(void) {
  CFI_FUNC_COUNTER_INCREMENT(rom_counters, kCfiRomInit, 1);

  OT_DISCARD(rom_printf("Starting 2nd stage ROM\r\n"));

  // Reset MMIO counters
  sec_mmio_next_stage_init();

  // Set static_critical region format version.
  static_critical_version = kStaticCriticalVersion1;

  lc_state = lifecycle_state_get();

  // Re-initialize the watchdog timer.
  watchdog_init(lc_state);
  SEC_MMIO_WRITE_INCREMENT(kWatchdogSecMmioInit);

  // Initialize the shutdown policy.
  HARDENED_RETURN_IF_ERROR(shutdown_init(lc_state));

  // Update in-memory copy of the ePMP register configuration.
  second_rom_epmp_state_init(lc_state);
  HARDENED_RETURN_IF_ERROR(epmp_state_check());

  // Check that AST is in the expected state.
  HARDENED_RETURN_IF_ERROR(ast_check(lc_state));

  // Initialize the retention RAM based on the reset reason and the OTP value.
  // Note: Retention RAM is always reset on PoR regardless of the OTP value.
  uint32_t reset_reasons = rstmgr_reason_get();
  uint32_t reset_mask =
      (1 << kRstmgrReasonPowerOn) |
      otp_read32(OTP_CTRL_PARAM_CREATOR_SW_CFG_RET_RAM_RESET_MASK_OFFSET);
  if ((reset_reasons & reset_mask) != 0) {
    retention_sram_init();
    retention_sram_get()->version = kRetentionSramVersion1;
  }
  // Store the reset reason in retention RAM and clear the register.
  retention_sram_get()->creator.reset_reasons = reset_reasons;
  rstmgr_reason_clear(reset_reasons);

  // This function is a NOP unless ROM is built for an fpga.
  device_fpga_version_print();

  sec_mmio_check_values(rnd_uint32());
  sec_mmio_check_counters(/*expected_check_count=*/1);

  CFI_FUNC_COUNTER_INCREMENT(rom_counters, kCfiRomInit, 2);
  return kErrorOk;
}

/* These symbols are defined in
 * `opentitan/sw/device/silicon_creator/rom/second_rom.ld`, and describes the
 * location of the flash header.
 */
extern char _rom_ext_load_start[];
extern char _rom_ext_virtual_start[];
extern char _rom_ext_virtual_size[];

/**
 * Attempts to boot ROM_EXTs in the order given by the boot policy module.
 *
 * @return Result of the last attempt.
 */
OT_WARN_UNUSED_RESULT
static rom_error_t rom_try_boot(void) {
  CFI_FUNC_COUNTER_INCREMENT(rom_counters, kCfiRomTryBoot, 1);

  const int kSpiCsid = 0; // Flash is at chip select 0

  // Initialize SPI_HOST controller
  spi_host_init(kSpiHostDivValue);

  // Initialize SPI Flash memory
  uint32_t jedec_id;
  HARDENED_RETURN_IF_ERROR(spi_nor_flash_init(kSpiCsid, &jedec_id));
  OT_DISCARD(rom_printf("Detected Flash, JEDEC ID is %x\r\n", jedec_id));

  // Find partition for OTRE bundle
  part_desc_t part = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_lookup_partition(kSpiCsid, PARTITION_ROM_EXT_IDENTIFIER, kPartTypeBundle, &part));

  // Find Asset for OTRE firmware
  asset_manifest_t asset = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_lookup_asset(kSpiCsid, &part, ASSET_ROM_EXT_IDENTIFIER, kAssetTypeFirmware, &asset));

  // Load and verify firmware
  firmware_desc_t fw = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_load_firmware(kSpiCsid, &asset, (uintptr_t)_rom_ext_load_start, (uintptr_t)_rom_ext_virtual_start, (uintptr_t)_rom_ext_virtual_size, &fw));

  // Remap the ROM ext virtual region to shared SRAM.
  // TODO: Use a reserved remapper, that must not be used by ROM patches.
  HARDENED_RETURN_IF_ERROR(
      ibex_addr_remap_set(1, (uintptr_t)_rom_ext_virtual_start, (uintptr_t)_rom_ext_load_start,
                          (size_t)_rom_ext_virtual_size));

  HARDENED_RETURN_IF_ERROR(epmp_state_check());
  second_rom_epmp_unlock_rom_ext(
      (epmp_region_t){.start = fw.code_start,
                      .end = fw.code_end},
      (epmp_region_t){.start = (uintptr_t)_rom_ext_load_start,
                      .end = (uintptr_t)_rom_ext_load_start + (uintptr_t)_rom_ext_virtual_size});
  OT_DISCARD(rom_printf("Jumping to ROM_EXT entry point at 0x%x\r\n",
                        (unsigned)fw.entry_point));
  ((rom_ext_entry_point *)fw.entry_point)();

  return kErrorRomBootFailed;
}

void second_rom_main(void) {
  CFI_FUNC_COUNTER_INIT(rom_counters, kCfiRomMain);

  CFI_FUNC_COUNTER_PREPCALL(rom_counters, kCfiRomMain, 1, kCfiRomInit);
  SHUTDOWN_IF_ERROR(rom_init());
  CFI_FUNC_COUNTER_INCREMENT(rom_counters, kCfiRomMain, 3);
  CFI_FUNC_COUNTER_CHECK(rom_counters, kCfiRomInit, 3);

  hardened_bool_t bootstrap_req = bootstrap_requested();
  if (launder32(bootstrap_req) == kHardenedBoolTrue) {
    HARDENED_CHECK_EQ(bootstrap_req, kHardenedBoolTrue);
    rom_bootstrap_message();
    watchdog_disable();
    shutdown_finalize(bootstrap());
  }

  // `rom_try_boot` will not return unless there is an error.
  CFI_FUNC_COUNTER_PREPCALL(rom_counters, kCfiRomMain, 4, kCfiRomTryBoot);
  shutdown_finalize(rom_try_boot());
}

void rom_interrupt_handler(void) {
  register rom_error_t error asm("a0") = rom_irq_error();
  asm volatile("tail shutdown_finalize;" ::"r"(error));
  OT_UNREACHABLE();
}

// We only need a single handler for all ROM interrupts, but we want to
// keep distinct symbols to make writing tests easier.  In the ROM,
// alias all interrupt handler symbols to the single handler.
OT_ALIAS("rom_interrupt_handler")
noreturn void rom_exception_handler(void);

OT_ALIAS("rom_interrupt_handler")
noreturn void rom_nmi_handler(void);
