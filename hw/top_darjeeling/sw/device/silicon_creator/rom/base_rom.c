// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "hw/top_darjeeling/sw/device/silicon_creator/rom/base_rom.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include "hw/top_darjeeling/sw/device/silicon_creator/rom/base_rom_epmp.h"
#include "sw/device/lib/arch/device.h"
#include "sw/device/lib/base/bitfield.h"
#include "sw/device/lib/base/csr.h"
#include "sw/device/lib/base/hardened.h"
#include "sw/device/lib/base/macros.h"
#include "sw/device/lib/base/memory.h"
#include "sw/device/lib/base/stdasm.h"
#include "sw/device/silicon_creator/lib/base/boot_measurements.h"
#include "sw/device/silicon_creator/lib/base/sec_mmio.h"
#include "sw/device/silicon_creator/lib/base/static_critical_version.h"
#include "sw/device/silicon_creator/lib/boot_data.h"
#include "sw/device/silicon_creator/lib/boot_log.h"
#include "sw/device/silicon_creator/lib/cfi.h"
#include "sw/device/silicon_creator/lib/chip_info.h"
#include "sw/device/silicon_creator/lib/dbg_print.h"
#include "sw/device/silicon_creator/lib/drivers/alert.h"
#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/device/silicon_creator/lib/drivers/ibex.h"
#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"
#include "sw/device/silicon_creator/lib/drivers/otp.h"
#include "sw/device/silicon_creator/lib/drivers/pwrmgr.h"
#include "sw/device/silicon_creator/lib/drivers/retention_sram.h"
#include "sw/device/silicon_creator/lib/drivers/rnd.h"
#include "sw/device/silicon_creator/lib/drivers/rstmgr.h"
#include "sw/device/silicon_creator/lib/drivers/uart.h"
#include "sw/device/silicon_creator/lib/error.h"
#include "sw/device/silicon_creator/lib/shutdown.h"
#include "sw/device/silicon_creator/lib/stack_utilization.h"
#include "sw/device/silicon_creator/rom/rom_state.h"

#include "hw/top/hmac_regs.h"  // Generated.
#include "hw/top/otp_ctrl_regs.h"
#include "hw/top/rstmgr_regs.h"
#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"

/**
 * Table of forward branch Control Flow Integrity (CFI) counters.
 *
 * Columns: Name, Initital Value.
 *
 * Each counter is indexed by Name. The Initial Value is used to initialize the
 * counters with unique values with a good hamming distance. The values are
 * restricted to 11-bit to be able use immediate load instructions.
 *
 * $ ./util/design/sparse-fsm-encode.py -d 6 -m 4 -n 11 \
 *     -s 6918825940 --language=c
 *
 * Minimum Hamming distance: 6
 * Maximum Hamming distance: 8
 * Minimum Hamming weight: 3
 * Maximum Hamming weight: 7
 */
// clang-format off
#define ROM_CFI_FUNC_COUNTERS_TABLE(X) \
  X(kCfiBaseRomMain,         0x591)   \
  X(kCfiBaseRomInit,         0x81e) \
  X(kCfiSecondRomBoot,       0x02c) \
  X(kCfiSecondRomPatch,      0x4eb)
// clang-format on

// Define counters and constant values required by the CFI counter macros.
CFI_DEFINE_COUNTERS(base_rom_counters, ROM_CFI_FUNC_COUNTERS_TABLE);

// Life cycle state of the chip.
lifecycle_state_t lc_state = (lifecycle_state_t)0;
// Boot data from flash.
boot_data_t boot_data = {0};
// Whether we are "simply" waking from low power mode.
static hardened_bool_t waking_from_low_power = 0;
// First stage (ROM-->ROM_EXT) secure boot keys loaded from OTP.
// static sigverify_otp_key_ctx_t sigverify_ctx;
// A check value for the reset reason.
uint32_t reset_reason_check;

/**
 * Prints a banner during bootup.
 *
 * OpenTitan:ssss-pppp-rr
 *
 * Where:
 * - ssss: Silicon Creator ID.
 * - pppp: Product ID.
 * - rr: Revision ID.
 */
static void rom_banner(void) {
  // TODO Do we want to control that from OTP?
  //                          a t i T n e p O
  const uint64_t kTitle1 = 0x617469546e65704f;
  //                          : n
  const uint32_t kTitle2 = 0x3a6e;
  const uint32_t kNewline = 0x0a0d;
  lifecycle_hw_rev_t hw;
  lifecycle_hw_rev_get(&hw);
  uart_write_imm(kTitle1);
  uart_write_imm(kTitle2);
  uart_write_hex(hw.silicon_creator_id, sizeof(hw.silicon_creator_id), '-');
  uart_write_hex(hw.product_id, sizeof(hw.product_id), '-');
  uart_write_hex(hw.revision_id, sizeof(hw.revision_id), kNewline);
}

/**
 * Prints a status message indicating that the ROM is entering bootstrap mode.
 */
static void rom_bootstrap_message(void) {
  //                              a r t s t o o b
  const uint64_t kBootstrap1 = 0x61727473746f6f62;
  //                             \n\r 1 : p
  const uint64_t kBootstrap2 = 0x0a0d313a70;
  uart_write_imm(kBootstrap1);
  uart_write_imm(kBootstrap2);
}

/**
 * Performs once-per-boot initialization of ROM modules and peripherals.
 */
OT_WARN_UNUSED_RESULT
static rom_error_t base_rom_init(void) {
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiBaseRomInit, 1);
  sec_mmio_init();
  uint32_t reset_reasons = rstmgr_reason_get();
  if (reset_reasons != (1U << RSTMGR_RESET_INFO_LOW_POWER_EXIT_BIT)) {
    // The above compares all bits, rather than just the one indication "low
    // power exit", because if there is any other reset reason, besides
    // LOW_POWER_EXIT, it means that the chip did full reset while coming out of
    // low power.  In that case, the state of AON IP blocks would have been
    // reset, and the ROM should not treat this as "waking from low power".
    waking_from_low_power = kHardenedBoolFalse;
  } else {
    waking_from_low_power = kHardenedBoolTrue;
  }

  // Configure UART0 as stdout.
  uart_init(kUartNCOValue);

  // Set static_critical region format version.
  static_critical_version = kStaticCriticalVersion2;

  // There are no conditional checks before writing to this CSR because it is
  // expected that if relevant Ibex countermeasures are disabled, this will
  // result in a nop.
  CSR_WRITE(CSR_REG_SECURESEED, rnd_uint32());

  // Write the OTP value to bits 0 to 5 of the cpuctrl CSR.
  uint32_t cpuctrl_csr;
  CSR_READ(CSR_REG_CPUCTRL, &cpuctrl_csr);
  cpuctrl_csr = bitfield_field32_write(
      cpuctrl_csr, (bitfield_field32_t){.mask = 0x3f, .index = 0},
      otp_read32(OTP_CTRL_PARAM_CREATOR_SW_CFG_CPUCTRL_OFFSET));
  CSR_WRITE(CSR_REG_CPUCTRL, cpuctrl_csr);

  lc_state = lifecycle_state_get();

  // Update epmp config for debug rom according to lifecycle state.
  base_rom_epmp_config_debug_rom(lc_state);

  // Initialize the shutdown policy.
  HARDENED_RETURN_IF_ERROR(shutdown_init(lc_state));

  // Initialize in-memory copy of the ePMP register configuration.
  base_rom_epmp_state_init(lc_state);

  // Initialize the retention RAM based on the reset reason and the OTP value.
  // Note: Retention RAM is always reset on PoR regardless of the OTP value.
  uint32_t reset_mask =
      (1 << kRstmgrReasonPowerOn) |
      otp_read32(OTP_CTRL_PARAM_CREATOR_SW_CFG_RET_RAM_RESET_MASK_OFFSET);
  if ((reset_reasons & reset_mask) != 0) {
    retention_sram_init();
    retention_sram_get()->creator.last_shutdown_reason = kErrorOk;
  }

  // Initialize boot_log
  // TODO Use a Darjeeling compatible boot log structure.
  boot_log_t *boot_log = &retention_sram_get()->creator.boot_log;
  memset(boot_log, 0, sizeof(*boot_log));
  boot_log->identifier = kBootLogIdentifier;
  boot_log->chip_version = kChipInfo.scm_revision;
  boot_log->retention_ram_initialized =
      reset_reasons & reset_mask ? kHardenedBoolTrue : kHardenedBoolFalse;

  // Always store the retention RAM version so firmware can depend on its
  // accuracy even after scrambling.
  retention_sram_get()->version = kRetentionSramVersion4;

  // Store the reset reason in retention RAM.
  retention_sram_get()->creator.reset_reasons = reset_reasons;

  // Print a nice message.
  if (waking_from_low_power != kHardenedBoolTrue) {
    rom_banner();
  }
  // This function is a NOP unless ROM is built for an fpga.
  device_fpga_version_print();

  sec_mmio_check_values(rnd_uint32());
  sec_mmio_check_counters(/*expected_check_count=*/1);

  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiBaseRomInit, 2);
  return kErrorOk;
}

static rom_error_t second_rom_patch(void) {
  dbg_printf("Patching Second ROM\n");

  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomPatch, 1);
  /* TODO Patch second ROM */
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomPatch, 2);
  return kErrorOk;
}

/**
 * Type alias for the second stage ROM entry point.
 */
typedef void second_rom_entry_point(void);

// This symbol is defined in `base_rom.ld` and describes the location of the
// second ROM entry point.
extern char _second_rom_boot_address[];

/**
 * Attempts to boot 2nd stage ROM.
 *
 * @return Result of the last attempt.
 */
OT_WARN_UNUSED_RESULT
static rom_error_t second_rom_boot(void) {
  CFI_FUNC_COUNTER_PREPCALL(base_rom_counters, kCfiSecondRomBoot, 1,
                            kCfiSecondRomPatch);
  HARDENED_RETURN_IF_ERROR(second_rom_patch());
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomBoot, 3);
  CFI_FUNC_COUNTER_CHECK(base_rom_counters, kCfiSecondRomPatch, 3);

  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomBoot, 4);
  uintptr_t entry_point = ((uintptr_t)_second_rom_boot_address) + 0x80;

  // Configure ePMP for the second stage ROM
  base_rom_epmp_unlock_second_rom_rx();

  // TODO: base_rom_epmp_unlock_second_rom_patch_ram(patch);

  // Check the ePMP state again
  HARDENED_RETURN_IF_ERROR(epmp_state_check());
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomBoot, 5);

  // Re-initialize mtvec
  CSR_WRITE(CSR_REG_MTVEC, ((uintptr_t)_second_rom_boot_address) | 1);

  // Jump to the second rom entry point
  dbg_printf("Jumping to 2nd stage ROM\n");
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiSecondRomBoot, 6);
  ((second_rom_entry_point *)entry_point)();

  return kErrorRomBootFailed;
}

enum {
  kRomStateCnt = 2,
};

/**
 * Table of ROM states.
 *
 * Encoding generated with:
 * $ ./util/design/sparse-fsm-encode.py -d 6 -m 4 -n 16 \
 *     -s 519644925 --language=c
 */
// clang-format off
#define ROM_STATES(X)                                                               \
  X(kRomStateInit,           0x5616, base_rom_state_init, NULL)                          \
  X(kRomStateBootSecondRom,     0xed14, base_rom_state_boot_second_rom, NULL)
// clang-format on

ROM_STATE_INIT_TABLE(rom_states, kRomStateCnt, ROM_STATES);

static OT_WARN_UNUSED_RESULT rom_error_t
base_rom_state_init(void *arg, uint32_t *next_state) {
  CFI_FUNC_COUNTER_INIT(base_rom_counters, kCfiBaseRomMain);

  CFI_FUNC_COUNTER_PREPCALL(base_rom_counters, kCfiBaseRomMain, 1,
                            kCfiBaseRomInit);
  HARDENED_RETURN_IF_ERROR(base_rom_init());
  CFI_FUNC_COUNTER_INCREMENT(base_rom_counters, kCfiBaseRomMain, 3);

  *next_state = kRomStateBootSecondRom;

  return kErrorOk;
}

static OT_WARN_UNUSED_RESULT rom_error_t
base_rom_state_boot_second_rom(void *arg, uint32_t *next_state) {
  /* // `second_rom_boot` will not return unless there is an error. */
  CFI_FUNC_COUNTER_PREPCALL(base_rom_counters, kCfiBaseRomMain, 4,
                            kCfiSecondRomBoot);
  return second_rom_boot();
}

void base_rom_main(void) {
  CFI_FUNC_COUNTER_INIT(base_rom_counters, kCfiBaseRomMain);
  shutdown_finalize(rom_state_fsm_walk(rom_states, kRomStateCnt, kRomStateInit,
                                       rom_states_cfi));
}
