// Copyright lowRISC contributors (OpenTitan project).
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>

#include "hw/top/dt/dt_api.h"  // Generated
#include "sw/device/lib/base/macros.h"

static const uint32_t clock_freq_dividers[kDtClockCount] = {
    [kDtClockMain] = 1,
    [kDtClockIo] = 4,
    [kDtClockAon] = 16,
};

/*
 * Weak symbol that can be overridden by e.g. ROM vendor hooks.
 * Default clock frequency for Darjeeling is 1 GHz.
 */
OT_WEAK uint32_t clock_main_freq_hz(void) { return 1000 * 1000 * 1000; }

uint32_t dt_clock_frequency(dt_clock_t clk) {
  if (clk < kDtClockCount) {
    return clock_main_freq_hz() / clock_freq_dividers[clk];
  }
  return 0;
}
