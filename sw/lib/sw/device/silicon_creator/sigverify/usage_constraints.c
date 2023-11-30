// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/lib/sw/device/silicon_creator/sigverify/usage_constraints.h"

#include "sw/device/silicon_creator/lib/drivers/otp.h"
#include "sw/lib/sw/device/base/bitfield.h"
#include "sw/lib/sw/device/base/hardened.h"

#include "otp_ctrl_regs.h"

void sigverify_usage_constraints_get(
    uint32_t selector_bits, usage_constraints_t *usage_constraints) {
  usage_constraints->selector_bits = selector_bits;
  lifecycle_device_id_get(&usage_constraints->device_id);

  usage_constraints->manuf_state_creator =
      otp_read32(OTP_CTRL_PARAM_CREATOR_SW_CFG_MANUF_STATE_OFFSET);
  usage_constraints->manuf_state_owner =
      otp_read32(OTP_CTRL_PARAM_OWNER_SW_CFG_MANUF_STATE_OFFSET);
  usage_constraints->life_cycle_state = lifecycle_state_get();

  static_assert(
      kUsageConstraintsSelectorBitDeviceIdFirst == 0 &&
          kUsageConstraintsSelectorBitDeviceIdLast == kLifecycleDeviceIdNumWords - 1,
      "mapping from selector_bits to device_id changed, loop must be updated");
  for (size_t i = 0; i < kLifecycleDeviceIdNumWords; ++i) {
    if (!bitfield_bit32_read(selector_bits, i)) {
      usage_constraints->device_id.device_id[i] =
          MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL;
    }
  }
  if (!bitfield_bit32_read(selector_bits,
                           kUsageConstraintsSelectorBitManufStateCreator)) {
    usage_constraints->manuf_state_creator =
        MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL;
  }
  if (!bitfield_bit32_read(selector_bits,
                           kUsageConstraintsSelectorBitManufStateOwner)) {
    usage_constraints->manuf_state_owner =
        MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL;
  }
  if (!bitfield_bit32_read(selector_bits, kUsageConstraintsSelectorBitLifeCycleState)) {
    usage_constraints->life_cycle_state =
        MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL;
  }
}
