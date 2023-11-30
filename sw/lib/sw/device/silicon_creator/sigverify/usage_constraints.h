// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_SIGVERIFY_USAGE_CONSTRAINTS_H_
#define OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_SIGVERIFY_USAGE_CONSTRAINTS_H_

#include "sw/device/silicon_creator/lib/drivers/lifecycle.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

/**
 * Usage constraints.
 *
 * This struct is used to constrain a boot stage image to a set of devices based
 * on their device IDs, creator and/or owner manufacturing states, and life
 * cycle states. Bits of `selector_bits` determine which fields (or individual
 * words of a field as in the case of `device_id`) must be read from the
 * hardware during verification. Unselected fields must be set to
 * `MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL` to be able to generate a
 * consistent value during verification.
 */
typedef struct usage_constraints {
  /**
   * Usage constraint selector bits.
   *
   * The bits of this field are mapped to the remaining fields as follows:
   * - Bits 0-7: `device_id[0-7]`
   * - Bit 8   : `manuf_state_creator`
   * - Bit 9   : `manuf_state_owner`
   * - Bit 10  : `life_cycle_state`
   */
  uint32_t selector_bits;
  /**
   * Device identifier value which is compared against the `DEVICE_ID` value
   * stored in the `HW_CFG0` partition in OTP.
   *
   * Mapped to bits 0-7 of `selector_bits`.
   */
  lifecycle_device_id_t device_id;
  /**
   * Device Silicon Creator manufacting status compared against the
   * `CREATOR_SW_MANUF_STATUS` value stored in the `CREATOR_SW_CFG` partition in
   * OTP.
   *
   * Mapped to bit 8 of `selector_bits`.
   */
  uint32_t manuf_state_creator;
  /**
   * Device Silicon Owner manufacturing status compared against the
   * `OWNER_SW_MANUF_STATUS` value stored in the `OWNER_SW_CFG` partition in
   * OTP.
   *
   * Mapped to bit 9 of `selector_bits`.
   */
  uint32_t manuf_state_owner;
  /**
   * Device life cycle status compared against the status reported by the life
   * cycle controller.
   *
   * Mapped to bit 10 of `selector_bits`.
   */
  uint32_t life_cycle_state;
} usage_constraints_t;

/**
 * Value to use for unselected usage constraint words.
 */
#define MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL 0xA5A5A5A5

/**
 * `selector_bits` bit indices for usage constraints fields.
 */
enum {
  /**
   * Bits mapped to the `device_id` field.
   */
  kUsageConstraintsSelectorBitDeviceIdFirst = 0,
  kUsageConstraintsSelectorBitDeviceIdLast = 7,

  /**
   * Bit mapped to the `manuf_state_creator` field.
   */
  kUsageConstraintsSelectorBitManufStateCreator = 8,
  /**
   * Bit mapped to the `manuf_state_owner` field.
   */
  kUsageConstraintsSelectorBitManufStateOwner = 9,
  /**
   * Bit mapped to the `life_cycle_state` field.
   */
  kUsageConstraintsSelectorBitLifeCycleState = 10,
};

/**
 * Gets the usage constraints struct that is used for verifying boot stage
 * images stored in flash.
 *
 * This function reads
 * - The device identifier from the life cycle controller,
 * - Creator and owner manufacturing states from the OTP,
 * - The life cycle state from life cycle controller, and
 * masks the fields of `usage_constraints` according to the given
 * `selector_bits`.
 *
 * See also: `usage_constraints_t`.
 *
 * @param selector_bits Selector bits to be verified.
 * @param[out] usage_constraints Usage constraints.
 */
void sigverify_usage_constraints_get(
    uint32_t selector_bits, usage_constraints_t *usage_constraints);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_SIGVERIFY_USAGE_CONSTRAINTS_H_
