// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/lib/sw/device/silicon_creator/rom_patch.h"

#include <stddef.h>
#include <stdint.h>

#include "sw/device/silicon_creator/lib/drivers/otp.h"
#include "sw/lib/sw/device/base/hardened_memory.h"
#include "sw/lib/sw/device/runtime/hart.h"
#include "sw/lib/sw/device/silicon_creator/base/sec_mmio.h"
#include "sw/lib/sw/device/silicon_creator/rom_print.h"
#include "sw/lib/sw/device/silicon_creator/sigverify/sigverify.h"

#include "hw/top_darjeeling/sw/autogen/top_darjeeling.h"
#include "otp_ctrl_regs.h"  // Generated.
#include "rv_core_ibex_regs.h"

#define IBEX_IBUS_ADDR_MATCHING_REG(i) \
  (RV_CORE_IBEX_IBUS_ADDR_MATCHING_0_REG_OFFSET + 4 * (i))
#define IBEX_IBUS_ADDR_EN_REG(i) \
  (RV_CORE_IBEX_IBUS_ADDR_EN_0_REG_OFFSET + 4 * (i))

#define IBEX_DBUS_ADDR_MATCHING_REG(i) \
  (RV_CORE_IBEX_DBUS_ADDR_MATCHING_0_REG_OFFSET + 4 * (i))
#define IBEX_DBUS_ADDR_EN_REG(i) \
  (RV_CORE_IBEX_DBUS_ADDR_EN_0_REG_OFFSET + 4 * (i))

#define IBEX_IBUS_REMAP_ADDR_REG(i) \
  (RV_CORE_IBEX_IBUS_REMAP_ADDR_0_REG_OFFSET + 4 * (i))
#define IBEX_DBUS_REMAP_ADDR_REG(i) \
  (RV_CORE_IBEX_DBUS_REMAP_ADDR_0_REG_OFFSET + 4 * (i))

#define IBEX_IBUS_REGWEN_REG(i) \
  (RV_CORE_IBEX_IBUS_REGWEN_0_REG_OFFSET + 4 * (i))
#define IBEX_DBUS_REGWEN_REG(i) \
  (RV_CORE_IBEX_DBUS_REGWEN_0_REG_OFFSET + 4 * (i))

#define ROM_PATCH_FIELD(field, shift, length)                              \
  enum { PATCH_REGION_##field##_SHIFT = (shift) };                         \
  enum { PATCH_REGION_##field##_LENGTH = (length) };                       \
  enum {                                                                   \
    PATCH_REGION_##field##_MASK = (((~0UL) >> (32 - (length))) << (shift)) \
  };

ROM_PATCH_FIELD(LOCK_VALID, 0, 4)
ROM_PATCH_FIELD(PROGRAM_START, 4, 4)
ROM_PATCH_FIELD(SIZE, 8, 16)
ROM_PATCH_FIELD(REVISION, 24, 8)

#define ROM_PATCH_FIELD_VALUE(p, field)              \
  (((((p)->header) & PATCH_REGION_##field##_MASK) >> \
    PATCH_REGION_##field##_SHIFT))

#define ROM_PATCH_MATCH_FIELD(field, shift, length)                       \
  enum { PATCH_MATCH_##field##_SHIFT = (shift) };                         \
  enum { PATCH_MATCH_##field##_LENGTH = (length) };                       \
  enum {                                                                  \
    PATCH_MATCH_##field##_MASK = (((~0UL) >> (32 - (length))) << (shift)) \
  };

ROM_PATCH_MATCH_FIELD(M_BASE, 0, 27)
ROM_PATCH_MATCH_FIELD(P_SIZE, 27, 4)
ROM_PATCH_MATCH_FIELD(LOCKED, 31, 1)

#define ROM_PATCH_MATCH_FIELD_VALUE(m, field)       \
  (((((m)->m_base) & PATCH_MATCH_##field##_MASK) >> \
    PATCH_MATCH_##field##_SHIFT))

enum {
  kIbexBase = TOP_DARJEELING_RV_CORE_IBEX_CFG_BASE_ADDR,
  kOtpBase = TOP_DARJEELING_OTP_CTRL_CORE_BASE_ADDR,
  kSwConfig = OTP_CTRL_SW_CFG_WINDOW_REG_OFFSET,
};

enum {
  kRomPatchBaseAddr = OTP_CTRL_PARAM_ROM_PATCH_OFFSET,
  kRomPatchMaxAddr =
      kRomPatchBaseAddr + (OTP_CTRL_PARAM_NUM_SW_CFG_WINDOW_WORDS * 4),
  kRomPatchInvalidAddr = UINTPTR_MAX,
  kRomPatchRegionHeaderSize = 4,
  kRomPatchRegionMatchTableSize = 256,  // 32 * 2 DWORDs
  kRomPatchRegionSignatureSize = kSigVerifyRsaNumBytes,
  // Preamble is the patch header and the complete match table.
  kRomPatchRegionPreambleSize =
      kRomPatchRegionHeaderSize + kRomPatchRegionMatchTableSize,
};

#define PATCH_REGION_CODE_SIZE(p)                                       \
  (ROM_PATCH_FIELD_VALUE((p), SIZE) << 2) - kRomPatchRegionHeaderSize - \
      kRomPatchRegionMatchTableSize - kRomPatchRegionSignatureSize

static inline bool rom_patch_lock_valid(const rom_patch_t *patch) {
  HARDENED_CHECK_NE(patch, NULL);
  return ROM_PATCH_FIELD_VALUE(patch, LOCK_VALID) == kMultiBitBool4True;
}

static inline uint8_t rom_patch_revision(const rom_patch_t *patch) {
  HARDENED_CHECK_NE(patch, NULL);
  return ROM_PATCH_FIELD_VALUE(patch, REVISION);
}

static inline uint16_t rom_patch_size(const rom_patch_t *patch) {
  HARDENED_CHECK_NE(patch, NULL);
  return (uint16_t)ROM_PATCH_FIELD_VALUE(patch, SIZE);
}

static inline size_t rom_patch_code_size(const rom_patch_t *patch) {
  HARDENED_CHECK_NE(patch, NULL);
  return PATCH_REGION_CODE_SIZE(patch);
}

static inline size_t rom_patch_region_enabled(
    const rom_patch_match_regs_t *match) {
  HARDENED_CHECK_NE(match, NULL);
  return match->m_base != 0 && match->r_base != 0;
}

static inline bool rom_patch_region_locked(
    const rom_patch_match_regs_t *match) {
  HARDENED_CHECK_NE(match, NULL);
  return ROM_PATCH_MATCH_FIELD_VALUE(match, LOCKED) == 1;
}

static inline size_t rom_patch_region_size(
    const rom_patch_match_regs_t *match) {
  HARDENED_CHECK_NE(match, NULL);
  return ROM_PATCH_MATCH_FIELD_VALUE(match, P_SIZE);
}

static inline uint32_t rom_patch_region_r_base(
    const rom_patch_match_regs_t *match) {
  HARDENED_CHECK_NE(match, NULL);
  return match->r_base;
}

static inline uint32_t rom_patch_region_m_base(
    const rom_patch_match_regs_t *match) {
  HARDENED_CHECK_NE(match, NULL);
  return ROM_PATCH_MATCH_FIELD_VALUE(match, M_BASE);
}

bool rom_patch_valid(const uintptr_t patch_addr) {
  if (patch_addr == kRomPatchInvalidAddr || patch_addr < kRomPatchBaseAddr ||
      patch_addr > kRomPatchMaxAddr) {
    return false;
  }

  uint32_t patch_header = otp_read32(patch_addr);
  rom_patch_t *patch = (rom_patch_t *)(&patch_header);

  return !!rom_patch_size(patch);
}

OT_WARN_UNUSED_RESULT uintptr_t rom_patch_latest(void) {
  size_t next_patch_offset = 0;
  size_t latest_patch_offset = SIZE_MAX;
  size_t current_patch_size = 0;
  rom_patch_t *current_patch = NULL;
  uint8_t current_patch_revision = 0;
  uint8_t latest_patch_revision = 0;
  uint32_t patch_header;

  do {
    patch_header = otp_read32(kRomPatchBaseAddr + next_patch_offset);
    current_patch = (rom_patch_t *)(&patch_header);
    current_patch_size = rom_patch_size(current_patch);
    current_patch_revision = rom_patch_revision(current_patch);

    /*
     * Check if the current patch is better than the latest, i.e.:
     * - It is valid, i.e. it's been fully programmed.
     * - It has a strictly higher revision number.
     */
    if (rom_patch_lock_valid(current_patch) &&
        (current_patch_revision > latest_patch_revision)) {
      // Found a better patch, let's keep it.
      latest_patch_offset = next_patch_offset;
      latest_patch_revision = current_patch_revision;
    }

    next_patch_offset += current_patch_size * 4;
  } while (current_patch_size > 0 &&
           next_patch_offset < OTP_CTRL_PARAM_NUM_SW_CFG_WINDOW_WORDS * 4);

  if (latest_patch_offset == SIZE_MAX) {
    return kRomPatchInvalidAddr;
  }

  patch_header = otp_read32(kRomPatchBaseAddr + latest_patch_offset);
  OT_DISCARD(rom_printf("Latest patch header 0x%x\n", patch_header));

  return (uintptr_t)(kRomPatchBaseAddr + latest_patch_offset);
}

static OT_WARN_UNUSED_RESULT rom_error_t rom_patch_verify_sig(
    const rom_patch_t *patch, const hmac_digest_t *patch_digest) {
  /*
   * TODO sameo
   * Verify that the loaded code matches the OTP signature.
   */
  return kErrorOk;
}

static OT_WARN_UNUSED_RESULT rom_error_t
rom_patch_remap(const rom_patch_t *patch) {
  for (uint32_t i = 0; i < RV_CORE_IBEX_PARAM_NUM_REGIONS; i++) {
    const rom_patch_match_regs_t *match = &patch->table[i];
    // If patch is not enabled, skip it.
    if (!rom_patch_region_enabled(match)) {
      continue;
    }

    uint32_t patch_size_bytes = (uint32_t)(rom_patch_region_size(match) << 2);
    uint32_t m_base = rom_patch_region_m_base(match);
    uint32_t r_base = rom_patch_region_r_base(match);
    uint32_t mask =
        (m_base & ~(patch_size_bytes - 1)) | ((patch_size_bytes - 1) >> 1);

    sec_mmio_write32(kIbexBase + IBEX_IBUS_ADDR_MATCHING_REG(i), mask);
    sec_mmio_write32(kIbexBase + IBEX_IBUS_REMAP_ADDR_REG(i), r_base);
    sec_mmio_write32(kIbexBase + IBEX_IBUS_ADDR_EN_REG(i), 1);
    if (rom_patch_region_locked(match)) {
      sec_mmio_write32(kIbexBase + IBEX_IBUS_REGWEN_REG(i), 0);
    }

    OT_DISCARD(rom_printf("Configured Ibex remapping reg 0x%x->0x%x %x\n", mask,
                          r_base, rom_patch_region_locked(match)));
  }

  icache_invalidate();

  return kErrorOk;
}

OT_WARN_UNUSED_RESULT rom_error_t
rom_patch_apply(const uintptr_t patch_addr, hmac_digest_t *const patch_digest) {
  size_t patch_code_offset = kRomPatchRegionPreambleSize;
  uint32_t patch_preamble_bytes[kRomPatchRegionPreambleSize];
  rom_patch_t *patch;

  hmac_sha256_init();

  // Read the patch preamble from OTP.
  otp_read(patch_addr, patch_preamble_bytes, kRomPatchRegionPreambleSize);
  patch = (rom_patch_t *)(patch_preamble_bytes);

  // The first header byte (LOCK_VALID & PROGRAM_START) is not signed.
  hmac_sha256_update(patch_preamble_bytes + 1, kRomPatchRegionPreambleSize - 1);

  // The patch code size must not be 0.
  size_t patch_code_size_bytes = rom_patch_code_size(patch);
  HARDENED_CHECK_NE(patch_code_size_bytes, 0);

  // The remapping base address is the first entry in the match table.
  const rom_patch_match_regs_t *match = &patch->table[0];
  uint32_t remap_addr = rom_patch_region_r_base(match);

  /*
   * Read the whole patch section, dword by dword, and copy it to the
   * remapped address.
   */
  for (size_t i = 0; i < patch_code_size_bytes; i += 4) {
    uint32_t insn = otp_read32(patch_addr + patch_code_offset + i);
    hmac_sha256_update(&insn, 4);

    sec_mmio_write32(remap_addr + i, insn);
  }

  hmac_sha256_final(patch_digest);

  // Verify the patch signature
  HARDENED_RETURN_IF_ERROR(rom_patch_verify_sig(patch, patch_digest));

  // Remap and enable each patches
  RETURN_IF_ERROR(rom_patch_remap(patch));

  return kErrorOk;
}
