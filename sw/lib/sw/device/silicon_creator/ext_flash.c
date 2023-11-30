// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#include "sw/lib/sw/device/base/hardened_memory.h"
#include "sw/lib/sw/device/silicon_creator/ext_flash.h"
#include "sw/lib/sw/device/silicon_creator/spi_nor_flash.h"

static const union {
    part_desc_t partition;
    bundle_signature_t signature;
    asset_manifest_t asset_manifest;
} dummies = { 0 };

OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_parse_partition_table(const uint8_t *buffer,
                                            size_t length,
                                            part_table_t *part_table)
{
    size_t offset;

    // Point to partition table
    if (sizeof(part_table_header_t) > length) {
        return kErrorExtFlashInvalidPartTable;
    }
    part_table->header = (part_table_header_t*)&buffer[0];
    offset = sizeof(part_table_header_t);

    // Check partition table expected constants
    if (part_table->header->magic_number != PARTITION_TABLE_MAGIC_NUMBER) {
        return kErrorExtFlashInvalidPartTable;
    }
    if (part_table->header->version.version_major != EXT_FLASH_VERSION_MAJOR) {
        return kErrorExtFlashInvalidPartTable;
    }

    // Check overflow of number of partitions
    if (part_table->header->part_count > EXT_FLASH_MAX_PARTITIONS) {
        return kErrorExtFlashInvalidPartTable;
    }

    // Point to partitions
    if (offset + sizeof(part_desc_t) * part_table->header->part_count > length) {
        return kErrorExtFlashInvalidPartTable;
    }
    for (uint32_t index = 0; index < EXT_FLASH_MAX_PARTITIONS; index++) {
        if (index < part_table->header->part_count) {
            part_table->partitions[index] = (part_desc_t*)&buffer[offset];
            offset += sizeof(part_desc_t);
        } else {
            part_table->partitions[index] = &dummies.partition;
        }
    }

    return kErrorOk;
}

OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_parse_bundle(const uint8_t *buffer,
                                   size_t length,
                                   bundle_manifest_t *bundle,
                                   size_t *used)
{
    size_t offset;

    // Point to signature header
    if (sizeof(bundle_signature_header_t) > length) {
        return kErrorExtFlashInvalidBundle;
    }
    bundle->sig_header = (bundle_signature_header_t*)&buffer[0];
    offset = sizeof(bundle_signature_header_t);

    // Check overflow of number of signatures
    if (bundle->sig_header->signature_count > EXT_FLASH_MAX_BUNDLE_SIGNATURES) {
        return kErrorExtFlashInvalidBundle;
    }

    // Point to signatures
    if (offset + sizeof(bundle_signature_t) * bundle->sig_header->signature_count > length) {
        return kErrorExtFlashInvalidBundle;
    }
    for (uint32_t index = 0; index < EXT_FLASH_MAX_BUNDLE_SIGNATURES; index++) {
        if (index < bundle->sig_header->signature_count) {
            bundle->signatures[index] = (bundle_signature_t*)&buffer[offset];
            offset += sizeof(bundle_signature_t);
        } else {
            bundle->signatures[index] = &dummies.signature;
        }
    }

    // Point to bundle header
    if (offset + sizeof(bundle_header_t) > length) {
        return kErrorExtFlashInvalidBundle;
    }
    bundle->header = (bundle_header_t*)&buffer[offset];
    bundle->asset_start = offset;
    offset += sizeof(bundle_header_t);

    if (bundle->header->version.version_major != EXT_FLASH_VERSION_MAJOR) {
        return kErrorExtFlashInvalidBundle;
    }

    // Check overflow of number of asset manifests
    if (bundle->header->asset_count > EXT_FLASH_MAX_BUNDLE_ASSETS) {
        return kErrorExtFlashInvalidBundle;
    }

    // Point to asset manifests
    if (offset + sizeof(asset_manifest_t) * bundle->header->asset_count > length) {
        return kErrorExtFlashInvalidBundle;
    }
    for (uint32_t index = 0; index < EXT_FLASH_MAX_BUNDLE_ASSETS; index++) {
        if (index < bundle->header->asset_count) {
            bundle->assets[index] = (asset_manifest_t*)&buffer[offset];
            offset += sizeof(asset_manifest_t);
        } else {
            bundle->assets[index] = &dummies.asset_manifest;
        }
    }

    if (used)
        *used = offset;

    return kErrorOk;
}


OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_lookup_partition(uint32_t csid, uint32_t part_id, uint16_t part_type, part_desc_t *partition) {
  // read enough data for partition table (always at flash offset 0)
  uint8_t pt_buffer[EXT_FLASH_PART_TABLE_BUFFER_SIZE];
  HARDENED_RETURN_IF_ERROR(
      spi_nor_flash_read(csid, 0, sizeof(pt_buffer), pt_buffer));

  // Parse partition table
  part_table_t pt = {0};
  HARDENED_RETURN_IF_ERROR(
      ext_flash_parse_partition_table(pt_buffer, sizeof(pt_buffer), &pt));

  // Look for matching partition
  uint32_t idx;
  for (idx = 0; idx < pt.header->part_count; idx++) {
      // TODO: Handle slots: this currently stops at the first matching partition
      if (pt.partitions[idx]->identifier == part_id &&
          pt.partitions[idx]->type == part_type) {
        break;
      }
  }
  if (idx == pt.header->part_count) {
      // Matching partition not found
      return kErrorExtFlashPartitionNotFound;
  }

  // TODO: check start_address and size? (need to know the flash size!)

  *partition = *pt.partitions[idx];
  return kErrorOk;
}

OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_lookup_asset(uint32_t csid, const part_desc_t *partition,
        uint32_t asset_id, uint16_t asset_type, asset_manifest_t *asset) {
  uint32_t flash_offset = partition->start_address;

  // Load enough data for a complete bundle manifest.
  // We may overflow the partition here but it's checked later
  uint8_t bundle_buffer[EXT_FLASH_BUNDLE_BUFFER_SIZE];
  HARDENED_RETURN_IF_ERROR(
      spi_nor_flash_read(csid, partition->start_address, sizeof(bundle_buffer), bundle_buffer));

  // Parse the bundle signatures/manifest
  bundle_manifest_t bundle = {0};
  uint32_t used = 0;
  HARDENED_RETURN_IF_ERROR(
      ext_flash_parse_bundle(bundle_buffer, sizeof(bundle_buffer), &bundle, &used));
  flash_offset += bundle.asset_start;
  if (used > partition->size) {
      // Bundle overflows its partition
      return kErrorExtFlashInvalidBundle;
  }

  // TODO: Verify bundle signature(s) here

  // Look for asset
  uint32_t idx;
  for (idx = 0; idx < bundle.header->asset_count; idx++) {
      if (bundle.assets[idx]->identifier == asset_id &&
          bundle.assets[idx]->type == asset_type) {
        break;
      }
  }
  if (idx == bundle.header->asset_count) {
      // Firmware asset not found
      return kErrorExtFlashAssetNotFound;
  }

  *asset = *bundle.assets[idx];

  // Adjust asset offset to make it relative to flash origin
  asset->start += flash_offset;

  return kErrorOk;
}

OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_load_firmware(uint32_t csid,
        const asset_manifest_t *asset, uint32_t load_addr, uint32_t virtual_addr,
        uint32_t max_size, firmware_desc_t *firmware) {
  // Load firmware descriptor
  HARDENED_RETURN_IF_ERROR(
      spi_nor_flash_read(csid, asset->start, sizeof(*firmware), firmware));

  uint32_t firmware_offset = asset->start + sizeof(*firmware);
  uint32_t firmware_size = asset->size - sizeof(*firmware);

  // Sanity checks
  if (firmware_size > max_size) {
    // Asset too big for destination region
    return kErrorExtFlashInvalidAsset;
  }
  if (firmware->entry_point < virtual_addr ||
      firmware->entry_point >= (virtual_addr + max_size)) {
    // Entry point outside of bounds
    return kErrorExtFlashBadAssetEntryPoint;
  }
  if (firmware->code_start >= firmware->code_end) {
    // Code start after code end
    return kErrorExtFlashBadAssetCodeRegion;
  }
  if (firmware->code_start < virtual_addr ||
      firmware->code_start >= (virtual_addr + firmware_size) ||
      firmware->code_end < virtual_addr ||
      firmware->code_end >= (virtual_addr + firmware_size)) {
    // Code start/end outside of bounds
    return kErrorExtFlashBadAssetCodeRegion;
  }

  // Load firmware
  HARDENED_RETURN_IF_ERROR(
      spi_nor_flash_read(csid, firmware_offset, firmware_size, (void *)load_addr));

  // Compute digest
  hmac_sha256_init();
  hmac_sha256_update(firmware, sizeof(*firmware));
  hmac_sha256_update((void*)load_addr, firmware_size);
  // Verify digest
  hmac_digest_t digest;
  hmac_sha256_final(&digest);
  hardened_bool_t digest_ok = hardened_memeq(digest.digest, asset->digest.digest, kHmacDigestNumWords);
  if (launder32(digest_ok) != kHardenedBoolTrue) {
    // Invalid firmware digest
    return kErrorExtFlashBadAssetDigest;
  }

  return kErrorOk;
}
