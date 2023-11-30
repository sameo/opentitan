// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#ifndef OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_EXT_FLASH_H_
#define OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_EXT_FLASH_H_

#include <stddef.h>

#include "sw/device/silicon_creator/lib/drivers/hmac.h"
#include "sw/lib/sw/device/base/macros.h"
#include "sw/lib/sw/device/silicon_creator/error.h"
#include "sw/lib/sw/device/silicon_creator/keymgr_binding_value.h"
#include "sw/lib/sw/device/silicon_creator/sigverify/rsa_key.h"
#include "sw/lib/sw/device/silicon_creator/sigverify/usage_constraints.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// FIXME: these could be defined in a top-specific file (chip.h?)
#define EXT_FLASH_MAX_PARTITIONS 2
#define EXT_FLASH_MAX_BUNDLE_SIGNATURES 2
#define EXT_FLASH_MAX_BUNDLE_ASSETS 8

/**
 * Major version number for this flash format.
 */
#define EXT_FLASH_VERSION_MAJOR 0

/**
 * Minor version number for this flash format.
 */
#define EXT_FLASH_VERSION_MINOR 1

typedef struct ext_flash_version {
    uint16_t version_major;
    uint16_t version_minor;
} ext_flash_version_t;

OT_ASSERT_MEMBER_OFFSET(ext_flash_version_t, version_major, 0);
OT_ASSERT_MEMBER_OFFSET(ext_flash_version_t, version_minor, 2);
OT_ASSERT_SIZE(ext_flash_version_t, 4);

/**
 * Header for external flash Partition Table.
 *
 * The partition table header is followed by `part_count` Partition Descritors
 * of type `part_desc_t`.
 */
typedef struct part_table_header {
  /**
   * Magic number to identify a Partition Table.
   */
  uint32_t magic_number;
  /**
   * External Flash format version.
   */
  ext_flash_version_t version;
  /**
   * Number of partitions.
   */
  uint32_t part_count;
} part_table_header_t;

OT_ASSERT_MEMBER_OFFSET(part_table_header_t, magic_number, 0);
OT_ASSERT_MEMBER_OFFSET(part_table_header_t, version, 4);
OT_ASSERT_MEMBER_OFFSET(part_table_header_t, part_count, 8);
OT_ASSERT_SIZE(part_table_header_t, 12);

/**
 * Partition Table Magic Number (ASCII "OTPT").
 */
#define PARTITION_TABLE_MAGIC_NUMBER 0x5450544f

/**
 * Descriptor for an external flash Partition.
 */
typedef struct part_desc {
  /**
   * Partition identifier.
   */
  uint32_t identifier;
  /**
   * Partition type.
   */
  uint16_t type;
  /**
   * Partition slot number.
   * Use PARTITION_SLOT_NUMBER_UNDEFINED_VAL if not used.
   */
  uint16_t slot_number;
  /**
   * Start of the partition in flash (in bytes from the start of the flash).
   */
  uint32_t start_address;
  /**
   * Maximum size in bytes allocated for the partition.
   */
  uint32_t size;
} part_desc_t;

OT_ASSERT_MEMBER_OFFSET(part_desc_t, identifier, 0);
OT_ASSERT_MEMBER_OFFSET(part_desc_t, type, 4);
OT_ASSERT_MEMBER_OFFSET(part_desc_t, slot_number, 6);
OT_ASSERT_MEMBER_OFFSET(part_desc_t, start_address, 8);
OT_ASSERT_MEMBER_OFFSET(part_desc_t, size, 12);
OT_ASSERT_SIZE(part_desc_t, 16);

/**
 * Value to use for unused slot number.
 */
#define PARTITION_SLOT_NUMBER_UNDEFINED_VAL 0xA5A5

/**
 * ROM_EXT partition identifier (ASCII "OTRE").
 *
 * This partition should contain a Bundle with at least an OTRE firmware.
 */
#define PARTITION_ROM_EXT_IDENTIFIER 0x4552544f

/**
 * Platform Firmwares partition identifier (ASCII "OTPF").
 *
 * This partition should contain a Bundle with at least an OTB0 firmware.
 */
#define PARTITION_PLATFORM_FIRMWARES_IDENTIFIER 0x4650544f

/**
 * Partition Types.
 */
enum {
  /**
   * Partition type "Bundle".
   */
  kPartTypeBundle = 0x0,

  /**
   * Partition type "Key Manifest".
   */
  kPartTypeKeyManifest = 0x1,
};

typedef struct part_table {
  /**
   * Partition table header.
   */
  const part_table_header_t *header;
  /**
   * Partitions descriptors.
   */
  const part_desc_t *partitions[EXT_FLASH_MAX_PARTITIONS];
} part_table_t;

#define EXT_FLASH_PART_TABLE_BUFFER_SIZE \
        (sizeof(part_table_header_t) + \
         sizeof(part_desc_t) * EXT_FLASH_MAX_PARTITIONS)

/**
 * Header for external flash Bundle Signatures.
 *
 * The bundle signature header is followed by `signature_count` Bundle Signatures
 * of type `bundle_signature_t`.
 */
typedef struct bundle_signature_header {
  /**
   * Number of signatures.
   */
  uint32_t signature_count;
} bundle_signature_header_t;

OT_ASSERT_MEMBER_OFFSET(bundle_signature_header_t, signature_count, 0);
OT_ASSERT_SIZE(bundle_signature_header_t, 4);

/**
 * Descriptor for a Bundle Signature.
 */
typedef struct bundle_signature {
  /**
   * Signature.
   */
  sigverify_rsa_buffer_t signature; // FIXME: switch to ECDSA signature?
  /**
   * Key Owner for the key used for the signature.
   */
  uint32_t key_owner;
} bundle_signature_t;

OT_ASSERT_MEMBER_OFFSET(bundle_signature_t, signature, 0);
OT_ASSERT_MEMBER_OFFSET(bundle_signature_t, key_owner, 384);
OT_ASSERT_SIZE(bundle_signature_t, 388);

/**
 * Key Owners
 */
enum {
  /**
   * Key owner "Silicon Creator".
   */
  kKeyOwnerSiliconCreator = 0x0,

  /**
   * Key owner "Silicon Owner".
   */
  kKeyOwnerSiliconOwner = 0x1,

  /**
   * Key owner "Platform Integrator".
   */
  kKeyOwnerPlatformIntegrator = 0x2,

  /**
   * Key owner "Platform Owner".
   */
  kKeyOwnerPlatformOwner = 0x3,
};

#define MANIFEST_USAGE_CONSTRAINT_UNSELECTED_WORD_VAL 0xA5A5A5A5

/**
 * Unix timestamp in seconds since
 * 00:00:00 on January 1, 1970 UTC (the Unix Epoch).
 */
typedef struct timestamp {
  /**
   * Least significant word of the timestamp.
   */
  uint32_t timestamp_low;
  /**
   * Most significant word of the timestamp.
   */
  uint32_t timestamp_high;
} timestamp_t;

/**
 * Header for external flash Bundle.
 *
 * The bundle header is followed by `asset_count` Asset Manifests
 * of type `asset_manifest_t`.
 */
typedef struct bundle_header {
  // FIXME: add a magic number?
  /**
   * External Flash format version.
   */
  ext_flash_version_t version;
  /**
   * Usage constraints.
   */
  usage_constraints_t usage_constraints;
  /**
   * Security version of the bundle used for anti-rollback protection.
   */
  uint32_t security_version;
  /**
   * Creation time of the bundle.
   */
  timestamp_t timestamp;
  /**
   * Binding value used by key manager to derive secret values.
   *
   * A change in this value changes the secret value of key manager, and
   * consequently, the versioned keys and identity seeds generated at subsequent
   * boot stages.
   */
  keymgr_binding_value_t binding_value;
  /**
   * Maximum allowed version for keys generated at the next boot stage.
   */
  uint32_t max_key_version;
  /**
   * Number of assets.
   */
  uint32_t asset_count;
} bundle_header_t;

OT_ASSERT_MEMBER_OFFSET(bundle_header_t, version, 0);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, usage_constraints, 4);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, security_version, 52);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, timestamp, 56);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, binding_value, 64);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, max_key_version, 96);
OT_ASSERT_MEMBER_OFFSET(bundle_header_t, asset_count, 100);
OT_ASSERT_SIZE(bundle_header_t, 104);

/**
 * Manifest for a bundle asset.
 */
typedef struct asset_manifest {
  /**
   * Asset identifier.
   */
  uint32_t identifier;
  /**
   * Asset digest (SHA256).
   */
  hmac_digest_t digest;
  /**
   * Unused field.
   */
  uint16_t reserved;
  /**
   * Type of asset.
   */
  uint16_t type;
  /**
   * Start offset of the asset (in bytes from the start of the bundle header).
   */
  uint32_t start;
  /**
   * Size in bytes of the asset.
   */
  uint32_t size;
} asset_manifest_t;

OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, identifier, 0);
OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, digest, 4);
OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, reserved, 36);
OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, type, 38);
OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, start, 40);
OT_ASSERT_MEMBER_OFFSET(asset_manifest_t, size, 44);
OT_ASSERT_SIZE(asset_manifest_t, 48);

/**
 * ROM_EXT asset identifier (ASCII "OTRE").
 */
#define ASSET_ROM_EXT_IDENTIFIER 0x4552544f

/**
 * BL0 (Owner Stage) asset identifier (ASCII "OTB0").
 */
#define ASSET_BL0_IDENTIFIER 0x3042544f

/**
 * Asset Types.
 */
enum {
  /**
   * Asset type "Raw Data".
   */
  kAssetTypeRawData = 0x0,

  /**
   * Asset type "Firmware".
   */
  kAssetTypeFirmware = 0x1,
};

/**
 * Descriptor for a firmware asset.
 */
typedef struct firmware_desc {
  /**
   * Absolute address of the first instruction to execute in the firmware.
   */
  uint32_t entry_point;
  /**
   * Absolute address of the start of the executable region of the firmware.
   */
  uint32_t code_start;
  /**
   * Absolute address of the end of the executable region of the firmware
   * (exclusive).
   */
  uint32_t code_end;
} firmware_desc_t;

OT_ASSERT_MEMBER_OFFSET(firmware_desc_t, entry_point, 0);
OT_ASSERT_MEMBER_OFFSET(firmware_desc_t, code_start, 4);
OT_ASSERT_MEMBER_OFFSET(firmware_desc_t, code_end, 8);
OT_ASSERT_SIZE(firmware_desc_t, 12);

/**
 * Manifest for a bundle.
 */
typedef struct bundle_manifest {
  /**
   * Signature header.
   */
  const bundle_signature_header_t *sig_header;
  /**
   * Signatures.
   */
  const bundle_signature_t *signatures[EXT_FLASH_MAX_BUNDLE_SIGNATURES];
  /**
   * Bundle Header.
   */
  const bundle_header_t *header;
  /**
   * Start offset in flash for asset data
   */
  uint32_t asset_start;
  /**
   * Assets.
   */
  const asset_manifest_t *assets[EXT_FLASH_MAX_BUNDLE_ASSETS];
} bundle_manifest_t;

#define EXT_FLASH_BUNDLE_BUFFER_SIZE \
        (sizeof(bundle_signature_header_t) + \
         sizeof(bundle_signature_t) * EXT_FLASH_MAX_BUNDLE_SIGNATURES + \
         sizeof(bundle_header_t) + \
         sizeof(asset_manifest_t) * EXT_FLASH_MAX_BUNDLE_ASSETS)


/**
 * Parse a buffer into a partition table structure.
 *
 * This function parses a given buffer into a partition structure.
 *
 * Warning: the partition structure returned contains pointers into the buffer
 * to avoid copying data. Callers must be careful to handle the lifecycle of the
 * variables accordingly.
 *
 * @param buffer A buffer to parse.
 * @param length The buffer length.
 * @param part_table Pointer to a partition table structure that will be filled.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_parse_partition_table(const uint8_t *buffer,
                                            size_t length,
                                            part_table_t *part_table);

/**
 * Parse a buffer into a bundle structure.
 *
 * This function parses a given buffer into a bundle structure.
 *
 * Warning: the bundle structure returned contains pointers into the buffer to
 * avoid copying data. Callers must be careful to handle the lifecycle of the
 * variables accordingly.
 *
 * @param buffer A buffer to parse.
 * @param length The buffer length.
 * @param bundle Pointer to a bundle structure that will be filled.
 * @param used Pointer to an int that will be updated with the number of bytes parsed.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_parse_bundle(const uint8_t *buffer,
                                   size_t length,
                                   bundle_manifest_t *bundle,
                                   size_t *used);

/**
 * Load partition information from flash.
 *
 * This function looks for a given partition. It will load from flash the
 * partition table, parse it then attempt to find a matching partition.
 *
 * @param csid The chip-select ID of the flash memory.
 * @param part_id The expected partition identifier.
 * @param part_type The expected partition type.
 * @param partition Pointer to a partition structure that will be filled.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_lookup_partition(uint32_t csid,
                                       uint32_t part_id,
                                       uint16_t part_type,
                                       part_desc_t *partition);

/**
 * Load asset information from flash.
 *
 * This function looks for a given asset in a bundle. It will load from flash
 * the bundle contained in the partition, parse it then attempt to find a
 * matching asset.
 *
 * TODO: This function is expected to perform the bundle signature(s)
 * verification but currently does not.
 *
 * @param csid The chip-select ID of the flash memory.
 * @param partition The partition containing the bundle.
 * @param asset_id The expected asset identifier.
 * @param asset_type The expected asset type.
 * @param asset Pointer to an asset structure that will be filled.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_lookup_asset(uint32_t csid,
                                   const part_desc_t *partition,
                                   uint32_t asset_id,
                                   uint16_t asset_type,
                                   asset_manifest_t *asset);

/**
 * Load firmware from flash.
 *
 * This function loads from flash a firmware from a firmware asset.
 *
 * This function performs firmware digest verification.
 *
 * @param csid The chip-select ID of the flash memory.
 * @param asset The asset containing the firmware.
 * @param load_addr The address at which to load the firmware.
 * @param virtual_addr The virtual address for the firmware (only used for
 * sanity checks on entry point, code start and code end fields).
 * @param max_load_size Size limit for the loaded firmware.
 * @param firmware Pointer to a firmware structure that will be filled.
 * @return The result of the operation.
 */
OT_WARN_UNUSED_RESULT
rom_error_t ext_flash_load_firmware(uint32_t csid,
                                    const asset_manifest_t *asset,
                                    uint32_t load_addr,
                                    uint32_t virtual_addr,
                                    uint32_t max_load_size,
                                    firmware_desc_t *firmware);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // OPENTITAN_SW_LIB_SW_DEVICE_SILICON_CREATOR_EXT_FLASH_H_
