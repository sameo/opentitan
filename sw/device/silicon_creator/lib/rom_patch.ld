/* Copyright lowRISC contributors. */
/* Licensed under the Apache License, Version 2.0, see LICENSE for details. */
/* SPDX-License-Identifier: Apache-2.0 */

/**
 * Partial linker script for ROM patch region
 */

/**
 * Patch RAM just before stack
 */
_patch_ram_size = 8192;
_patch_ram_end = _stack_start;
_patch_ram_start = _patch_ram_end - _patch_ram_size;

.patch_ram _patch_ram_start (NOLOAD) : ALIGN(4) {
  . = . + _patch_ram_size;
} > ram_main
