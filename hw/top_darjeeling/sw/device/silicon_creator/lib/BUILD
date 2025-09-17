# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("//rules/opentitan:defs.bzl", "OPENTITAN_CPU")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "irq_asm",
    srcs = ["irq_asm.S"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//hw/top:aon_timer_c_regs",
        "//hw/top:pwrmgr_c_regs",
        "//hw/top:rstmgr_c_regs",
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:multibits",
    ],
)
