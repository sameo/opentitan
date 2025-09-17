# Copyright lowRISC contributors (OpenTitan project).
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

load("@rules_fuzzing//fuzzing:cc_defs.bzl", "cc_fuzz_test")
load("@rules_pkg//pkg:mappings.bzl", "pkg_files")
load("//rules:cross_platform.bzl", "dual_cc_library", "dual_inputs")
load("//rules:files.bzl", "output_groups")
load("//rules:linker.bzl", "ld_library")
load(
    "//rules/opentitan:defs.bzl",
    "OPENTITAN_CPU",
    "fpga_params",
    "opentitan_binary",
    "opentitan_manual_test",
    "opentitan_test",
)
load("//rules/opentitan:legacy.bzl", "legacy_rom_targets")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "rom_isrs",
    srcs = [
        #        "rom_isrs.S",
        "rom_isrs.c",
    ],
    hdrs = ["rom_isrs.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/base:macros",
        "//sw/device/silicon_creator/lib:error",
        "//sw/device/silicon_creator/lib:shutdown",
    ],
)

ld_library(
    name = "base_rom_linker_script",
    script = "base_rom.ld",
    deps = [
        "//hw/top_darjeeling/sw/autogen:top_darjeeling_memory",
        "//sw/device:info_sections",
        "//sw/device/silicon_creator/lib:rom_patch_sections",
    ],
)

cc_library(
    name = "base_rom_epmp",
    srcs = [
        "base_rom_epmp.c",
        "base_rom_epmp_init.S",
    ],
    hdrs = ["base_rom_epmp.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:bitfield",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/base:memory",
        "//sw/device/silicon_creator/lib:epmp_state",
        "//sw/device/silicon_creator/lib/drivers:lifecycle",
    ],
)

cc_library(
    name = "base_rom_common",
    srcs = [
        "base_rom.c",
        "base_rom.h",
    ],
    deps = [
        # ":boot_policy",
        # ":boot_policy_ptrs",
        # ":bootstrap",
        ":base_rom_epmp",
        # ":rom_state",
        # ":sigverify_keys_ecdsa_p256",
        # ":sigverify_keys_spx",
        # ":sigverify_otp_keys",
        # "//hw/top:aon_timer_c_regs",
        "//sw/device/lib/arch:device",
        "//sw/device/lib/base:bitfield",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/base:macros",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/base:stdasm",
        "//sw/device/lib/crt",
        "//sw/device/lib/runtime:hart",
        # "//sw/device/silicon_creator/lib:boot_log",
        # "//sw/device/silicon_creator/lib:cfi",
        # "//sw/device/silicon_creator/lib:chip_info",
        # "//sw/device/silicon_creator/lib:epmp_state",
        # "//sw/device/silicon_creator/lib:error",
        "//hw/top_darjeeling/sw/device/silicon_creator/lib:irq_asm",
        # "//sw/device/silicon_creator/lib:manifest",
        # "//sw/device/silicon_creator/lib:otbn_boot_services",
        "//sw/device/silicon_creator/lib:dbg_print",
        "//sw/device/silicon_creator/lib:shutdown",
        "//sw/device/silicon_creator/lib:stack_utilization",
        "//sw/device/silicon_creator/lib/base:chip",
        "//sw/device/silicon_creator/lib/base:sec_mmio",
        "//sw/device/silicon_creator/lib/base:static_critical",
        "//sw/device/silicon_creator/lib/drivers:alert",
        #"//sw/device/silicon_creator/lib/drivers:ast",
        "//sw/device/silicon_creator/lib/drivers:hmac",
        "//sw/device/silicon_creator/lib/drivers:ibex",
        #"//sw/device/silicon_creator/lib/drivers:keymgr",
        "//sw/device/silicon_creator/lib/drivers:kmac",
        "//sw/device/silicon_creator/lib/drivers:lifecycle",
        "//sw/device/silicon_creator/lib/drivers:otbn",
        "//sw/device/silicon_creator/lib/drivers:otp",
        "//sw/device/silicon_creator/lib/drivers:pinmux",
        "//sw/device/silicon_creator/lib/drivers:pwrmgr",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
        "//sw/device/silicon_creator/lib/drivers:rnd",
        "//sw/device/silicon_creator/lib/drivers:rstmgr",
        "//sw/device/silicon_creator/lib/drivers:watchdog",
        # "//sw/device/silicon_creator/lib/sigverify",
        "@darjeeling_rom_hooks",
    ],
)

cc_library(
    name = "base_rom_lib",
    srcs = ["base_rom_start.S"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        ":base_rom_common",
        ":base_rom_epmp",
        "//hw/top:aon_timer_c_regs",
        "//hw/top:ast_c_regs",
        "//hw/top:clkmgr_c_regs",
        "//hw/top:csrng_c_regs",
        "//hw/top:edn_c_regs",
        "//hw/top:entropy_src_c_regs",
        "//hw/top:lc_ctrl_c_regs",
        "//hw/top:otp_ctrl_c_regs",
        "//hw/top:pwrmgr_c_regs",
        "//hw/top:rstmgr_c_regs",
        "//hw/top:rv_core_ibex_c_regs",
        "//hw/top:sram_ctrl_c_regs",
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:hardened",
        "//sw/device/lib/base:multibits",
        "//sw/device/silicon_creator/lib/base:chip",
    ],
    alwayslink = True,
)

opentitan_binary(
    name = "base_rom",
    exec_env = [
        "//hw/top_darjeeling:sim_dv_base", 
        "//hw/top_darjeeling:silicon_creator",
    ],
    kind = "rom",
    linker_script = ":base_rom_linker_script",
    transitive_features = [
        "use_lld",
        "lto",
        "minsize",
    ],
    deps = [
        ":base_rom_lib",
        # We depend on rom_isrs here rather than in mask_rom_lib so that the
        # `rom_exception_handler` symbol remains unresolved and can be supplied
        # by tests such as `rom_epmp_test`.
        ":rom_isrs",
    ],
)

[
    # Generate targets with `sim_dv` and `sim_verilator` suffixes as expected
    # by dvsim.
    alias(
        name = "base_rom_{}".format(env),
        actual = ":base_rom",
    )
    for env in [
        "sim_dv",
        "sim_verilator",
    ]
]

ld_library(
    name = "second_rom_linker_script",
    script = "second_rom.ld",
    deps = [
        "//hw/top_darjeeling/sw/autogen:top_darjeeling_memory",
        "//sw/device:info_sections",
    ],
)

cc_library(
    name = "second_rom_epmp",
    srcs = [
        "second_rom_epmp.c",
    ],
    hdrs = ["second_rom_epmp.h"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:bitfield",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/base:memory",
        "//sw/device/silicon_creator/lib:epmp_state",
        "//sw/device/silicon_creator/lib/drivers:lifecycle",
    ],
)

cc_library(
    name = "second_rom_lib",
    srcs = ["second_rom_start.S"],
    target_compatible_with = [OPENTITAN_CPU],
    deps = [
        ":second_rom_common",
        ":second_rom_epmp",
        "//hw/top:aon_timer_c_regs",
        "//hw/top:ast_c_regs",
        "//hw/top:clkmgr_c_regs",
        "//hw/top:csrng_c_regs",
        "//hw/top:edn_c_regs",
        "//hw/top:entropy_src_c_regs",
        "//hw/top:lc_ctrl_c_regs",
        "//hw/top:otp_ctrl_c_regs",
        "//hw/top:pwrmgr_c_regs",
        "//hw/top:rstmgr_c_regs",
        "//hw/top:rv_core_ibex_c_regs",
        "//hw/top:sram_ctrl_c_regs",
        "//hw/top_darjeeling/sw/autogen:top_darjeeling",
        "//sw/device/lib/base:hardened",
        "//sw/device/lib/base:multibits",
        "//sw/device/silicon_creator/lib/base:chip",
    ],
    alwayslink = True,
)

cc_library(
    name = "second_rom_common",
    srcs = [
        "second_rom.c",
#        "base_rom.h",
    ],
    deps = [
        # ":boot_policy",
        # ":boot_policy_ptrs",
        # ":bootstrap",
        ":second_rom_epmp",
        # ":rom_state",
        # ":sigverify_keys_ecdsa_p256",
        # ":sigverify_keys_spx",
        # ":sigverify_otp_keys",
        # "//hw/top:aon_timer_c_regs",
        "//sw/device/lib/arch:device",
        "//sw/device/lib/base:bitfield",
        "//sw/device/lib/base:csr",
        "//sw/device/lib/base:macros",
        "//sw/device/lib/base:memory",
        "//sw/device/lib/base:stdasm",
        "//sw/device/lib/crt",
        "//sw/device/lib/runtime:hart",
        # "//sw/device/silicon_creator/lib:boot_log",
        # "//sw/device/silicon_creator/lib:cfi",
        # "//sw/device/silicon_creator/lib:chip_info",
        # "//sw/device/silicon_creator/lib:epmp_state",
        # "//sw/device/silicon_creator/lib:error",
        "//hw/top_darjeeling/sw/device/silicon_creator/lib:irq_asm",
        # "//sw/device/silicon_creator/lib:manifest",
        # "//sw/device/silicon_creator/lib:otbn_boot_services",
        "//sw/device/silicon_creator/lib:dbg_print",
        "//sw/device/silicon_creator/lib:shutdown",
        "//sw/device/silicon_creator/lib:stack_utilization",
        "//sw/device/silicon_creator/lib/base:chip",
        "//sw/device/silicon_creator/lib/base:sec_mmio",
        "//sw/device/silicon_creator/lib/base:static_critical",
        "//sw/device/silicon_creator/lib/drivers:alert",
        #"//sw/device/silicon_creator/lib/drivers:ast",
        "//sw/device/silicon_creator/lib/drivers:hmac",
        "//sw/device/silicon_creator/lib/drivers:ibex",
        #"//sw/device/silicon_creator/lib/drivers:keymgr",
        "//sw/device/silicon_creator/lib/drivers:kmac",
        "//sw/device/silicon_creator/lib/drivers:lifecycle",
        "//sw/device/silicon_creator/lib/drivers:otbn",
        "//sw/device/silicon_creator/lib/drivers:otp",
        "//sw/device/silicon_creator/lib/drivers:pinmux",
        "//sw/device/silicon_creator/lib/drivers:pwrmgr",
        "//sw/device/silicon_creator/lib/drivers:retention_sram",
        "//sw/device/silicon_creator/lib/drivers:rnd",
        "//sw/device/silicon_creator/lib/drivers:rstmgr",
        "//sw/device/silicon_creator/lib/drivers:watchdog",
        # "//sw/device/silicon_creator/lib/sigverify",
        "@darjeeling_rom_hooks",
    ],
)


opentitan_binary(
    name = "second_rom",
    exec_env = [
        "//hw/top_darjeeling:sim_dv_base", 
        "//hw/top_darjeeling:silicon_creator",
    ],
    kind = "rom",
    rom_scramble_mode = "second-rom",
    linker_script = ":second_rom_linker_script",
    transitive_features = [
        "use_lld",
        "lto",
        "minsize",
    ],
    deps = [
        ":second_rom_lib",
        # We depend on rom_isrs here rather than in mask_rom_lib so that the
        # `rom_exception_handler` symbol remains unresolved and can be supplied
        # by tests such as `rom_epmp_test`.
        ":rom_isrs",
    ],
)

[
    # Generate targets with `sim_dv` and `sim_verilator` suffixes as expected
    # by dvsim.
    alias(
        name = "second_rom_{}".format(env),
        actual = ":second_rom",
    )
    for env in [
        "sim_dv",
        "sim_verilator",
    ]
]
