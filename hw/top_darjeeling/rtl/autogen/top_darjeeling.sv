// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// ------------------- W A R N I N G: A U T O - G E N E R A T E D   C O D E !! -------------------//
// PLEASE DO NOT HAND-EDIT THIS FILE. IT HAS BEEN AUTO-GENERATED WITH THE FOLLOWING COMMAND:
//
// util/topgen.py -t hw/top_darjeeling/data/top_darjeeling.hjson \
//                -o hw/top_darjeeling/ \
//                --rnd_cnst_seed \
//                1017106219537032642877583828875051302543807092889754935647094601236425074047

`include "prim_assert.sv"

module top_darjeeling #(
  // Manually defined parameters

  // Auto-inferred parameters
  // parameters for uart0
  // parameters for gpio
  parameter bit GpioGpioAsyncOn = 1,
  parameter bit GpioGpioAsHwStrapsEn = 1,
  // parameters for spi_device
  // parameters for i2c0
  // parameters for rv_timer
  // parameters for otp_ctrl
  parameter OtpCtrlMemInitFile = "",
  // parameters for lc_ctrl
  parameter bit SecLcCtrlVolatileRawUnlockEn = top_pkg::SecVolatileRawUnlockEn,
  parameter logic [15:0] LcCtrlSiliconCreatorId = 16'h 0001,
  parameter logic [15:0] LcCtrlProductId = 16'h 4000,
  parameter logic [7:0] LcCtrlRevisionId = 8'h 01,
  // parameters for alert_handler
  // parameters for spi_host0
  // parameters for pwrmgr_aon
  // parameters for rstmgr_aon
  parameter bit SecRstmgrAonCheck = 1'b1,
  parameter int SecRstmgrAonMaxSyncDelay = 2,
  // parameters for clkmgr_aon
  // parameters for adc_ctrl_aon
  // parameters for pinmux_aon
  parameter bit PinmuxAonUsbWkupModuleEn = 0,
  parameter bit PinmuxAonHwStrapSamplingEn = 0,
  parameter bit SecPinmuxAonVolatileRawUnlockEn = top_pkg::SecVolatileRawUnlockEn,
  parameter pinmux_pkg::target_cfg_t PinmuxAonTargetCfg = pinmux_pkg::DefaultTargetCfg,
  // parameters for aon_timer_aon
  // parameters for sensor_ctrl
  // parameters for soc_proxy
  // parameters for sram_ctrl_ret_aon
  parameter bit SramCtrlRetAonInstrExec = 0,
  // parameters for rv_dm
  // parameters for rv_plic
  // parameters for aes
  parameter bit SecAesMasking = 1,
  parameter aes_pkg::sbox_impl_e SecAesSBoxImpl = aes_pkg::SBoxImplDom,
  parameter int unsigned SecAesStartTriggerDelay = 0,
  parameter bit SecAesAllowForcingMasks = 1'b0,
  parameter bit SecAesSkipPRNGReseeding = 1'b0,
  // parameters for hmac
  // parameters for kmac
  parameter bit KmacEnMasking = 1,
  parameter bit KmacSwKeyMasked = 0,
  parameter int SecKmacCmdDelay = 0,
  parameter bit SecKmacIdleAcceptSwMsg = 0,
  // parameters for otbn
  parameter bit OtbnStub = 0,
  parameter otbn_pkg::regfile_e OtbnRegFile = otbn_pkg::RegFileFF,
  parameter bit SecOtbnMuteUrnd = 0,
  parameter bit SecOtbnSkipUrndReseedAtStart = 0,
  // parameters for keymgr_dpe
  parameter bit KeymgrDpeUseOtpSeedsInsteadOfFlash = 1,
  parameter bit KeymgrDpeKmacEnMasking = 1,
  // parameters for csrng
  parameter aes_pkg::sbox_impl_e CsrngSBoxImpl = aes_pkg::SBoxImplCanright,
  // parameters for edn0
  // parameters for edn1
  // parameters for sram_ctrl_main
  parameter bit SramCtrlMainInstrExec = 1,
  // parameters for sram_ctrl_mbox
  parameter bit SramCtrlMboxInstrExec = 0,
  // parameters for rom_ctrl0
  parameter RomCtrl0BootRomInitFile = "",
  parameter bit SecRomCtrl0DisableScrambling = 1'b0,
  // parameters for rom_ctrl1
  parameter RomCtrl1BootRomInitFile = "",
  parameter bit SecRomCtrl1DisableScrambling = 1'b0,
  // parameters for dma
  parameter bit DmaEnableDataIntgGen = 1'b1,
  parameter logic [tlul_pkg::RsvdWidth-1:0] DmaTlUserRsvd = '0,
  parameter logic [dma_pkg::SYS_RACL_WIDTH-1:0] DmaSysRacl = '0,
  parameter int unsigned DmaOtAgentId = 0,
  // parameters for mbx0
  // parameters for mbx1
  // parameters for mbx2
  // parameters for mbx3
  // parameters for mbx4
  // parameters for mbx5
  // parameters for mbx6
  // parameters for mbx_jtag
  // parameters for mbx_pcie0
  // parameters for mbx_pcie1
  // parameters for rv_core_ibex
  parameter bit RvCoreIbexPMPEnable = 1,
  parameter int unsigned RvCoreIbexPMPGranularity = 0,
  parameter int unsigned RvCoreIbexPMPNumRegions = 16,
  parameter int unsigned RvCoreIbexMHPMCounterNum = 10,
  parameter int unsigned RvCoreIbexMHPMCounterWidth = 32,
  parameter bit RvCoreIbexRV32E = 0,
  parameter ibex_pkg::rv32m_e RvCoreIbexRV32M = ibex_pkg::RV32MSingleCycle,
  parameter ibex_pkg::rv32b_e RvCoreIbexRV32B = ibex_pkg::RV32BOTEarlGrey,
  parameter ibex_pkg::regfile_e RvCoreIbexRegFile = ibex_pkg::RegFileFF,
  parameter bit RvCoreIbexBranchTargetALU = 1,
  parameter bit RvCoreIbexWritebackStage = 1,
  parameter bit RvCoreIbexICache = 1,
  parameter bit RvCoreIbexICacheECC = 1,
  parameter bit RvCoreIbexICacheScramble = 1,
  parameter bit RvCoreIbexBranchPredictor = 0,
  parameter bit RvCoreIbexDbgTriggerEn = 1,
  parameter int RvCoreIbexDbgHwBreakNum = 4,
  parameter bit RvCoreIbexSecureIbex = 1,
  parameter int unsigned RvCoreIbexDmHaltAddr =
      tl_main_pkg::ADDR_SPACE_RV_DM__MEM + dm::HaltAddress[31:0],
  parameter int unsigned RvCoreIbexDmExceptionAddr =
      tl_main_pkg::ADDR_SPACE_RV_DM__MEM + dm::ExceptionAddress[31:0],
  parameter bit RvCoreIbexPipeLine = 0
) (
  // Multiplexed I/O
  input        [46:0] mio_in_i,
  output logic [46:0] mio_out_o,
  output logic [46:0] mio_oe_o,
  // Dedicated I/O
  input        [11:0] dio_in_i,
  output logic [11:0] dio_out_o,
  output logic [11:0] dio_oe_o,

  // pad attributes to padring
  output prim_pad_wrapper_pkg::pad_attr_t [pinmux_reg_pkg::NMioPads-1:0] mio_attr_o,
  output prim_pad_wrapper_pkg::pad_attr_t [pinmux_reg_pkg::NDioPads-1:0] dio_attr_o,


  // Inter-module Signal External type
  output ast_pkg::adc_ast_req_t       adc_req_o,
  input  ast_pkg::adc_ast_rsp_t       adc_rsp_i,
  input  edn_pkg::edn_req_t       ast_edn_req_i,
  output edn_pkg::edn_rsp_t       ast_edn_rsp_o,
  output lc_ctrl_pkg::lc_tx_t       ast_lc_dft_en_o,
  output lc_ctrl_pkg::lc_tx_t       ast_lc_hw_debug_en_o,
  input  ast_pkg::ast_obs_ctrl_t       obs_ctrl_i,
  input  prim_ram_1p_pkg::ram_1p_cfg_t       ram_1p_cfg_i,
  input  prim_ram_2p_pkg::ram_2p_cfg_t       spi_ram_2p_cfg_i,
  input  prim_rom_pkg::rom_cfg_t       rom_cfg_i,
  output prim_mubi_pkg::mubi4_t       clk_main_jitter_en_o,
  output prim_mubi_pkg::mubi4_t       io_clk_byp_req_o,
  input  prim_mubi_pkg::mubi4_t       io_clk_byp_ack_i,
  output prim_mubi_pkg::mubi4_t       all_clk_byp_req_o,
  input  prim_mubi_pkg::mubi4_t       all_clk_byp_ack_i,
  output prim_mubi_pkg::mubi4_t       hi_speed_sel_o,
  input  prim_mubi_pkg::mubi4_t       div_step_down_req_i,
  input  prim_mubi_pkg::mubi4_t       calib_rdy_i,
  output entropy_src_pkg::entropy_src_hw_if_req_t       entropy_src_hw_if_req_o,
  input  entropy_src_pkg::entropy_src_hw_if_rsp_t       entropy_src_hw_if_rsp_i,
  output dma_pkg::sys_req_t       dma_sys_req_o,
  input  dma_pkg::sys_rsp_t       dma_sys_rsp_i,
  output tlul_pkg::tl_h2d_t       dma_ctn_tl_h2d_o,
  input  tlul_pkg::tl_d2h_t       dma_ctn_tl_d2h_i,
  input  tlul_pkg::tl_h2d_t       mbx_tl_req_i,
  output tlul_pkg::tl_d2h_t       mbx_tl_rsp_o,
  output logic       mbx0_doe_intr_o,
  output logic       mbx0_doe_intr_en_o,
  output logic       mbx0_doe_intr_support_o,
  output logic       mbx1_doe_intr_o,
  output logic       mbx1_doe_intr_en_o,
  output logic       mbx1_doe_intr_support_o,
  output logic       mbx2_doe_intr_o,
  output logic       mbx2_doe_intr_en_o,
  output logic       mbx2_doe_intr_support_o,
  output logic       mbx3_doe_intr_o,
  output logic       mbx3_doe_intr_en_o,
  output logic       mbx3_doe_intr_support_o,
  output logic       mbx4_doe_intr_o,
  output logic       mbx4_doe_intr_en_o,
  output logic       mbx4_doe_intr_support_o,
  output logic       mbx5_doe_intr_o,
  output logic       mbx5_doe_intr_en_o,
  output logic       mbx5_doe_intr_support_o,
  output logic       mbx6_doe_intr_o,
  output logic       mbx6_doe_intr_en_o,
  output logic       mbx6_doe_intr_support_o,
  output logic       mbx_jtag_doe_intr_o,
  output logic       mbx_jtag_doe_intr_en_o,
  output logic       mbx_jtag_doe_intr_support_o,
  output logic       mbx_pcie0_doe_intr_o,
  output logic       mbx_pcie0_doe_intr_en_o,
  output logic       mbx_pcie0_doe_intr_support_o,
  output logic       mbx_pcie1_doe_intr_o,
  output logic       mbx_pcie1_doe_intr_en_o,
  output logic       mbx_pcie1_doe_intr_support_o,
  input  tlul_pkg::tl_h2d_t       mbx_jtag_dmi_req_i,
  output tlul_pkg::tl_d2h_t       mbx_jtag_dmi_rsp_o,
  input  tlul_pkg::tl_h2d_t       lc_ctrl_dmi_h2d_i,
  output tlul_pkg::tl_d2h_t       lc_ctrl_dmi_d2h_o,
  input  tlul_pkg::tl_h2d_t       rv_dm_dmi_h2d_i,
  output tlul_pkg::tl_d2h_t       rv_dm_dmi_d2h_o,
  output logic       pwrmgr_strap_en_o,
  input  lc_ctrl_pkg::lc_tx_t       rv_pinmux_hw_debug_en_i,
  output tlul_pkg::tl_h2d_t       ast_tl_req_o,
  input  tlul_pkg::tl_d2h_t       ast_tl_rsp_i,
  output pinmux_pkg::dft_strap_test_req_t       dft_strap_test_o,
  input  logic       dft_hold_tap_sel_i,
  output pwrmgr_pkg::pwr_ast_req_t       pwrmgr_ast_req_o,
  input  pwrmgr_pkg::pwr_ast_rsp_t       pwrmgr_ast_rsp_i,
  output otp_ctrl_pkg::otp_ast_req_t       otp_ctrl_otp_ast_pwr_seq_o,
  input  otp_ctrl_pkg::otp_ast_rsp_t       otp_ctrl_otp_ast_pwr_seq_h_i,
  inout         otp_ext_voltage_h_io,
  output logic [7:0] otp_obs_o,
  input  logic [1:0] por_n_i,
  input  logic [31:0] fpga_info_i,
  input  ast_pkg::ast_alert_req_t       sensor_ctrl_ast_alert_req_i,
  output ast_pkg::ast_alert_rsp_t       sensor_ctrl_ast_alert_rsp_o,
  input  ast_pkg::ast_status_t       sensor_ctrl_ast_status_i,
  input  logic [8:0] ast2pinmux_i,
  input  prim_mubi_pkg::mubi4_t       ast_init_done_i,
  output tlul_pkg::tl_h2d_t       ctn_tl_h2d_o,
  input  tlul_pkg::tl_d2h_t       ctn_tl_d2h_i,
  input  soc_proxy_pkg::soc_alert_req_t [3:0] soc_fatal_alert_req_i,
  output soc_proxy_pkg::soc_alert_rsp_t [3:0] soc_fatal_alert_rsp_o,
  input  soc_proxy_pkg::soc_alert_req_t [3:0] soc_recov_alert_req_i,
  output soc_proxy_pkg::soc_alert_rsp_t [3:0] soc_recov_alert_rsp_o,
  input  logic       soc_wkup_async_i,
  input  logic       soc_rst_req_async_i,
  input  logic [7:0] soc_intr_async_i,
  input  logic [7:0] soc_lsio_trigger_i,
  output logic       sck_monitor_o,


  // All externally supplied clocks
  input clk_main_i,
  input clk_io_i,
  input clk_usb_i,
  input clk_aon_i,

  // All clocks forwarded to ast
  output clkmgr_pkg::clkmgr_out_t clks_ast_o,
  output rstmgr_pkg::rstmgr_out_t rsts_ast_o,

  input                      scan_rst_ni, // reset used for test mode
  input                      scan_en_i,
  input prim_mubi_pkg::mubi4_t scanmode_i   // lc_ctrl_pkg::On for Scan
);

  import tlul_pkg::*;
  import top_pkg::*;
  import tl_main_pkg::*;
  import top_darjeeling_pkg::*;
  // Compile-time random constants
  import top_darjeeling_rnd_cnst_pkg::*;

  // Signals
  logic [35:0] mio_p2d;
  logic [44:0] mio_d2p;
  logic [44:0] mio_en_d2p;
  logic [11:0] dio_p2d;
  logic [11:0] dio_d2p;
  logic [11:0] dio_en_d2p;
  // uart0
  logic        cio_uart0_rx_p2d;
  logic        cio_uart0_tx_d2p;
  logic        cio_uart0_tx_en_d2p;
  // gpio
  logic [31:0] cio_gpio_gpio_p2d;
  logic [31:0] cio_gpio_gpio_d2p;
  logic [31:0] cio_gpio_gpio_en_d2p;
  // spi_device
  logic        cio_spi_device_sck_p2d;
  logic        cio_spi_device_csb_p2d;
  logic        cio_spi_device_tpm_csb_p2d;
  logic [3:0]  cio_spi_device_sd_p2d;
  logic [3:0]  cio_spi_device_sd_d2p;
  logic [3:0]  cio_spi_device_sd_en_d2p;
  // i2c0
  logic        cio_i2c0_sda_p2d;
  logic        cio_i2c0_scl_p2d;
  logic        cio_i2c0_sda_d2p;
  logic        cio_i2c0_sda_en_d2p;
  logic        cio_i2c0_scl_d2p;
  logic        cio_i2c0_scl_en_d2p;
  // rv_timer
  // otp_ctrl
  logic [7:0]  cio_otp_ctrl_test_d2p;
  logic [7:0]  cio_otp_ctrl_test_en_d2p;
  // lc_ctrl
  // alert_handler
  // spi_host0
  logic [3:0]  cio_spi_host0_sd_p2d;
  logic        cio_spi_host0_sck_d2p;
  logic        cio_spi_host0_sck_en_d2p;
  logic        cio_spi_host0_csb_d2p;
  logic        cio_spi_host0_csb_en_d2p;
  logic [3:0]  cio_spi_host0_sd_d2p;
  logic [3:0]  cio_spi_host0_sd_en_d2p;
  // pwrmgr_aon
  // rstmgr_aon
  // clkmgr_aon
  // adc_ctrl_aon
  // pinmux_aon
  // aon_timer_aon
  // sensor_ctrl
  logic [8:0]  cio_sensor_ctrl_ast_debug_out_d2p;
  logic [8:0]  cio_sensor_ctrl_ast_debug_out_en_d2p;
  // soc_proxy
  // sram_ctrl_ret_aon
  // rv_dm
  // rv_plic
  // aes
  // hmac
  // kmac
  // otbn
  // keymgr_dpe
  // csrng
  // edn0
  // edn1
  // sram_ctrl_main
  // sram_ctrl_mbox
  // rom_ctrl0
  // rom_ctrl1
  // dma
  // mbx0
  // mbx1
  // mbx2
  // mbx3
  // mbx4
  // mbx5
  // mbx6
  // mbx_jtag
  // mbx_pcie0
  // mbx_pcie1
  // rv_core_ibex


  logic [129:0]  intr_vector;
  // Interrupt source list
  logic intr_uart0_tx_watermark;
  logic intr_uart0_rx_watermark;
  logic intr_uart0_tx_empty;
  logic intr_uart0_rx_overflow;
  logic intr_uart0_rx_frame_err;
  logic intr_uart0_rx_break_err;
  logic intr_uart0_rx_timeout;
  logic intr_uart0_rx_parity_err;
  logic [31:0] intr_gpio_gpio;
  logic intr_spi_device_generic_rx_full;
  logic intr_spi_device_generic_rx_watermark;
  logic intr_spi_device_generic_tx_watermark;
  logic intr_spi_device_generic_rx_error;
  logic intr_spi_device_generic_rx_overflow;
  logic intr_spi_device_generic_tx_underflow;
  logic intr_spi_device_upload_cmdfifo_not_empty;
  logic intr_spi_device_upload_payload_not_empty;
  logic intr_spi_device_upload_payload_overflow;
  logic intr_spi_device_readbuf_watermark;
  logic intr_spi_device_readbuf_flip;
  logic intr_spi_device_tpm_header_not_empty;
  logic intr_i2c0_fmt_threshold;
  logic intr_i2c0_rx_threshold;
  logic intr_i2c0_fmt_overflow;
  logic intr_i2c0_rx_overflow;
  logic intr_i2c0_nak;
  logic intr_i2c0_scl_interference;
  logic intr_i2c0_sda_interference;
  logic intr_i2c0_stretch_timeout;
  logic intr_i2c0_sda_unstable;
  logic intr_i2c0_cmd_complete;
  logic intr_i2c0_tx_stretch;
  logic intr_i2c0_tx_overflow;
  logic intr_i2c0_acq_full;
  logic intr_i2c0_unexp_stop;
  logic intr_i2c0_host_timeout;
  logic intr_rv_timer_timer_expired_hart0_timer0;
  logic intr_otp_ctrl_otp_operation_done;
  logic intr_otp_ctrl_otp_error;
  logic intr_alert_handler_classa;
  logic intr_alert_handler_classb;
  logic intr_alert_handler_classc;
  logic intr_alert_handler_classd;
  logic intr_spi_host0_error;
  logic intr_spi_host0_spi_event;
  logic intr_pwrmgr_aon_wakeup;
  logic intr_adc_ctrl_aon_match_done;
  logic intr_aon_timer_aon_wkup_timer_expired;
  logic intr_aon_timer_aon_wdog_timer_bark;
  logic intr_sensor_ctrl_io_status_change;
  logic intr_sensor_ctrl_init_status_change;
  logic [7:0] intr_soc_proxy_external;
  logic intr_hmac_hmac_done;
  logic intr_hmac_fifo_empty;
  logic intr_hmac_hmac_err;
  logic intr_kmac_kmac_done;
  logic intr_kmac_fifo_empty;
  logic intr_kmac_kmac_err;
  logic intr_otbn_done;
  logic intr_keymgr_dpe_op_done;
  logic intr_csrng_cs_cmd_req_done;
  logic intr_csrng_cs_entropy_req;
  logic intr_csrng_cs_hw_inst_exc;
  logic intr_csrng_cs_fatal_err;
  logic intr_edn0_edn_cmd_req_done;
  logic intr_edn0_edn_fatal_err;
  logic intr_edn1_edn_cmd_req_done;
  logic intr_edn1_edn_fatal_err;
  logic intr_dma_dma_done;
  logic intr_dma_dma_error;
  logic intr_dma_dma_memory_buffer_limit;
  logic intr_mbx0_mbx_ready;
  logic intr_mbx0_mbx_abort;
  logic intr_mbx1_mbx_ready;
  logic intr_mbx1_mbx_abort;
  logic intr_mbx2_mbx_ready;
  logic intr_mbx2_mbx_abort;
  logic intr_mbx3_mbx_ready;
  logic intr_mbx3_mbx_abort;
  logic intr_mbx4_mbx_ready;
  logic intr_mbx4_mbx_abort;
  logic intr_mbx5_mbx_ready;
  logic intr_mbx5_mbx_abort;
  logic intr_mbx6_mbx_ready;
  logic intr_mbx6_mbx_abort;
  logic intr_mbx_jtag_mbx_ready;
  logic intr_mbx_jtag_mbx_abort;
  logic intr_mbx_pcie0_mbx_ready;
  logic intr_mbx_pcie0_mbx_abort;
  logic intr_mbx_pcie1_mbx_ready;
  logic intr_mbx_pcie1_mbx_abort;

  // Alert list
  prim_alert_pkg::alert_tx_t [alert_pkg::NAlerts-1:0]  alert_tx;
  prim_alert_pkg::alert_rx_t [alert_pkg::NAlerts-1:0]  alert_rx;


  // define inter-module signals
  ast_pkg::ast_obs_ctrl_t       ast_obs_ctrl;
  prim_ram_1p_pkg::ram_1p_cfg_t       ast_ram_1p_cfg;
  prim_ram_2p_pkg::ram_2p_cfg_t       ast_spi_ram_2p_cfg;
  prim_rom_pkg::rom_cfg_t       ast_rom_cfg;
  alert_pkg::alert_crashdump_t       alert_handler_crashdump;
  prim_esc_pkg::esc_rx_t [3:0] alert_handler_esc_rx;
  prim_esc_pkg::esc_tx_t [3:0] alert_handler_esc_tx;
  logic       aon_timer_aon_nmi_wdog_timer_bark;
  csrng_pkg::csrng_req_t [1:0] csrng_csrng_cmd_req;
  csrng_pkg::csrng_rsp_t [1:0] csrng_csrng_cmd_rsp;
  otp_ctrl_pkg::sram_otp_key_req_t [3:0] otp_ctrl_sram_otp_key_req;
  otp_ctrl_pkg::sram_otp_key_rsp_t [3:0] otp_ctrl_sram_otp_key_rsp;
  pwrmgr_pkg::pwr_rst_req_t       pwrmgr_aon_pwr_rst_req;
  pwrmgr_pkg::pwr_rst_rsp_t       pwrmgr_aon_pwr_rst_rsp;
  pwrmgr_pkg::pwr_clk_req_t       pwrmgr_aon_pwr_clk_req;
  pwrmgr_pkg::pwr_clk_rsp_t       pwrmgr_aon_pwr_clk_rsp;
  pwrmgr_pkg::pwr_otp_req_t       pwrmgr_aon_pwr_otp_req;
  pwrmgr_pkg::pwr_otp_rsp_t       pwrmgr_aon_pwr_otp_rsp;
  pwrmgr_pkg::pwr_lc_req_t       pwrmgr_aon_pwr_lc_req;
  pwrmgr_pkg::pwr_lc_rsp_t       pwrmgr_aon_pwr_lc_rsp;
  logic       pwrmgr_aon_strap;
  logic       pwrmgr_aon_low_power;
  lc_ctrl_pkg::lc_tx_t       pwrmgr_aon_fetch_en;
  rom_ctrl_pkg::pwrmgr_data_t [1:0] pwrmgr_aon_rom_ctrl;
  rom_ctrl_pkg::keymgr_data_t [1:0] keymgr_dpe_rom_digest;
  dma_pkg::lsio_trigger_t       dma_lsio_trigger;
  logic       i2c0_lsio_trigger;
  logic       spi_host0_lsio_trigger;
  logic       uart0_lsio_trigger;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_flash_rma_req;
  lc_ctrl_pkg::lc_tx_t       otbn_lc_rma_ack;
  edn_pkg::edn_req_t [7:0] edn0_edn_req;
  edn_pkg::edn_rsp_t [7:0] edn0_edn_rsp;
  edn_pkg::edn_req_t [7:0] edn1_edn_req;
  edn_pkg::edn_rsp_t [7:0] edn1_edn_rsp;
  otp_ctrl_pkg::otbn_otp_key_req_t       otp_ctrl_otbn_otp_key_req;
  otp_ctrl_pkg::otbn_otp_key_rsp_t       otp_ctrl_otbn_otp_key_rsp;
  otp_ctrl_pkg::otp_keymgr_key_t       otp_ctrl_otp_keymgr_key;
  keymgr_pkg::hw_key_req_t       keymgr_dpe_aes_key;
  keymgr_pkg::hw_key_req_t       keymgr_dpe_kmac_key;
  keymgr_pkg::otbn_key_req_t       keymgr_dpe_otbn_key;
  kmac_pkg::app_req_t [3:0] kmac_app_req;
  kmac_pkg::app_rsp_t [3:0] kmac_app_rsp;
  logic       kmac_en_masking;
  prim_mubi_pkg::mubi4_t [3:0] clkmgr_aon_idle;
  otp_ctrl_pkg::otp_lc_data_t       otp_ctrl_otp_lc_data;
  otp_ctrl_pkg::lc_otp_program_req_t       lc_ctrl_lc_otp_program_req;
  otp_ctrl_pkg::lc_otp_program_rsp_t       lc_ctrl_lc_otp_program_rsp;
  otp_ctrl_pkg::lc_otp_vendor_test_req_t       lc_ctrl_lc_otp_vendor_test_req;
  otp_ctrl_pkg::lc_otp_vendor_test_rsp_t       lc_ctrl_lc_otp_vendor_test_rsp;
  lc_ctrl_pkg::lc_keymgr_div_t       lc_ctrl_lc_keymgr_div;
  logic       lc_ctrl_strap_en_override;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_dft_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_hw_debug_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_cpu_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_keymgr_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_escalate_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_check_byp_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_clk_byp_req;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_clk_byp_ack;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_creator_seed_sw_rw_en;
  lc_ctrl_pkg::lc_tx_t       lc_ctrl_lc_seed_hw_rd_en;
  logic       rv_plic_msip;
  logic       rv_plic_irq;
  logic       rv_dm_debug_req;
  rv_core_ibex_pkg::cpu_crash_dump_t       rv_core_ibex_crash_dump;
  pwrmgr_pkg::pwr_cpu_t       rv_core_ibex_pwrmgr;
  spi_device_pkg::passthrough_req_t       spi_device_passthrough_req;
  spi_device_pkg::passthrough_rsp_t       spi_device_passthrough_rsp;
  logic       rv_dm_ndmreset_req;
  prim_mubi_pkg::mubi4_t       rstmgr_aon_sw_rst_req;
  logic [6:0] pwrmgr_aon_wakeups;
  logic [1:0] pwrmgr_aon_rstreqs;
  tlul_pkg::tl_h2d_t       main_tl_rv_core_ibex__corei_req;
  tlul_pkg::tl_d2h_t       main_tl_rv_core_ibex__corei_rsp;
  tlul_pkg::tl_h2d_t       main_tl_rv_core_ibex__cored_req;
  tlul_pkg::tl_d2h_t       main_tl_rv_core_ibex__cored_rsp;
  tlul_pkg::tl_h2d_t       main_tl_rv_dm__sba_req;
  tlul_pkg::tl_d2h_t       main_tl_rv_dm__sba_rsp;
  tlul_pkg::tl_h2d_t       rv_dm_regs_tl_d_req;
  tlul_pkg::tl_d2h_t       rv_dm_regs_tl_d_rsp;
  tlul_pkg::tl_h2d_t       rv_dm_mem_tl_d_req;
  tlul_pkg::tl_d2h_t       rv_dm_mem_tl_d_rsp;
  tlul_pkg::tl_h2d_t       rom_ctrl0_rom_tl_req;
  tlul_pkg::tl_d2h_t       rom_ctrl0_rom_tl_rsp;
  tlul_pkg::tl_h2d_t       rom_ctrl0_regs_tl_req;
  tlul_pkg::tl_d2h_t       rom_ctrl0_regs_tl_rsp;
  tlul_pkg::tl_h2d_t       rom_ctrl1_rom_tl_req;
  tlul_pkg::tl_d2h_t       rom_ctrl1_rom_tl_rsp;
  tlul_pkg::tl_h2d_t       rom_ctrl1_regs_tl_req;
  tlul_pkg::tl_d2h_t       rom_ctrl1_regs_tl_rsp;
  tlul_pkg::tl_h2d_t       main_tl_peri_req;
  tlul_pkg::tl_d2h_t       main_tl_peri_rsp;
  tlul_pkg::tl_h2d_t       soc_proxy_core_tl_req;
  tlul_pkg::tl_d2h_t       soc_proxy_core_tl_rsp;
  tlul_pkg::tl_h2d_t       soc_proxy_ctn_tl_req;
  tlul_pkg::tl_d2h_t       soc_proxy_ctn_tl_rsp;
  tlul_pkg::tl_h2d_t       hmac_tl_req;
  tlul_pkg::tl_d2h_t       hmac_tl_rsp;
  tlul_pkg::tl_h2d_t       kmac_tl_req;
  tlul_pkg::tl_d2h_t       kmac_tl_rsp;
  tlul_pkg::tl_h2d_t       aes_tl_req;
  tlul_pkg::tl_d2h_t       aes_tl_rsp;
  tlul_pkg::tl_h2d_t       csrng_tl_req;
  tlul_pkg::tl_d2h_t       csrng_tl_rsp;
  tlul_pkg::tl_h2d_t       edn0_tl_req;
  tlul_pkg::tl_d2h_t       edn0_tl_rsp;
  tlul_pkg::tl_h2d_t       edn1_tl_req;
  tlul_pkg::tl_d2h_t       edn1_tl_rsp;
  tlul_pkg::tl_h2d_t       rv_plic_tl_req;
  tlul_pkg::tl_d2h_t       rv_plic_tl_rsp;
  tlul_pkg::tl_h2d_t       otbn_tl_req;
  tlul_pkg::tl_d2h_t       otbn_tl_rsp;
  tlul_pkg::tl_h2d_t       keymgr_dpe_tl_req;
  tlul_pkg::tl_d2h_t       keymgr_dpe_tl_rsp;
  tlul_pkg::tl_h2d_t       rv_core_ibex_cfg_tl_d_req;
  tlul_pkg::tl_d2h_t       rv_core_ibex_cfg_tl_d_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_main_regs_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_main_regs_tl_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_main_ram_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_main_ram_tl_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_mbox_regs_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_mbox_regs_tl_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_mbox_ram_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_mbox_ram_tl_rsp;
  tlul_pkg::tl_h2d_t       dma_tl_d_req;
  tlul_pkg::tl_d2h_t       dma_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_dma__host_req;
  tlul_pkg::tl_d2h_t       main_tl_dma__host_rsp;
  tlul_pkg::tl_h2d_t       mbx0_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx0_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx0__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx0__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx1_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx1_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx1__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx1__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx2_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx2_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx2__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx2__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx3_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx3_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx3__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx3__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx4_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx4_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx4__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx4__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx5_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx5_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx5__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx5__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx6_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx6_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx6__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx6__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx_jtag_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_jtag_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx_jtag__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx_jtag__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx_pcie0_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_pcie0_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx_pcie0__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx_pcie0__sram_rsp;
  tlul_pkg::tl_h2d_t       mbx_pcie1_core_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_pcie1_core_tl_d_rsp;
  tlul_pkg::tl_h2d_t       main_tl_mbx_pcie1__sram_req;
  tlul_pkg::tl_d2h_t       main_tl_mbx_pcie1__sram_rsp;
  tlul_pkg::tl_h2d_t       uart0_tl_req;
  tlul_pkg::tl_d2h_t       uart0_tl_rsp;
  tlul_pkg::tl_h2d_t       i2c0_tl_req;
  tlul_pkg::tl_d2h_t       i2c0_tl_rsp;
  tlul_pkg::tl_h2d_t       gpio_tl_req;
  tlul_pkg::tl_d2h_t       gpio_tl_rsp;
  tlul_pkg::tl_h2d_t       spi_host0_tl_req;
  tlul_pkg::tl_d2h_t       spi_host0_tl_rsp;
  tlul_pkg::tl_h2d_t       spi_device_tl_req;
  tlul_pkg::tl_d2h_t       spi_device_tl_rsp;
  tlul_pkg::tl_h2d_t       rv_timer_tl_req;
  tlul_pkg::tl_d2h_t       rv_timer_tl_rsp;
  tlul_pkg::tl_h2d_t       pwrmgr_aon_tl_req;
  tlul_pkg::tl_d2h_t       pwrmgr_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       rstmgr_aon_tl_req;
  tlul_pkg::tl_d2h_t       rstmgr_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       clkmgr_aon_tl_req;
  tlul_pkg::tl_d2h_t       clkmgr_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       pinmux_aon_tl_req;
  tlul_pkg::tl_d2h_t       pinmux_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       otp_ctrl_core_tl_req;
  tlul_pkg::tl_d2h_t       otp_ctrl_core_tl_rsp;
  tlul_pkg::tl_h2d_t       otp_ctrl_prim_tl_req;
  tlul_pkg::tl_d2h_t       otp_ctrl_prim_tl_rsp;
  tlul_pkg::tl_h2d_t       lc_ctrl_tl_req;
  tlul_pkg::tl_d2h_t       lc_ctrl_tl_rsp;
  tlul_pkg::tl_h2d_t       sensor_ctrl_tl_req;
  tlul_pkg::tl_d2h_t       sensor_ctrl_tl_rsp;
  tlul_pkg::tl_h2d_t       alert_handler_tl_req;
  tlul_pkg::tl_d2h_t       alert_handler_tl_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_ret_aon_regs_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_ret_aon_regs_tl_rsp;
  tlul_pkg::tl_h2d_t       sram_ctrl_ret_aon_ram_tl_req;
  tlul_pkg::tl_d2h_t       sram_ctrl_ret_aon_ram_tl_rsp;
  tlul_pkg::tl_h2d_t       aon_timer_aon_tl_req;
  tlul_pkg::tl_d2h_t       aon_timer_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       adc_ctrl_aon_tl_req;
  tlul_pkg::tl_d2h_t       adc_ctrl_aon_tl_rsp;
  tlul_pkg::tl_h2d_t       mbx0_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx0_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx1_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx1_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx2_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx2_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx3_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx3_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx4_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx4_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx5_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx5_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx6_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx6_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx_pcie0_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_pcie0_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx_pcie1_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_pcie1_soc_tl_d_rsp;
  tlul_pkg::tl_h2d_t       mbx_jtag_soc_tl_d_req;
  tlul_pkg::tl_d2h_t       mbx_jtag_soc_tl_d_rsp;
  clkmgr_pkg::clkmgr_out_t       clkmgr_aon_clocks;
  clkmgr_pkg::clkmgr_cg_en_t       clkmgr_aon_cg_en;
  rstmgr_pkg::rstmgr_out_t       rstmgr_aon_resets;
  rstmgr_pkg::rstmgr_rst_en_t       rstmgr_aon_rst_en;
  logic       rv_core_ibex_irq_timer;
  logic [31:0] rv_core_ibex_hart_id;
  logic [31:0] rv_core_ibex_boot_addr;
  otp_ctrl_part_pkg::otp_broadcast_t       otp_ctrl_otp_broadcast;
  otp_ctrl_pkg::otp_device_id_t       lc_ctrl_otp_device_id;
  otp_ctrl_pkg::otp_manuf_state_t       lc_ctrl_otp_manuf_state;
  otp_ctrl_pkg::otp_device_id_t       keymgr_dpe_otp_device_id;
  prim_mubi_pkg::mubi8_t       sram_ctrl_main_otp_en_sram_ifetch;

  // define mixed connection to port
  assign edn0_edn_req[2] = ast_edn_req_i;
  assign ast_edn_rsp_o = edn0_edn_rsp[2];
  assign ast_lc_dft_en_o = lc_ctrl_lc_dft_en;
  assign ast_lc_hw_debug_en_o = lc_ctrl_lc_hw_debug_en;
  assign ast_obs_ctrl = obs_ctrl_i;
  assign ast_ram_1p_cfg = ram_1p_cfg_i;
  assign ast_spi_ram_2p_cfg = spi_ram_2p_cfg_i;
  assign ast_rom_cfg = rom_cfg_i;
  assign pwrmgr_strap_en_o = pwrmgr_aon_strap;

  // define partial inter-module tie-off
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp1;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp2;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp3;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp4;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp5;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp6;
  edn_pkg::edn_rsp_t unused_edn1_edn_rsp7;

  // assign partial inter-module tie-off
  assign unused_edn1_edn_rsp1 = edn1_edn_rsp[1];
  assign unused_edn1_edn_rsp2 = edn1_edn_rsp[2];
  assign unused_edn1_edn_rsp3 = edn1_edn_rsp[3];
  assign unused_edn1_edn_rsp4 = edn1_edn_rsp[4];
  assign unused_edn1_edn_rsp5 = edn1_edn_rsp[5];
  assign unused_edn1_edn_rsp6 = edn1_edn_rsp[6];
  assign unused_edn1_edn_rsp7 = edn1_edn_rsp[7];
  assign edn1_edn_req[1] = '0;
  assign edn1_edn_req[2] = '0;
  assign edn1_edn_req[3] = '0;
  assign edn1_edn_req[4] = '0;
  assign edn1_edn_req[5] = '0;
  assign edn1_edn_req[6] = '0;
  assign edn1_edn_req[7] = '0;


  // OTP HW_CFG Broadcast signals.
  // TODO(#6713): The actual struct breakout and mapping currently needs to
  // be performed by hand.
  assign sram_ctrl_main_otp_en_sram_ifetch =
      otp_ctrl_otp_broadcast.hw_cfg1_data.en_sram_ifetch;
  assign lc_ctrl_otp_device_id =
      otp_ctrl_otp_broadcast.hw_cfg0_data.device_id;
  assign lc_ctrl_otp_manuf_state =
      otp_ctrl_otp_broadcast.hw_cfg0_data.manuf_state;
  assign keymgr_dpe_otp_device_id =
      otp_ctrl_otp_broadcast.hw_cfg0_data.device_id;

  logic unused_otp_broadcast_bits;
  assign unused_otp_broadcast_bits = ^{
    otp_ctrl_otp_broadcast.valid,
    otp_ctrl_otp_broadcast.hw_cfg0_data.hw_cfg0_digest,
    otp_ctrl_otp_broadcast.hw_cfg1_data.hw_cfg1_digest,
    otp_ctrl_otp_broadcast.hw_cfg1_data.soc_dbg_state,
    otp_ctrl_otp_broadcast.hw_cfg1_data.unallocated
  };

  // See #7978 This below is a hack.
  // This is because ast is a comportable-like module that sits outside
  // of top_darjeeling's boundary.
  assign clks_ast_o = clkmgr_aon_clocks;
  assign rsts_ast_o = rstmgr_aon_resets;

  // ibex specific assignments
  // TODO: This should be further automated in the future.
  assign rv_core_ibex_irq_timer = intr_rv_timer_timer_expired_hart0_timer0;
  assign rv_core_ibex_hart_id = '0;

  assign rv_core_ibex_boot_addr = ADDR_SPACE_ROM_CTRL0__ROM;


  // Wire up alert handler LPGs
  prim_mubi_pkg::mubi4_t [alert_pkg::NLpg-1:0] lpg_cg_en;
  prim_mubi_pkg::mubi4_t [alert_pkg::NLpg-1:0] lpg_rst_en;


  // peri_lc_io_div4_0
  assign lpg_cg_en[0] = clkmgr_aon_cg_en.io_div4_peri;
  assign lpg_rst_en[0] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::Domain0Sel];
  // peri_spi_device_0
  assign lpg_cg_en[1] = clkmgr_aon_cg_en.io_div4_peri;
  assign lpg_rst_en[1] = rstmgr_aon_rst_en.spi_device[rstmgr_pkg::Domain0Sel];
  // peri_i2c0_0
  assign lpg_cg_en[2] = clkmgr_aon_cg_en.io_div4_peri;
  assign lpg_rst_en[2] = rstmgr_aon_rst_en.i2c0[rstmgr_pkg::Domain0Sel];
  // timers_lc_io_div4_0
  assign lpg_cg_en[3] = clkmgr_aon_cg_en.io_div4_timers;
  assign lpg_rst_en[3] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::Domain0Sel];
  // secure_lc_io_div4_0
  assign lpg_cg_en[4] = clkmgr_aon_cg_en.io_div4_secure;
  assign lpg_rst_en[4] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::Domain0Sel];
  // peri_spi_host0_0
  assign lpg_cg_en[5] = clkmgr_aon_cg_en.io_div4_peri;
  assign lpg_rst_en[5] = rstmgr_aon_rst_en.spi_host0[rstmgr_pkg::Domain0Sel];
  // powerup_por_io_div4_Aon
  assign lpg_cg_en[6] = clkmgr_aon_cg_en.io_div4_powerup;
  assign lpg_rst_en[6] = rstmgr_aon_rst_en.por_io_div4[rstmgr_pkg::DomainAonSel];
  // powerup_lc_io_div4_Aon
  assign lpg_cg_en[7] = clkmgr_aon_cg_en.io_div4_powerup;
  assign lpg_rst_en[7] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::DomainAonSel];
  // peri_lc_io_div4_Aon
  assign lpg_cg_en[8] = clkmgr_aon_cg_en.io_div4_peri;
  assign lpg_rst_en[8] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::DomainAonSel];
  // timers_lc_io_div4_Aon
  assign lpg_cg_en[9] = clkmgr_aon_cg_en.io_div4_timers;
  assign lpg_rst_en[9] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::DomainAonSel];
  // infra_lc_io_div4_0
  assign lpg_cg_en[10] = clkmgr_aon_cg_en.io_div4_infra;
  assign lpg_rst_en[10] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::Domain0Sel];
  // secure_lc_io_div4_Aon
  assign lpg_cg_en[11] = clkmgr_aon_cg_en.io_div4_secure;
  assign lpg_rst_en[11] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::DomainAonSel];
  // infra_lc_0
  assign lpg_cg_en[12] = clkmgr_aon_cg_en.main_infra;
  assign lpg_rst_en[12] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];
  // infra_lc_io_div4_Aon
  assign lpg_cg_en[13] = clkmgr_aon_cg_en.io_div4_infra;
  assign lpg_rst_en[13] = rstmgr_aon_rst_en.lc_io_div4[rstmgr_pkg::DomainAonSel];
  // infra_sys_0
  assign lpg_cg_en[14] = clkmgr_aon_cg_en.main_infra;
  assign lpg_rst_en[14] = rstmgr_aon_rst_en.sys[rstmgr_pkg::Domain0Sel];
  // secure_lc_0
  assign lpg_cg_en[15] = clkmgr_aon_cg_en.main_secure;
  assign lpg_rst_en[15] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];
  // aes_trans_lc_0
  assign lpg_cg_en[16] = clkmgr_aon_cg_en.main_aes;
  assign lpg_rst_en[16] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];
  // hmac_trans_lc_0
  assign lpg_cg_en[17] = clkmgr_aon_cg_en.main_hmac;
  assign lpg_rst_en[17] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];
  // kmac_trans_lc_0
  assign lpg_cg_en[18] = clkmgr_aon_cg_en.main_kmac;
  assign lpg_rst_en[18] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];
  // otbn_trans_lc_0
  assign lpg_cg_en[19] = clkmgr_aon_cg_en.main_otbn;
  assign lpg_rst_en[19] = rstmgr_aon_rst_en.lc[rstmgr_pkg::Domain0Sel];

// tie-off unused connections
//VCS coverage off
// pragma coverage off
    prim_mubi_pkg::mubi4_t unused_cg_en_0;
    assign unused_cg_en_0 = clkmgr_aon_cg_en.aon_powerup;
    prim_mubi_pkg::mubi4_t unused_cg_en_1;
    assign unused_cg_en_1 = clkmgr_aon_cg_en.main_powerup;
    prim_mubi_pkg::mubi4_t unused_cg_en_2;
    assign unused_cg_en_2 = clkmgr_aon_cg_en.io_powerup;
    prim_mubi_pkg::mubi4_t unused_cg_en_3;
    assign unused_cg_en_3 = clkmgr_aon_cg_en.usb_powerup;
    prim_mubi_pkg::mubi4_t unused_cg_en_4;
    assign unused_cg_en_4 = clkmgr_aon_cg_en.io_div2_powerup;
    prim_mubi_pkg::mubi4_t unused_cg_en_5;
    assign unused_cg_en_5 = clkmgr_aon_cg_en.aon_infra;
    prim_mubi_pkg::mubi4_t unused_cg_en_6;
    assign unused_cg_en_6 = clkmgr_aon_cg_en.aon_secure;
    prim_mubi_pkg::mubi4_t unused_cg_en_7;
    assign unused_cg_en_7 = clkmgr_aon_cg_en.aon_peri;
    prim_mubi_pkg::mubi4_t unused_cg_en_8;
    assign unused_cg_en_8 = clkmgr_aon_cg_en.aon_timers;
    prim_mubi_pkg::mubi4_t unused_cg_en_9;
    assign unused_cg_en_9 = clkmgr_aon_cg_en.usb_infra;
    prim_mubi_pkg::mubi4_t unused_cg_en_10;
    assign unused_cg_en_10 = clkmgr_aon_cg_en.io_infra;
    prim_mubi_pkg::mubi4_t unused_cg_en_11;
    assign unused_cg_en_11 = clkmgr_aon_cg_en.io_div2_peri;
    prim_mubi_pkg::mubi4_t unused_cg_en_12;
    assign unused_cg_en_12 = clkmgr_aon_cg_en.io_peri;
    prim_mubi_pkg::mubi4_t unused_cg_en_13;
    assign unused_cg_en_13 = clkmgr_aon_cg_en.usb_peri;
    prim_mubi_pkg::mubi4_t unused_rst_en_0;
    assign unused_rst_en_0 = rstmgr_aon_rst_en.por_aon[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_1;
    assign unused_rst_en_1 = rstmgr_aon_rst_en.por_aon[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_2;
    assign unused_rst_en_2 = rstmgr_aon_rst_en.por[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_3;
    assign unused_rst_en_3 = rstmgr_aon_rst_en.por[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_4;
    assign unused_rst_en_4 = rstmgr_aon_rst_en.por_io[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_5;
    assign unused_rst_en_5 = rstmgr_aon_rst_en.por_io[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_6;
    assign unused_rst_en_6 = rstmgr_aon_rst_en.por_io_div2[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_7;
    assign unused_rst_en_7 = rstmgr_aon_rst_en.por_io_div2[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_8;
    assign unused_rst_en_8 = rstmgr_aon_rst_en.por_io_div4[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_9;
    assign unused_rst_en_9 = rstmgr_aon_rst_en.por_usb[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_10;
    assign unused_rst_en_10 = rstmgr_aon_rst_en.por_usb[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_11;
    assign unused_rst_en_11 = rstmgr_aon_rst_en.lc_shadowed[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_12;
    assign unused_rst_en_12 = rstmgr_aon_rst_en.lc[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_13;
    assign unused_rst_en_13 = rstmgr_aon_rst_en.lc_shadowed[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_14;
    assign unused_rst_en_14 = rstmgr_aon_rst_en.lc_aon[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_15;
    assign unused_rst_en_15 = rstmgr_aon_rst_en.lc_aon[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_16;
    assign unused_rst_en_16 = rstmgr_aon_rst_en.lc_io[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_17;
    assign unused_rst_en_17 = rstmgr_aon_rst_en.lc_io[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_18;
    assign unused_rst_en_18 = rstmgr_aon_rst_en.lc_io_div2[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_19;
    assign unused_rst_en_19 = rstmgr_aon_rst_en.lc_io_div2[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_20;
    assign unused_rst_en_20 = rstmgr_aon_rst_en.lc_io_div4_shadowed[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_21;
    assign unused_rst_en_21 = rstmgr_aon_rst_en.lc_io_div4_shadowed[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_22;
    assign unused_rst_en_22 = rstmgr_aon_rst_en.lc_usb[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_23;
    assign unused_rst_en_23 = rstmgr_aon_rst_en.lc_usb[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_24;
    assign unused_rst_en_24 = rstmgr_aon_rst_en.sys[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_25;
    assign unused_rst_en_25 = rstmgr_aon_rst_en.sys_io_div4[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_26;
    assign unused_rst_en_26 = rstmgr_aon_rst_en.sys_io_div4[rstmgr_pkg::Domain0Sel];
    prim_mubi_pkg::mubi4_t unused_rst_en_27;
    assign unused_rst_en_27 = rstmgr_aon_rst_en.spi_device[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_28;
    assign unused_rst_en_28 = rstmgr_aon_rst_en.spi_host0[rstmgr_pkg::DomainAonSel];
    prim_mubi_pkg::mubi4_t unused_rst_en_29;
    assign unused_rst_en_29 = rstmgr_aon_rst_en.i2c0[rstmgr_pkg::DomainAonSel];
//VCS coverage on
// pragma coverage on

  // Peripheral Instantiation


  uart #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[0:0])
  ) u_uart0 (

      // Input
      .cio_rx_i    (cio_uart0_rx_p2d),

      // Output
      .cio_tx_o    (cio_uart0_tx_d2p),
      .cio_tx_en_o (cio_uart0_tx_en_d2p),

      // Interrupt
      .intr_tx_watermark_o  (intr_uart0_tx_watermark),
      .intr_rx_watermark_o  (intr_uart0_rx_watermark),
      .intr_tx_empty_o      (intr_uart0_tx_empty),
      .intr_rx_overflow_o   (intr_uart0_rx_overflow),
      .intr_rx_frame_err_o  (intr_uart0_rx_frame_err),
      .intr_rx_break_err_o  (intr_uart0_rx_break_err),
      .intr_rx_timeout_o    (intr_uart0_rx_timeout),
      .intr_rx_parity_err_o (intr_uart0_rx_parity_err),
      // [0]: fatal_fault
      .alert_tx_o  ( alert_tx[0:0] ),
      .alert_rx_i  ( alert_rx[0:0] ),

      // Inter-module signals
      .lsio_trigger_o(uart0_lsio_trigger),
      .tl_i(uart0_tl_req),
      .tl_o(uart0_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  gpio #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[1:1]),
    .GpioAsyncOn(GpioGpioAsyncOn),
    .GpioAsHwStrapsEn(GpioGpioAsHwStrapsEn)
  ) u_gpio (

      // Input
      .cio_gpio_i    (cio_gpio_gpio_p2d),

      // Output
      .cio_gpio_o    (cio_gpio_gpio_d2p),
      .cio_gpio_en_o (cio_gpio_gpio_en_d2p),

      // Interrupt
      .intr_gpio_o (intr_gpio_gpio),
      // [1]: fatal_fault
      .alert_tx_o  ( alert_tx[1:1] ),
      .alert_rx_i  ( alert_rx[1:1] ),

      // Inter-module signals
      .strap_en_i(pwrmgr_aon_strap),
      .sampled_straps_o(),
      .tl_i(gpio_tl_req),
      .tl_o(gpio_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  spi_device #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[2:2])
  ) u_spi_device (

      // Input
      .cio_sck_i        (cio_spi_device_sck_p2d),
      .cio_csb_i        (cio_spi_device_csb_p2d),
      .cio_tpm_csb_i    (cio_spi_device_tpm_csb_p2d),
      .cio_sd_i         (cio_spi_device_sd_p2d),

      // Output
      .cio_sd_o         (cio_spi_device_sd_d2p),
      .cio_sd_en_o      (cio_spi_device_sd_en_d2p),

      // Interrupt
      .intr_generic_rx_full_o          (intr_spi_device_generic_rx_full),
      .intr_generic_rx_watermark_o     (intr_spi_device_generic_rx_watermark),
      .intr_generic_tx_watermark_o     (intr_spi_device_generic_tx_watermark),
      .intr_generic_rx_error_o         (intr_spi_device_generic_rx_error),
      .intr_generic_rx_overflow_o      (intr_spi_device_generic_rx_overflow),
      .intr_generic_tx_underflow_o     (intr_spi_device_generic_tx_underflow),
      .intr_upload_cmdfifo_not_empty_o (intr_spi_device_upload_cmdfifo_not_empty),
      .intr_upload_payload_not_empty_o (intr_spi_device_upload_payload_not_empty),
      .intr_upload_payload_overflow_o  (intr_spi_device_upload_payload_overflow),
      .intr_readbuf_watermark_o        (intr_spi_device_readbuf_watermark),
      .intr_readbuf_flip_o             (intr_spi_device_readbuf_flip),
      .intr_tpm_header_not_empty_o     (intr_spi_device_tpm_header_not_empty),
      // [2]: fatal_fault
      .alert_tx_o  ( alert_tx[2:2] ),
      .alert_rx_i  ( alert_rx[2:2] ),

      // Inter-module signals
      .ram_cfg_i(ast_spi_ram_2p_cfg),
      .passthrough_o(spi_device_passthrough_req),
      .passthrough_i(spi_device_passthrough_rsp),
      .mbist_en_i('0),
      .sck_monitor_o(sck_monitor_o),
      .tl_i(spi_device_tl_req),
      .tl_o(spi_device_tl_rsp),
      .scanmode_i,
      .scan_rst_ni,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .scan_clk_i (clkmgr_aon_clocks.clk_io_div2_peri),
      .rst_ni (rstmgr_aon_resets.rst_spi_device_n[rstmgr_pkg::Domain0Sel])
  );
  i2c #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[3:3])
  ) u_i2c0 (

      // Input
      .cio_sda_i    (cio_i2c0_sda_p2d),
      .cio_scl_i    (cio_i2c0_scl_p2d),

      // Output
      .cio_sda_o    (cio_i2c0_sda_d2p),
      .cio_sda_en_o (cio_i2c0_sda_en_d2p),
      .cio_scl_o    (cio_i2c0_scl_d2p),
      .cio_scl_en_o (cio_i2c0_scl_en_d2p),

      // Interrupt
      .intr_fmt_threshold_o    (intr_i2c0_fmt_threshold),
      .intr_rx_threshold_o     (intr_i2c0_rx_threshold),
      .intr_fmt_overflow_o     (intr_i2c0_fmt_overflow),
      .intr_rx_overflow_o      (intr_i2c0_rx_overflow),
      .intr_nak_o              (intr_i2c0_nak),
      .intr_scl_interference_o (intr_i2c0_scl_interference),
      .intr_sda_interference_o (intr_i2c0_sda_interference),
      .intr_stretch_timeout_o  (intr_i2c0_stretch_timeout),
      .intr_sda_unstable_o     (intr_i2c0_sda_unstable),
      .intr_cmd_complete_o     (intr_i2c0_cmd_complete),
      .intr_tx_stretch_o       (intr_i2c0_tx_stretch),
      .intr_tx_overflow_o      (intr_i2c0_tx_overflow),
      .intr_acq_full_o         (intr_i2c0_acq_full),
      .intr_unexp_stop_o       (intr_i2c0_unexp_stop),
      .intr_host_timeout_o     (intr_i2c0_host_timeout),
      // [3]: fatal_fault
      .alert_tx_o  ( alert_tx[3:3] ),
      .alert_rx_i  ( alert_rx[3:3] ),

      // Inter-module signals
      .lsio_trigger_o(i2c0_lsio_trigger),
      .tl_i(i2c0_tl_req),
      .tl_o(i2c0_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .rst_ni (rstmgr_aon_resets.rst_i2c0_n[rstmgr_pkg::Domain0Sel])
  );
  rv_timer #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[4:4])
  ) u_rv_timer (

      // Interrupt
      .intr_timer_expired_hart0_timer0_o (intr_rv_timer_timer_expired_hart0_timer0),
      // [4]: fatal_fault
      .alert_tx_o  ( alert_tx[4:4] ),
      .alert_rx_i  ( alert_rx[4:4] ),

      // Inter-module signals
      .tl_i(rv_timer_tl_req),
      .tl_o(rv_timer_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_timers),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  otp_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[9:5]),
    .MemInitFile(OtpCtrlMemInitFile),
    .RndCnstLfsrSeed(RndCnstOtpCtrlLfsrSeed),
    .RndCnstLfsrPerm(RndCnstOtpCtrlLfsrPerm),
    .RndCnstScrmblKeyInit(RndCnstOtpCtrlScrmblKeyInit)
  ) u_otp_ctrl (

      // Output
      .cio_test_o    (cio_otp_ctrl_test_d2p),
      .cio_test_en_o (cio_otp_ctrl_test_en_d2p),

      // Interrupt
      .intr_otp_operation_done_o (intr_otp_ctrl_otp_operation_done),
      .intr_otp_error_o          (intr_otp_ctrl_otp_error),
      // [5]: fatal_macro_error
      // [6]: fatal_check_error
      // [7]: fatal_bus_integ_error
      // [8]: fatal_prim_otp_alert
      // [9]: recov_prim_otp_alert
      .alert_tx_o  ( alert_tx[9:5] ),
      .alert_rx_i  ( alert_rx[9:5] ),

      // Inter-module signals
      .otp_ext_voltage_h_io(otp_ext_voltage_h_io),
      .otp_ast_pwr_seq_o(otp_ctrl_otp_ast_pwr_seq_o),
      .otp_ast_pwr_seq_h_i(otp_ctrl_otp_ast_pwr_seq_h_i),
      .edn_o(edn0_edn_req[1]),
      .edn_i(edn0_edn_rsp[1]),
      .pwr_otp_i(pwrmgr_aon_pwr_otp_req),
      .pwr_otp_o(pwrmgr_aon_pwr_otp_rsp),
      .lc_otp_vendor_test_i(lc_ctrl_lc_otp_vendor_test_req),
      .lc_otp_vendor_test_o(lc_ctrl_lc_otp_vendor_test_rsp),
      .lc_otp_program_i(lc_ctrl_lc_otp_program_req),
      .lc_otp_program_o(lc_ctrl_lc_otp_program_rsp),
      .otp_lc_data_o(otp_ctrl_otp_lc_data),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_creator_seed_sw_rw_en_i(lc_ctrl_lc_creator_seed_sw_rw_en),
      .lc_seed_hw_rd_en_i(lc_ctrl_lc_seed_hw_rd_en),
      .lc_dft_en_i(lc_ctrl_lc_dft_en),
      .lc_check_byp_en_i(lc_ctrl_lc_check_byp_en),
      .otp_keymgr_key_o(otp_ctrl_otp_keymgr_key),
      .flash_otp_key_i('0),
      .flash_otp_key_o(),
      .sram_otp_key_i(otp_ctrl_sram_otp_key_req),
      .sram_otp_key_o(otp_ctrl_sram_otp_key_rsp),
      .otbn_otp_key_i(otp_ctrl_otbn_otp_key_req),
      .otbn_otp_key_o(otp_ctrl_otbn_otp_key_rsp),
      .otp_broadcast_o(otp_ctrl_otp_broadcast),
      .obs_ctrl_i(ast_obs_ctrl),
      .otp_obs_o(otp_obs_o),
      .core_tl_i(otp_ctrl_core_tl_req),
      .core_tl_o(otp_ctrl_core_tl_rsp),
      .prim_tl_i(otp_ctrl_prim_tl_req),
      .prim_tl_o(otp_ctrl_prim_tl_rsp),
      .scanmode_i,
      .scan_rst_ni,
      .scan_en_i,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  lc_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[12:10]),
    .SecVolatileRawUnlockEn(SecLcCtrlVolatileRawUnlockEn),
    .RndCnstLcKeymgrDivInvalid(RndCnstLcCtrlLcKeymgrDivInvalid),
    .RndCnstLcKeymgrDivTestDevRma(RndCnstLcCtrlLcKeymgrDivTestDevRma),
    .RndCnstLcKeymgrDivProduction(RndCnstLcCtrlLcKeymgrDivProduction),
    .RndCnstInvalidTokens(RndCnstLcCtrlInvalidTokens),
    .SiliconCreatorId(LcCtrlSiliconCreatorId),
    .ProductId(LcCtrlProductId),
    .RevisionId(LcCtrlRevisionId)
  ) u_lc_ctrl (
      // [10]: fatal_prog_error
      // [11]: fatal_state_error
      // [12]: fatal_bus_integ_error
      .alert_tx_o  ( alert_tx[12:10] ),
      .alert_rx_i  ( alert_rx[12:10] ),

      // Inter-module signals
      .dmi_tl_h2d_i(lc_ctrl_dmi_h2d_i),
      .dmi_tl_d2h_o(lc_ctrl_dmi_d2h_o),
      .esc_scrap_state0_tx_i(alert_handler_esc_tx[1]),
      .esc_scrap_state0_rx_o(alert_handler_esc_rx[1]),
      .esc_scrap_state1_tx_i(alert_handler_esc_tx[2]),
      .esc_scrap_state1_rx_o(alert_handler_esc_rx[2]),
      .pwr_lc_i(pwrmgr_aon_pwr_lc_req),
      .pwr_lc_o(pwrmgr_aon_pwr_lc_rsp),
      .lc_otp_vendor_test_o(lc_ctrl_lc_otp_vendor_test_req),
      .lc_otp_vendor_test_i(lc_ctrl_lc_otp_vendor_test_rsp),
      .otp_lc_data_i(otp_ctrl_otp_lc_data),
      .lc_otp_program_o(lc_ctrl_lc_otp_program_req),
      .lc_otp_program_i(lc_ctrl_lc_otp_program_rsp),
      .kmac_data_o(kmac_app_req[1]),
      .kmac_data_i(kmac_app_rsp[1]),
      .lc_dft_en_o(lc_ctrl_lc_dft_en),
      .lc_nvm_debug_en_o(),
      .lc_hw_debug_en_o(lc_ctrl_lc_hw_debug_en),
      .lc_cpu_en_o(lc_ctrl_lc_cpu_en),
      .lc_keymgr_en_o(lc_ctrl_lc_keymgr_en),
      .lc_escalate_en_o(lc_ctrl_lc_escalate_en),
      .lc_clk_byp_req_o(lc_ctrl_lc_clk_byp_req),
      .lc_clk_byp_ack_i(lc_ctrl_lc_clk_byp_ack),
      .lc_flash_rma_req_o(lc_ctrl_lc_flash_rma_req),
      .lc_flash_rma_seed_o(),
      .lc_flash_rma_ack_i(otbn_lc_rma_ack),
      .lc_check_byp_en_o(lc_ctrl_lc_check_byp_en),
      .lc_creator_seed_sw_rw_en_o(lc_ctrl_lc_creator_seed_sw_rw_en),
      .lc_owner_seed_sw_rw_en_o(),
      .lc_iso_part_sw_rd_en_o(),
      .lc_iso_part_sw_wr_en_o(),
      .lc_seed_hw_rd_en_o(lc_ctrl_lc_seed_hw_rd_en),
      .lc_keymgr_div_o(lc_ctrl_lc_keymgr_div),
      .otp_device_id_i(lc_ctrl_otp_device_id),
      .otp_manuf_state_i(lc_ctrl_otp_manuf_state),
      .hw_rev_o(),
      .strap_en_override_o(lc_ctrl_strap_en_override),
      .tl_i(lc_ctrl_tl_req),
      .tl_o(lc_ctrl_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .clk_kmac_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),
      .rst_kmac_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  alert_handler #(
    .RndCnstLfsrSeed(RndCnstAlertHandlerLfsrSeed),
    .RndCnstLfsrPerm(RndCnstAlertHandlerLfsrPerm)
  ) u_alert_handler (

      // Interrupt
      .intr_classa_o (intr_alert_handler_classa),
      .intr_classb_o (intr_alert_handler_classb),
      .intr_classc_o (intr_alert_handler_classc),
      .intr_classd_o (intr_alert_handler_classd),

      // Inter-module signals
      .crashdump_o(alert_handler_crashdump),
      .edn_o(edn0_edn_req[4]),
      .edn_i(edn0_edn_rsp[4]),
      .esc_rx_i(alert_handler_esc_rx),
      .esc_tx_o(alert_handler_esc_tx),
      .tl_i(alert_handler_tl_req),
      .tl_o(alert_handler_tl_rsp),
      // alert signals
      .alert_rx_o  ( alert_rx ),
      .alert_tx_i  ( alert_tx ),
      // synchronized clock gated / reset asserted
      // indications for each alert
      .lpg_cg_en_i  ( lpg_cg_en  ),
      .lpg_rst_en_i ( lpg_rst_en ),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_shadowed_ni (rstmgr_aon_resets.rst_lc_io_div4_shadowed_n[rstmgr_pkg::Domain0Sel]),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  spi_host #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[13:13])
  ) u_spi_host0 (

      // Input
      .cio_sd_i     (cio_spi_host0_sd_p2d),

      // Output
      .cio_sck_o    (cio_spi_host0_sck_d2p),
      .cio_sck_en_o (cio_spi_host0_sck_en_d2p),
      .cio_csb_o    (cio_spi_host0_csb_d2p),
      .cio_csb_en_o (cio_spi_host0_csb_en_d2p),
      .cio_sd_o     (cio_spi_host0_sd_d2p),
      .cio_sd_en_o  (cio_spi_host0_sd_en_d2p),

      // Interrupt
      .intr_error_o     (intr_spi_host0_error),
      .intr_spi_event_o (intr_spi_host0_spi_event),
      // [13]: fatal_fault
      .alert_tx_o  ( alert_tx[13:13] ),
      .alert_rx_i  ( alert_rx[13:13] ),

      // Inter-module signals
      .passthrough_i(spi_device_passthrough_req),
      .passthrough_o(spi_device_passthrough_rsp),
      .lsio_trigger_o(spi_host0_lsio_trigger),
      .tl_i(spi_host0_tl_req),
      .tl_o(spi_host0_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .rst_ni (rstmgr_aon_resets.rst_spi_host0_n[rstmgr_pkg::Domain0Sel])
  );
  pwrmgr #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[14:14])
  ) u_pwrmgr_aon (

      // Interrupt
      .intr_wakeup_o (intr_pwrmgr_aon_wakeup),
      // [14]: fatal_fault
      .alert_tx_o  ( alert_tx[14:14] ),
      .alert_rx_i  ( alert_rx[14:14] ),

      // Inter-module signals
      .pwr_ast_o(pwrmgr_ast_req_o),
      .pwr_ast_i(pwrmgr_ast_rsp_i),
      .pwr_rst_o(pwrmgr_aon_pwr_rst_req),
      .pwr_rst_i(pwrmgr_aon_pwr_rst_rsp),
      .pwr_clk_o(pwrmgr_aon_pwr_clk_req),
      .pwr_clk_i(pwrmgr_aon_pwr_clk_rsp),
      .pwr_otp_o(pwrmgr_aon_pwr_otp_req),
      .pwr_otp_i(pwrmgr_aon_pwr_otp_rsp),
      .pwr_lc_o(pwrmgr_aon_pwr_lc_req),
      .pwr_lc_i(pwrmgr_aon_pwr_lc_rsp),
      .pwr_flash_i(pwrmgr_pkg::PWR_FLASH_DEFAULT),
      .esc_rst_tx_i(alert_handler_esc_tx[3]),
      .esc_rst_rx_o(alert_handler_esc_rx[3]),
      .pwr_cpu_i(rv_core_ibex_pwrmgr),
      .wakeups_i(pwrmgr_aon_wakeups),
      .rstreqs_i(pwrmgr_aon_rstreqs),
      .ndmreset_req_i(rv_dm_ndmreset_req),
      .strap_o(pwrmgr_aon_strap),
      .low_power_o(pwrmgr_aon_low_power),
      .rom_ctrl_i(pwrmgr_aon_rom_ctrl),
      .fetch_en_o(pwrmgr_aon_fetch_en),
      .lc_dft_en_i(lc_ctrl_lc_dft_en),
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .sw_rst_req_i(rstmgr_aon_sw_rst_req),
      .tl_i(pwrmgr_aon_tl_req),
      .tl_o(pwrmgr_aon_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_slow_i (clkmgr_aon_clocks.clk_aon_powerup),
      .clk_lc_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_esc_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .rst_ni (rstmgr_aon_resets.rst_por_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_main_ni (rstmgr_aon_resets.rst_por_aon_n[rstmgr_pkg::Domain0Sel]),
      .rst_lc_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_esc_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_slow_ni (rstmgr_aon_resets.rst_por_aon_n[rstmgr_pkg::DomainAonSel])
  );
  rstmgr #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[16:15]),
    .SecCheck(SecRstmgrAonCheck),
    .SecMaxSyncDelay(SecRstmgrAonMaxSyncDelay)
  ) u_rstmgr_aon (
      // [15]: fatal_fault
      // [16]: fatal_cnsty_fault
      .alert_tx_o  ( alert_tx[16:15] ),
      .alert_rx_i  ( alert_rx[16:15] ),

      // Inter-module signals
      .por_n_i(por_n_i),
      .pwr_i(pwrmgr_aon_pwr_rst_req),
      .pwr_o(pwrmgr_aon_pwr_rst_rsp),
      .resets_o(rstmgr_aon_resets),
      .rst_en_o(rstmgr_aon_rst_en),
      .alert_dump_i(alert_handler_crashdump),
      .cpu_dump_i(rv_core_ibex_crash_dump),
      .sw_rst_req_o(rstmgr_aon_sw_rst_req),
      .tl_i(rstmgr_aon_tl_req),
      .tl_o(rstmgr_aon_tl_rsp),
      .scanmode_i,
      .scan_rst_ni,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_por_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_powerup),
      .clk_main_i (clkmgr_aon_clocks.clk_main_powerup),
      .clk_io_i (clkmgr_aon_clocks.clk_io_powerup),
      .clk_usb_i (clkmgr_aon_clocks.clk_usb_powerup),
      .clk_io_div2_i (clkmgr_aon_clocks.clk_io_div2_powerup),
      .clk_io_div4_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_por_ni (rstmgr_aon_resets.rst_por_io_div4_n[rstmgr_pkg::DomainAonSel])
  );
  clkmgr #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[18:17])
  ) u_clkmgr_aon (
      // [17]: recov_fault
      // [18]: fatal_fault
      .alert_tx_o  ( alert_tx[18:17] ),
      .alert_rx_i  ( alert_rx[18:17] ),

      // Inter-module signals
      .clocks_o(clkmgr_aon_clocks),
      .cg_en_o(clkmgr_aon_cg_en),
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .io_clk_byp_req_o(io_clk_byp_req_o),
      .io_clk_byp_ack_i(io_clk_byp_ack_i),
      .all_clk_byp_req_o(all_clk_byp_req_o),
      .all_clk_byp_ack_i(all_clk_byp_ack_i),
      .hi_speed_sel_o(hi_speed_sel_o),
      .div_step_down_req_i(div_step_down_req_i),
      .lc_clk_byp_req_i(lc_ctrl_lc_clk_byp_req),
      .lc_clk_byp_ack_o(lc_ctrl_lc_clk_byp_ack),
      .jitter_en_o(clk_main_jitter_en_o),
      .pwr_i(pwrmgr_aon_pwr_clk_req),
      .pwr_o(pwrmgr_aon_pwr_clk_rsp),
      .idle_i(clkmgr_aon_idle),
      .calib_rdy_i(calib_rdy_i),
      .tl_i(clkmgr_aon_tl_req),
      .tl_o(clkmgr_aon_tl_rsp),
      .scanmode_i,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_main_i (clk_main_i),
      .clk_io_i (clk_io_i),
      .clk_usb_i (clk_usb_i),
      .clk_aon_i (clk_aon_i),
      .rst_shadowed_ni (rstmgr_aon_resets.rst_lc_io_div4_shadowed_n[rstmgr_pkg::DomainAonSel]),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::DomainAonSel]),
      .rst_io_ni (rstmgr_aon_resets.rst_lc_io_n[rstmgr_pkg::DomainAonSel]),
      .rst_io_div2_ni (rstmgr_aon_resets.rst_lc_io_div2_n[rstmgr_pkg::DomainAonSel]),
      .rst_io_div4_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_main_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::DomainAonSel]),
      .rst_usb_ni (rstmgr_aon_resets.rst_lc_usb_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_ni (rstmgr_aon_resets.rst_por_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_io_ni (rstmgr_aon_resets.rst_por_io_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_io_div2_ni (rstmgr_aon_resets.rst_por_io_div2_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_io_div4_ni (rstmgr_aon_resets.rst_por_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_main_ni (rstmgr_aon_resets.rst_por_n[rstmgr_pkg::DomainAonSel]),
      .rst_root_usb_ni (rstmgr_aon_resets.rst_por_usb_n[rstmgr_pkg::DomainAonSel])
  );
  adc_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[19:19])
  ) u_adc_ctrl_aon (

      // Interrupt
      .intr_match_done_o (intr_adc_ctrl_aon_match_done),
      // [19]: fatal_fault
      .alert_tx_o  ( alert_tx[19:19] ),
      .alert_rx_i  ( alert_rx[19:19] ),

      // Inter-module signals
      .adc_o(adc_req_o),
      .adc_i(adc_rsp_i),
      .wkup_req_o(pwrmgr_aon_wakeups[0]),
      .tl_i(adc_ctrl_aon_tl_req),
      .tl_o(adc_ctrl_aon_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_peri),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_peri),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::DomainAonSel])
  );
  pinmux #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[20:20]),
    .UsbWkupModuleEn(PinmuxAonUsbWkupModuleEn),
    .HwStrapSamplingEn(PinmuxAonHwStrapSamplingEn),
    .SecVolatileRawUnlockEn(SecPinmuxAonVolatileRawUnlockEn),
    .TargetCfg(PinmuxAonTargetCfg)
  ) u_pinmux_aon (
      // [20]: fatal_fault
      .alert_tx_o  ( alert_tx[20:20] ),
      .alert_rx_i  ( alert_rx[20:20] ),

      // Inter-module signals
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .lc_dft_en_i(lc_ctrl_lc_dft_en),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_check_byp_en_i(lc_ctrl_lc_check_byp_en),
      .pinmux_hw_debug_en_o(),
      .lc_jtag_o(),
      .lc_jtag_i(jtag_pkg::JTAG_RSP_DEFAULT),
      .rv_jtag_o(),
      .rv_jtag_i(jtag_pkg::JTAG_RSP_DEFAULT),
      .dft_jtag_o(),
      .dft_jtag_i(jtag_pkg::JTAG_RSP_DEFAULT),
      .dft_strap_test_o(dft_strap_test_o),
      .dft_hold_tap_sel_i(dft_hold_tap_sel_i),
      .sleep_en_i(pwrmgr_aon_low_power),
      .strap_en_i(pwrmgr_aon_strap),
      .strap_en_override_i(lc_ctrl_strap_en_override),
      .pin_wkup_req_o(pwrmgr_aon_wakeups[1]),
      .usbdev_dppullup_en_i('0),
      .usbdev_dnpullup_en_i('0),
      .usb_dppullup_en_o(),
      .usb_dnpullup_en_o(),
      .usb_wkup_req_o(pwrmgr_aon_wakeups[2]),
      .usbdev_suspend_req_i('0),
      .usbdev_wake_ack_i('0),
      .usbdev_bus_reset_o(),
      .usbdev_sense_lost_o(),
      .usbdev_wake_detect_active_o(),
      .tl_i(pinmux_aon_tl_req),
      .tl_o(pinmux_aon_tl_rsp),

      .periph_to_mio_i      (mio_d2p    ),
      .periph_to_mio_oe_i   (mio_en_d2p ),
      .mio_to_periph_o      (mio_p2d    ),

      .mio_attr_o,
      .mio_out_o,
      .mio_oe_o,
      .mio_in_i,

      .periph_to_dio_i      (dio_d2p    ),
      .periph_to_dio_oe_i   (dio_en_d2p ),
      .dio_to_periph_o      (dio_p2d    ),

      .dio_attr_o,
      .dio_out_o,
      .dio_oe_o,
      .dio_in_i,

      .scanmode_i,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_powerup),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_powerup),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::DomainAonSel]),
      .rst_sys_ni (rstmgr_aon_resets.rst_sys_io_div4_n[rstmgr_pkg::DomainAonSel])
  );
  aon_timer #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[21:21])
  ) u_aon_timer_aon (

      // Interrupt
      .intr_wkup_timer_expired_o (intr_aon_timer_aon_wkup_timer_expired),
      .intr_wdog_timer_bark_o    (intr_aon_timer_aon_wdog_timer_bark),
      // [21]: fatal_fault
      .alert_tx_o  ( alert_tx[21:21] ),
      .alert_rx_i  ( alert_rx[21:21] ),

      // Inter-module signals
      .nmi_wdog_timer_bark_o(aon_timer_aon_nmi_wdog_timer_bark),
      .wkup_req_o(pwrmgr_aon_wakeups[3]),
      .aon_timer_rst_req_o(pwrmgr_aon_rstreqs[0]),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .sleep_mode_i(pwrmgr_aon_low_power),
      .tl_i(aon_timer_aon_tl_req),
      .tl_o(aon_timer_aon_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_timers),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_timers),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::DomainAonSel])
  );
  sensor_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[23:22])
  ) u_sensor_ctrl (

      // Output
      .cio_ast_debug_out_o    (cio_sensor_ctrl_ast_debug_out_d2p),
      .cio_ast_debug_out_en_o (cio_sensor_ctrl_ast_debug_out_en_d2p),

      // Interrupt
      .intr_io_status_change_o   (intr_sensor_ctrl_io_status_change),
      .intr_init_status_change_o (intr_sensor_ctrl_init_status_change),
      // [22]: recov_alert
      // [23]: fatal_alert
      .alert_tx_o  ( alert_tx[23:22] ),
      .alert_rx_i  ( alert_rx[23:22] ),

      // Inter-module signals
      .ast_alert_i(sensor_ctrl_ast_alert_req_i),
      .ast_alert_o(sensor_ctrl_ast_alert_rsp_o),
      .ast_status_i(sensor_ctrl_ast_status_i),
      .ast_init_done_i(ast_init_done_i),
      .ast2pinmux_i(ast2pinmux_i),
      .wkup_req_o(pwrmgr_aon_wakeups[4]),
      .tl_i(sensor_ctrl_tl_req),
      .tl_o(sensor_ctrl_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::DomainAonSel])
  );
  soc_proxy #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[32:24])
  ) u_soc_proxy (

      // Interrupt
      .intr_external_o (intr_soc_proxy_external),
      // [24]: fatal_alert_intg
      // [25]: fatal_alert_external_0
      // [26]: fatal_alert_external_1
      // [27]: fatal_alert_external_2
      // [28]: fatal_alert_external_3
      // [29]: recov_alert_external_0
      // [30]: recov_alert_external_1
      // [31]: recov_alert_external_2
      // [32]: recov_alert_external_3
      .alert_tx_o  ( alert_tx[32:24] ),
      .alert_rx_i  ( alert_rx[32:24] ),

      // Inter-module signals
      .wkup_internal_req_o(pwrmgr_aon_wakeups[5]),
      .wkup_external_req_o(pwrmgr_aon_wakeups[6]),
      .rst_req_external_o(pwrmgr_aon_rstreqs[1]),
      .ctn_tl_h2d_o(ctn_tl_h2d_o),
      .ctn_tl_d2h_i(ctn_tl_d2h_i),
      .i2c_lsio_trigger_i(i2c0_lsio_trigger),
      .spi_host_lsio_trigger_i(spi_host0_lsio_trigger),
      .uart_lsio_trigger_i(uart0_lsio_trigger),
      .soc_lsio_trigger_i(soc_lsio_trigger_i),
      .dma_lsio_trigger_o(dma_lsio_trigger),
      .soc_fatal_alert_i(soc_fatal_alert_req_i),
      .soc_fatal_alert_o(soc_fatal_alert_rsp_o),
      .soc_recov_alert_i(soc_recov_alert_req_i),
      .soc_recov_alert_o(soc_recov_alert_rsp_o),
      .soc_wkup_async_i(soc_wkup_async_i),
      .soc_rst_req_async_i(soc_rst_req_async_i),
      .soc_intr_async_i(soc_intr_async_i),
      .core_tl_i(soc_proxy_core_tl_req),
      .core_tl_o(soc_proxy_core_tl_rsp),
      .ctn_tl_i(soc_proxy_ctn_tl_req),
      .ctn_tl_o(soc_proxy_ctn_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .clk_aon_i (clkmgr_aon_clocks.clk_aon_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_aon_ni (rstmgr_aon_resets.rst_lc_aon_n[rstmgr_pkg::Domain0Sel])
  );
  sram_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[33:33]),
    .RndCnstSramKey(RndCnstSramCtrlRetAonSramKey),
    .RndCnstSramNonce(RndCnstSramCtrlRetAonSramNonce),
    .RndCnstLfsrSeed(RndCnstSramCtrlRetAonLfsrSeed),
    .RndCnstLfsrPerm(RndCnstSramCtrlRetAonLfsrPerm),
    .MemSizeRam(4096),
    .InstrExec(SramCtrlRetAonInstrExec)
  ) u_sram_ctrl_ret_aon (
      // [33]: fatal_error
      .alert_tx_o  ( alert_tx[33:33] ),
      .alert_rx_i  ( alert_rx[33:33] ),

      // Inter-module signals
      .sram_otp_key_o(otp_ctrl_sram_otp_key_req[1]),
      .sram_otp_key_i(otp_ctrl_sram_otp_key_rsp[1]),
      .cfg_i(ast_ram_1p_cfg),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_hw_debug_en_i(lc_ctrl_pkg::Off),
      .otp_en_sram_ifetch_i(prim_mubi_pkg::MuBi8False),
      .regs_tl_i(sram_ctrl_ret_aon_regs_tl_req),
      .regs_tl_o(sram_ctrl_ret_aon_regs_tl_rsp),
      .ram_tl_i(sram_ctrl_ret_aon_ram_tl_req),
      .ram_tl_o(sram_ctrl_ret_aon_ram_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_io_div4_infra),
      .clk_otp_i (clkmgr_aon_clocks.clk_io_div4_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel]),
      .rst_otp_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::DomainAonSel])
  );
  rv_dm #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[34:34])
  ) u_rv_dm (
      // [34]: fatal_fault
      .alert_tx_o  ( alert_tx[34:34] ),
      .alert_rx_i  ( alert_rx[34:34] ),

      // Inter-module signals
      .dmi_tl_h2d_i(rv_dm_dmi_h2d_i),
      .dmi_tl_d2h_o(rv_dm_dmi_d2h_o),
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .pinmux_hw_debug_en_i(rv_pinmux_hw_debug_en_i),
      .unavailable_i(1'b0),
      .ndmreset_req_o(rv_dm_ndmreset_req),
      .dmactive_o(),
      .debug_req_o(rv_dm_debug_req),
      .sba_tl_h_o(main_tl_rv_dm__sba_req),
      .sba_tl_h_i(main_tl_rv_dm__sba_rsp),
      .regs_tl_d_i(rv_dm_regs_tl_d_req),
      .regs_tl_d_o(rv_dm_regs_tl_d_rsp),
      .mem_tl_d_i(rv_dm_mem_tl_d_req),
      .mem_tl_d_o(rv_dm_mem_tl_d_rsp),
      .scanmode_i,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_sys_n[rstmgr_pkg::Domain0Sel])
  );
  rv_plic #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[35:35])
  ) u_rv_plic (
      // [35]: fatal_fault
      .alert_tx_o  ( alert_tx[35:35] ),
      .alert_rx_i  ( alert_rx[35:35] ),

      // Inter-module signals
      .irq_o(rv_plic_irq),
      .irq_id_o(),
      .msip_o(rv_plic_msip),
      .tl_i(rv_plic_tl_req),
      .tl_o(rv_plic_tl_rsp),
      .intr_src_i (intr_vector),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  aes #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[37:36]),
    .AES192Enable(1'b1),
    .SecMasking(SecAesMasking),
    .SecSBoxImpl(SecAesSBoxImpl),
    .SecStartTriggerDelay(SecAesStartTriggerDelay),
    .SecAllowForcingMasks(SecAesAllowForcingMasks),
    .SecSkipPRNGReseeding(SecAesSkipPRNGReseeding),
    .RndCnstClearingLfsrSeed(RndCnstAesClearingLfsrSeed),
    .RndCnstClearingLfsrPerm(RndCnstAesClearingLfsrPerm),
    .RndCnstClearingSharePerm(RndCnstAesClearingSharePerm),
    .RndCnstMaskingLfsrSeed(RndCnstAesMaskingLfsrSeed),
    .RndCnstMaskingLfsrPerm(RndCnstAesMaskingLfsrPerm)
  ) u_aes (
      // [36]: recov_ctrl_update_err
      // [37]: fatal_fault
      .alert_tx_o  ( alert_tx[37:36] ),
      .alert_rx_i  ( alert_rx[37:36] ),

      // Inter-module signals
      .idle_o(clkmgr_aon_idle[0]),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .edn_o(edn0_edn_req[5]),
      .edn_i(edn0_edn_rsp[5]),
      .keymgr_key_i(keymgr_dpe_aes_key),
      .tl_i(aes_tl_req),
      .tl_o(aes_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_aes),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_aes),
      .rst_shadowed_ni (rstmgr_aon_resets.rst_lc_shadowed_n[rstmgr_pkg::Domain0Sel]),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  hmac #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[38:38])
  ) u_hmac (

      // Interrupt
      .intr_hmac_done_o  (intr_hmac_hmac_done),
      .intr_fifo_empty_o (intr_hmac_fifo_empty),
      .intr_hmac_err_o   (intr_hmac_hmac_err),
      // [38]: fatal_fault
      .alert_tx_o  ( alert_tx[38:38] ),
      .alert_rx_i  ( alert_rx[38:38] ),

      // Inter-module signals
      .idle_o(clkmgr_aon_idle[1]),
      .tl_i(hmac_tl_req),
      .tl_o(hmac_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_hmac),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  kmac #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[40:39]),
    .EnMasking(KmacEnMasking),
    .SwKeyMasked(KmacSwKeyMasked),
    .SecCmdDelay(SecKmacCmdDelay),
    .SecIdleAcceptSwMsg(SecKmacIdleAcceptSwMsg),
    .RndCnstLfsrSeed(RndCnstKmacLfsrSeed),
    .RndCnstLfsrPerm(RndCnstKmacLfsrPerm),
    .RndCnstLfsrFwdPerm(RndCnstKmacLfsrFwdPerm),
    .RndCnstMsgPerm(RndCnstKmacMsgPerm)
  ) u_kmac (

      // Interrupt
      .intr_kmac_done_o  (intr_kmac_kmac_done),
      .intr_fifo_empty_o (intr_kmac_fifo_empty),
      .intr_kmac_err_o   (intr_kmac_kmac_err),
      // [39]: recov_operation_err
      // [40]: fatal_fault_err
      .alert_tx_o  ( alert_tx[40:39] ),
      .alert_rx_i  ( alert_rx[40:39] ),

      // Inter-module signals
      .keymgr_key_i(keymgr_dpe_kmac_key),
      .app_i(kmac_app_req),
      .app_o(kmac_app_rsp),
      .entropy_o(edn0_edn_req[3]),
      .entropy_i(edn0_edn_rsp[3]),
      .idle_o(clkmgr_aon_idle[2]),
      .en_masking_o(kmac_en_masking),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .tl_i(kmac_tl_req),
      .tl_o(kmac_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_kmac),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_kmac),
      .rst_shadowed_ni (rstmgr_aon_resets.rst_lc_shadowed_n[rstmgr_pkg::Domain0Sel]),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  otbn #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[42:41]),
    .Stub(OtbnStub),
    .RegFile(OtbnRegFile),
    .RndCnstUrndPrngSeed(RndCnstOtbnUrndPrngSeed),
    .SecMuteUrnd(SecOtbnMuteUrnd),
    .SecSkipUrndReseedAtStart(SecOtbnSkipUrndReseedAtStart),
    .RndCnstOtbnKey(RndCnstOtbnOtbnKey),
    .RndCnstOtbnNonce(RndCnstOtbnOtbnNonce)
  ) u_otbn (

      // Interrupt
      .intr_done_o (intr_otbn_done),
      // [41]: fatal
      // [42]: recov
      .alert_tx_o  ( alert_tx[42:41] ),
      .alert_rx_i  ( alert_rx[42:41] ),

      // Inter-module signals
      .otbn_otp_key_o(otp_ctrl_otbn_otp_key_req),
      .otbn_otp_key_i(otp_ctrl_otbn_otp_key_rsp),
      .edn_rnd_o(edn1_edn_req[0]),
      .edn_rnd_i(edn1_edn_rsp[0]),
      .edn_urnd_o(edn0_edn_req[6]),
      .edn_urnd_i(edn0_edn_rsp[6]),
      .idle_o(clkmgr_aon_idle[3]),
      .ram_cfg_i(ast_ram_1p_cfg),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_rma_req_i(lc_ctrl_lc_flash_rma_req),
      .lc_rma_ack_o(otbn_lc_rma_ack),
      .keymgr_key_i(keymgr_dpe_otbn_key),
      .tl_i(otbn_tl_req),
      .tl_o(otbn_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_otbn),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_secure),
      .clk_otp_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_otp_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  keymgr_dpe #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[44:43]),
    .UseOtpSeedsInsteadOfFlash(KeymgrDpeUseOtpSeedsInsteadOfFlash),
    .KmacEnMasking(KeymgrDpeKmacEnMasking),
    .RndCnstLfsrSeed(RndCnstKeymgrDpeLfsrSeed),
    .RndCnstLfsrPerm(RndCnstKeymgrDpeLfsrPerm),
    .RndCnstRandPerm(RndCnstKeymgrDpeRandPerm),
    .RndCnstRevisionSeed(RndCnstKeymgrDpeRevisionSeed),
    .RndCnstSoftOutputSeed(RndCnstKeymgrDpeSoftOutputSeed),
    .RndCnstHardOutputSeed(RndCnstKeymgrDpeHardOutputSeed),
    .RndCnstAesSeed(RndCnstKeymgrDpeAesSeed),
    .RndCnstKmacSeed(RndCnstKeymgrDpeKmacSeed),
    .RndCnstOtbnSeed(RndCnstKeymgrDpeOtbnSeed),
    .RndCnstNoneSeed(RndCnstKeymgrDpeNoneSeed)
  ) u_keymgr_dpe (

      // Interrupt
      .intr_op_done_o (intr_keymgr_dpe_op_done),
      // [43]: recov_operation_err
      // [44]: fatal_fault_err
      .alert_tx_o  ( alert_tx[44:43] ),
      .alert_rx_i  ( alert_rx[44:43] ),

      // Inter-module signals
      .edn_o(edn0_edn_req[0]),
      .edn_i(edn0_edn_rsp[0]),
      .aes_key_o(keymgr_dpe_aes_key),
      .kmac_key_o(keymgr_dpe_kmac_key),
      .otbn_key_o(keymgr_dpe_otbn_key),
      .kmac_data_o(kmac_app_req[0]),
      .kmac_data_i(kmac_app_rsp[0]),
      .otp_key_i(otp_ctrl_otp_keymgr_key),
      .otp_device_id_i(keymgr_dpe_otp_device_id),
      .flash_i(flash_ctrl_pkg::KEYMGR_FLASH_DEFAULT),
      .lc_keymgr_en_i(lc_ctrl_lc_keymgr_en),
      .lc_keymgr_div_i(lc_ctrl_lc_keymgr_div),
      .rom_digest_i(keymgr_dpe_rom_digest),
      .kmac_en_masking_i(kmac_en_masking),
      .tl_i(keymgr_dpe_tl_req),
      .tl_o(keymgr_dpe_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_secure),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_shadowed_ni (rstmgr_aon_resets.rst_lc_shadowed_n[rstmgr_pkg::Domain0Sel]),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  csrng #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[46:45]),
    .RndCnstCsKeymgrDivNonProduction(RndCnstCsrngCsKeymgrDivNonProduction),
    .RndCnstCsKeymgrDivProduction(RndCnstCsrngCsKeymgrDivProduction),
    .SBoxImpl(CsrngSBoxImpl)
  ) u_csrng (

      // Interrupt
      .intr_cs_cmd_req_done_o (intr_csrng_cs_cmd_req_done),
      .intr_cs_entropy_req_o  (intr_csrng_cs_entropy_req),
      .intr_cs_hw_inst_exc_o  (intr_csrng_cs_hw_inst_exc),
      .intr_cs_fatal_err_o    (intr_csrng_cs_fatal_err),
      // [45]: recov_alert
      // [46]: fatal_alert
      .alert_tx_o  ( alert_tx[46:45] ),
      .alert_rx_i  ( alert_rx[46:45] ),

      // Inter-module signals
      .csrng_cmd_i(csrng_csrng_cmd_req),
      .csrng_cmd_o(csrng_csrng_cmd_rsp),
      .entropy_src_hw_if_o(entropy_src_hw_if_req_o),
      .entropy_src_hw_if_i(entropy_src_hw_if_rsp_i),
      .cs_aes_halt_i(entropy_src_pkg::CS_AES_HALT_REQ_DEFAULT),
      .cs_aes_halt_o(),
      .otp_en_csrng_sw_app_read_i(prim_mubi_pkg::MuBi8True),
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .tl_i(csrng_tl_req),
      .tl_o(csrng_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  edn #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[48:47])
  ) u_edn0 (

      // Interrupt
      .intr_edn_cmd_req_done_o (intr_edn0_edn_cmd_req_done),
      .intr_edn_fatal_err_o    (intr_edn0_edn_fatal_err),
      // [47]: recov_alert
      // [48]: fatal_alert
      .alert_tx_o  ( alert_tx[48:47] ),
      .alert_rx_i  ( alert_rx[48:47] ),

      // Inter-module signals
      .csrng_cmd_o(csrng_csrng_cmd_req[0]),
      .csrng_cmd_i(csrng_csrng_cmd_rsp[0]),
      .edn_i(edn0_edn_req),
      .edn_o(edn0_edn_rsp),
      .tl_i(edn0_tl_req),
      .tl_o(edn0_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  edn #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[50:49])
  ) u_edn1 (

      // Interrupt
      .intr_edn_cmd_req_done_o (intr_edn1_edn_cmd_req_done),
      .intr_edn_fatal_err_o    (intr_edn1_edn_fatal_err),
      // [49]: recov_alert
      // [50]: fatal_alert
      .alert_tx_o  ( alert_tx[50:49] ),
      .alert_rx_i  ( alert_rx[50:49] ),

      // Inter-module signals
      .csrng_cmd_o(csrng_csrng_cmd_req[1]),
      .csrng_cmd_i(csrng_csrng_cmd_rsp[1]),
      .edn_i(edn1_edn_req),
      .edn_o(edn1_edn_rsp),
      .tl_i(edn1_tl_req),
      .tl_o(edn1_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  sram_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[51:51]),
    .RndCnstSramKey(RndCnstSramCtrlMainSramKey),
    .RndCnstSramNonce(RndCnstSramCtrlMainSramNonce),
    .RndCnstLfsrSeed(RndCnstSramCtrlMainLfsrSeed),
    .RndCnstLfsrPerm(RndCnstSramCtrlMainLfsrPerm),
    .MemSizeRam(65536),
    .InstrExec(SramCtrlMainInstrExec)
  ) u_sram_ctrl_main (
      // [51]: fatal_error
      .alert_tx_o  ( alert_tx[51:51] ),
      .alert_rx_i  ( alert_rx[51:51] ),

      // Inter-module signals
      .sram_otp_key_o(otp_ctrl_sram_otp_key_req[0]),
      .sram_otp_key_i(otp_ctrl_sram_otp_key_rsp[0]),
      .cfg_i(ast_ram_1p_cfg),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_hw_debug_en_i(lc_ctrl_lc_hw_debug_en),
      .otp_en_sram_ifetch_i(sram_ctrl_main_otp_en_sram_ifetch),
      .regs_tl_i(sram_ctrl_main_regs_tl_req),
      .regs_tl_o(sram_ctrl_main_regs_tl_rsp),
      .ram_tl_i(sram_ctrl_main_ram_tl_req),
      .ram_tl_o(sram_ctrl_main_ram_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .clk_otp_i (clkmgr_aon_clocks.clk_io_div4_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_otp_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  sram_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[52:52]),
    .RndCnstSramKey(RndCnstSramCtrlMboxSramKey),
    .RndCnstSramNonce(RndCnstSramCtrlMboxSramNonce),
    .RndCnstLfsrSeed(RndCnstSramCtrlMboxLfsrSeed),
    .RndCnstLfsrPerm(RndCnstSramCtrlMboxLfsrPerm),
    .MemSizeRam(4096),
    .InstrExec(SramCtrlMboxInstrExec)
  ) u_sram_ctrl_mbox (
      // [52]: fatal_error
      .alert_tx_o  ( alert_tx[52:52] ),
      .alert_rx_i  ( alert_rx[52:52] ),

      // Inter-module signals
      .sram_otp_key_o(otp_ctrl_sram_otp_key_req[2]),
      .sram_otp_key_i(otp_ctrl_sram_otp_key_rsp[2]),
      .cfg_i(ast_ram_1p_cfg),
      .lc_escalate_en_i(lc_ctrl_lc_escalate_en),
      .lc_hw_debug_en_i(lc_ctrl_pkg::Off),
      .otp_en_sram_ifetch_i(prim_mubi_pkg::MuBi8False),
      .regs_tl_i(sram_ctrl_mbox_regs_tl_req),
      .regs_tl_o(sram_ctrl_mbox_regs_tl_rsp),
      .ram_tl_i(sram_ctrl_mbox_ram_tl_req),
      .ram_tl_o(sram_ctrl_mbox_ram_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .clk_otp_i (clkmgr_aon_clocks.clk_io_div4_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_otp_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  rom_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[53:53]),
    .BootRomInitFile(RomCtrl0BootRomInitFile),
    .RndCnstScrNonce(RndCnstRomCtrl0ScrNonce),
    .RndCnstScrKey(RndCnstRomCtrl0ScrKey),
    .SecDisableScrambling(SecRomCtrl0DisableScrambling),
    .MemSizeRom(32768)
  ) u_rom_ctrl0 (
      // [53]: fatal
      .alert_tx_o  ( alert_tx[53:53] ),
      .alert_rx_i  ( alert_rx[53:53] ),

      // Inter-module signals
      .rom_cfg_i(ast_rom_cfg),
      .pwrmgr_data_o(pwrmgr_aon_rom_ctrl[0]),
      .keymgr_data_o(keymgr_dpe_rom_digest[0]),
      .kmac_data_o(kmac_app_req[2]),
      .kmac_data_i(kmac_app_rsp[2]),
      .regs_tl_i(rom_ctrl0_regs_tl_req),
      .regs_tl_o(rom_ctrl0_regs_tl_rsp),
      .rom_tl_i(rom_ctrl0_rom_tl_req),
      .rom_tl_o(rom_ctrl0_rom_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  rom_ctrl #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[54:54]),
    .BootRomInitFile(RomCtrl1BootRomInitFile),
    .RndCnstScrNonce(RndCnstRomCtrl1ScrNonce),
    .RndCnstScrKey(RndCnstRomCtrl1ScrKey),
    .SecDisableScrambling(SecRomCtrl1DisableScrambling),
    .MemSizeRom(65536)
  ) u_rom_ctrl1 (
      // [54]: fatal
      .alert_tx_o  ( alert_tx[54:54] ),
      .alert_rx_i  ( alert_rx[54:54] ),

      // Inter-module signals
      .rom_cfg_i(ast_rom_cfg),
      .pwrmgr_data_o(pwrmgr_aon_rom_ctrl[1]),
      .keymgr_data_o(keymgr_dpe_rom_digest[1]),
      .kmac_data_o(kmac_app_req[3]),
      .kmac_data_i(kmac_app_rsp[3]),
      .regs_tl_i(rom_ctrl1_regs_tl_req),
      .regs_tl_o(rom_ctrl1_regs_tl_rsp),
      .rom_tl_i(rom_ctrl1_rom_tl_req),
      .rom_tl_o(rom_ctrl1_rom_tl_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  dma #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[55:55]),
    .EnableDataIntgGen(DmaEnableDataIntgGen),
    .TlUserRsvd(DmaTlUserRsvd),
    .SysRacl(DmaSysRacl),
    .OtAgentId(DmaOtAgentId)
  ) u_dma (

      // Interrupt
      .intr_dma_done_o                (intr_dma_dma_done),
      .intr_dma_error_o               (intr_dma_dma_error),
      .intr_dma_memory_buffer_limit_o (intr_dma_dma_memory_buffer_limit),
      // [55]: fatal_fault
      .alert_tx_o  ( alert_tx[55:55] ),
      .alert_rx_i  ( alert_rx[55:55] ),

      // Inter-module signals
      .lsio_trigger_i(dma_lsio_trigger),
      .sys_o(dma_sys_req_o),
      .sys_i(dma_sys_rsp_i),
      .ctn_tl_h2d_o(dma_ctn_tl_h2d_o),
      .ctn_tl_d2h_i(dma_ctn_tl_d2h_i),
      .host_tl_h_o(main_tl_dma__host_req),
      .host_tl_h_i(main_tl_dma__host_rsp),
      .tl_d_i(dma_tl_d_req),
      .tl_d_o(dma_tl_d_rsp),
      .scanmode_i,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[57:56])
  ) u_mbx0 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx0_mbx_ready),
      .intr_mbx_abort_o (intr_mbx0_mbx_abort),
      // [56]: fatal_fault
      // [57]: recov_fault
      .alert_tx_o  ( alert_tx[57:56] ),
      .alert_rx_i  ( alert_rx[57:56] ),

      // Inter-module signals
      .doe_intr_support_o(mbx0_doe_intr_support_o),
      .doe_intr_en_o(mbx0_doe_intr_en_o),
      .doe_intr_o(mbx0_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx0__sram_req),
      .sram_tl_h_i(main_tl_mbx0__sram_rsp),
      .core_tl_d_i(mbx0_core_tl_d_req),
      .core_tl_d_o(mbx0_core_tl_d_rsp),
      .soc_tl_d_i(mbx0_soc_tl_d_req),
      .soc_tl_d_o(mbx0_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[59:58])
  ) u_mbx1 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx1_mbx_ready),
      .intr_mbx_abort_o (intr_mbx1_mbx_abort),
      // [58]: fatal_fault
      // [59]: recov_fault
      .alert_tx_o  ( alert_tx[59:58] ),
      .alert_rx_i  ( alert_rx[59:58] ),

      // Inter-module signals
      .doe_intr_support_o(mbx1_doe_intr_support_o),
      .doe_intr_en_o(mbx1_doe_intr_en_o),
      .doe_intr_o(mbx1_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx1__sram_req),
      .sram_tl_h_i(main_tl_mbx1__sram_rsp),
      .core_tl_d_i(mbx1_core_tl_d_req),
      .core_tl_d_o(mbx1_core_tl_d_rsp),
      .soc_tl_d_i(mbx1_soc_tl_d_req),
      .soc_tl_d_o(mbx1_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[61:60])
  ) u_mbx2 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx2_mbx_ready),
      .intr_mbx_abort_o (intr_mbx2_mbx_abort),
      // [60]: fatal_fault
      // [61]: recov_fault
      .alert_tx_o  ( alert_tx[61:60] ),
      .alert_rx_i  ( alert_rx[61:60] ),

      // Inter-module signals
      .doe_intr_support_o(mbx2_doe_intr_support_o),
      .doe_intr_en_o(mbx2_doe_intr_en_o),
      .doe_intr_o(mbx2_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx2__sram_req),
      .sram_tl_h_i(main_tl_mbx2__sram_rsp),
      .core_tl_d_i(mbx2_core_tl_d_req),
      .core_tl_d_o(mbx2_core_tl_d_rsp),
      .soc_tl_d_i(mbx2_soc_tl_d_req),
      .soc_tl_d_o(mbx2_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[63:62])
  ) u_mbx3 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx3_mbx_ready),
      .intr_mbx_abort_o (intr_mbx3_mbx_abort),
      // [62]: fatal_fault
      // [63]: recov_fault
      .alert_tx_o  ( alert_tx[63:62] ),
      .alert_rx_i  ( alert_rx[63:62] ),

      // Inter-module signals
      .doe_intr_support_o(mbx3_doe_intr_support_o),
      .doe_intr_en_o(mbx3_doe_intr_en_o),
      .doe_intr_o(mbx3_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx3__sram_req),
      .sram_tl_h_i(main_tl_mbx3__sram_rsp),
      .core_tl_d_i(mbx3_core_tl_d_req),
      .core_tl_d_o(mbx3_core_tl_d_rsp),
      .soc_tl_d_i(mbx3_soc_tl_d_req),
      .soc_tl_d_o(mbx3_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[65:64])
  ) u_mbx4 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx4_mbx_ready),
      .intr_mbx_abort_o (intr_mbx4_mbx_abort),
      // [64]: fatal_fault
      // [65]: recov_fault
      .alert_tx_o  ( alert_tx[65:64] ),
      .alert_rx_i  ( alert_rx[65:64] ),

      // Inter-module signals
      .doe_intr_support_o(mbx4_doe_intr_support_o),
      .doe_intr_en_o(mbx4_doe_intr_en_o),
      .doe_intr_o(mbx4_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx4__sram_req),
      .sram_tl_h_i(main_tl_mbx4__sram_rsp),
      .core_tl_d_i(mbx4_core_tl_d_req),
      .core_tl_d_o(mbx4_core_tl_d_rsp),
      .soc_tl_d_i(mbx4_soc_tl_d_req),
      .soc_tl_d_o(mbx4_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[67:66])
  ) u_mbx5 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx5_mbx_ready),
      .intr_mbx_abort_o (intr_mbx5_mbx_abort),
      // [66]: fatal_fault
      // [67]: recov_fault
      .alert_tx_o  ( alert_tx[67:66] ),
      .alert_rx_i  ( alert_rx[67:66] ),

      // Inter-module signals
      .doe_intr_support_o(mbx5_doe_intr_support_o),
      .doe_intr_en_o(mbx5_doe_intr_en_o),
      .doe_intr_o(mbx5_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx5__sram_req),
      .sram_tl_h_i(main_tl_mbx5__sram_rsp),
      .core_tl_d_i(mbx5_core_tl_d_req),
      .core_tl_d_o(mbx5_core_tl_d_rsp),
      .soc_tl_d_i(mbx5_soc_tl_d_req),
      .soc_tl_d_o(mbx5_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[69:68])
  ) u_mbx6 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx6_mbx_ready),
      .intr_mbx_abort_o (intr_mbx6_mbx_abort),
      // [68]: fatal_fault
      // [69]: recov_fault
      .alert_tx_o  ( alert_tx[69:68] ),
      .alert_rx_i  ( alert_rx[69:68] ),

      // Inter-module signals
      .doe_intr_support_o(mbx6_doe_intr_support_o),
      .doe_intr_en_o(mbx6_doe_intr_en_o),
      .doe_intr_o(mbx6_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx6__sram_req),
      .sram_tl_h_i(main_tl_mbx6__sram_rsp),
      .core_tl_d_i(mbx6_core_tl_d_req),
      .core_tl_d_o(mbx6_core_tl_d_rsp),
      .soc_tl_d_i(mbx6_soc_tl_d_req),
      .soc_tl_d_o(mbx6_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[71:70])
  ) u_mbx_jtag (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx_jtag_mbx_ready),
      .intr_mbx_abort_o (intr_mbx_jtag_mbx_abort),
      // [70]: fatal_fault
      // [71]: recov_fault
      .alert_tx_o  ( alert_tx[71:70] ),
      .alert_rx_i  ( alert_rx[71:70] ),

      // Inter-module signals
      .doe_intr_support_o(mbx_jtag_doe_intr_support_o),
      .doe_intr_en_o(mbx_jtag_doe_intr_en_o),
      .doe_intr_o(mbx_jtag_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx_jtag__sram_req),
      .sram_tl_h_i(main_tl_mbx_jtag__sram_rsp),
      .core_tl_d_i(mbx_jtag_core_tl_d_req),
      .core_tl_d_o(mbx_jtag_core_tl_d_rsp),
      .soc_tl_d_i(mbx_jtag_soc_tl_d_req),
      .soc_tl_d_o(mbx_jtag_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[73:72])
  ) u_mbx_pcie0 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx_pcie0_mbx_ready),
      .intr_mbx_abort_o (intr_mbx_pcie0_mbx_abort),
      // [72]: fatal_fault
      // [73]: recov_fault
      .alert_tx_o  ( alert_tx[73:72] ),
      .alert_rx_i  ( alert_rx[73:72] ),

      // Inter-module signals
      .doe_intr_support_o(mbx_pcie0_doe_intr_support_o),
      .doe_intr_en_o(mbx_pcie0_doe_intr_en_o),
      .doe_intr_o(mbx_pcie0_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx_pcie0__sram_req),
      .sram_tl_h_i(main_tl_mbx_pcie0__sram_rsp),
      .core_tl_d_i(mbx_pcie0_core_tl_d_req),
      .core_tl_d_o(mbx_pcie0_core_tl_d_rsp),
      .soc_tl_d_i(mbx_pcie0_soc_tl_d_req),
      .soc_tl_d_o(mbx_pcie0_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  mbx #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[75:74])
  ) u_mbx_pcie1 (

      // Interrupt
      .intr_mbx_ready_o (intr_mbx_pcie1_mbx_ready),
      .intr_mbx_abort_o (intr_mbx_pcie1_mbx_abort),
      // [74]: fatal_fault
      // [75]: recov_fault
      .alert_tx_o  ( alert_tx[75:74] ),
      .alert_rx_i  ( alert_rx[75:74] ),

      // Inter-module signals
      .doe_intr_support_o(mbx_pcie1_doe_intr_support_o),
      .doe_intr_en_o(mbx_pcie1_doe_intr_en_o),
      .doe_intr_o(mbx_pcie1_doe_intr_o),
      .sram_tl_h_o(main_tl_mbx_pcie1__sram_req),
      .sram_tl_h_i(main_tl_mbx_pcie1__sram_rsp),
      .core_tl_d_i(mbx_pcie1_core_tl_d_req),
      .core_tl_d_o(mbx_pcie1_core_tl_d_rsp),
      .soc_tl_d_i(mbx_pcie1_soc_tl_d_req),
      .soc_tl_d_o(mbx_pcie1_soc_tl_d_rsp),

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel])
  );
  rv_core_ibex #(
    .AlertAsyncOn(alert_handler_reg_pkg::AsyncOn[79:76]),
    .RndCnstLfsrSeed(RndCnstRvCoreIbexLfsrSeed),
    .RndCnstLfsrPerm(RndCnstRvCoreIbexLfsrPerm),
    .RndCnstIbexKeyDefault(RndCnstRvCoreIbexIbexKeyDefault),
    .RndCnstIbexNonceDefault(RndCnstRvCoreIbexIbexNonceDefault),
    .PMPEnable(RvCoreIbexPMPEnable),
    .PMPGranularity(RvCoreIbexPMPGranularity),
    .PMPNumRegions(RvCoreIbexPMPNumRegions),
    .MHPMCounterNum(RvCoreIbexMHPMCounterNum),
    .MHPMCounterWidth(RvCoreIbexMHPMCounterWidth),
    .RV32E(RvCoreIbexRV32E),
    .RV32M(RvCoreIbexRV32M),
    .RV32B(RvCoreIbexRV32B),
    .RegFile(RvCoreIbexRegFile),
    .BranchTargetALU(RvCoreIbexBranchTargetALU),
    .WritebackStage(RvCoreIbexWritebackStage),
    .ICache(RvCoreIbexICache),
    .ICacheECC(RvCoreIbexICacheECC),
    .ICacheScramble(RvCoreIbexICacheScramble),
    .BranchPredictor(RvCoreIbexBranchPredictor),
    .DbgTriggerEn(RvCoreIbexDbgTriggerEn),
    .DbgHwBreakNum(RvCoreIbexDbgHwBreakNum),
    .SecureIbex(RvCoreIbexSecureIbex),
    .DmHaltAddr(RvCoreIbexDmHaltAddr),
    .DmExceptionAddr(RvCoreIbexDmExceptionAddr),
    .PipeLine(RvCoreIbexPipeLine)
  ) u_rv_core_ibex (
      // [76]: fatal_sw_err
      // [77]: recov_sw_err
      // [78]: fatal_hw_err
      // [79]: recov_hw_err
      .alert_tx_o  ( alert_tx[79:76] ),
      .alert_rx_i  ( alert_rx[79:76] ),

      // Inter-module signals
      .rst_cpu_n_o(),
      .ram_cfg_i(ast_ram_1p_cfg),
      .hart_id_i(rv_core_ibex_hart_id),
      .boot_addr_i(rv_core_ibex_boot_addr),
      .irq_software_i(rv_plic_msip),
      .irq_timer_i(rv_core_ibex_irq_timer),
      .irq_external_i(rv_plic_irq),
      .esc_tx_i(alert_handler_esc_tx[0]),
      .esc_rx_o(alert_handler_esc_rx[0]),
      .debug_req_i(rv_dm_debug_req),
      .crash_dump_o(rv_core_ibex_crash_dump),
      .lc_cpu_en_i(lc_ctrl_lc_cpu_en),
      .pwrmgr_cpu_en_i(pwrmgr_aon_fetch_en),
      .pwrmgr_o(rv_core_ibex_pwrmgr),
      .nmi_wdog_i(aon_timer_aon_nmi_wdog_timer_bark),
      .edn_o(edn0_edn_req[7]),
      .edn_i(edn0_edn_rsp[7]),
      .icache_otp_key_o(otp_ctrl_sram_otp_key_req[3]),
      .icache_otp_key_i(otp_ctrl_sram_otp_key_rsp[3]),
      .fpga_info_i(fpga_info_i),
      .corei_tl_h_o(main_tl_rv_core_ibex__corei_req),
      .corei_tl_h_i(main_tl_rv_core_ibex__corei_rsp),
      .cored_tl_h_o(main_tl_rv_core_ibex__cored_req),
      .cored_tl_h_i(main_tl_rv_core_ibex__cored_rsp),
      .cfg_tl_d_i(rv_core_ibex_cfg_tl_d_req),
      .cfg_tl_d_o(rv_core_ibex_cfg_tl_d_rsp),
      .scanmode_i,
      .scan_rst_ni,

      // Clock and reset connections
      .clk_i (clkmgr_aon_clocks.clk_main_infra),
      .clk_edn_i (clkmgr_aon_clocks.clk_main_infra),
      .clk_esc_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .clk_otp_i (clkmgr_aon_clocks.clk_io_div4_secure),
      .rst_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_edn_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
      .rst_esc_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),
      .rst_otp_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel])
  );
  // interrupt assignments
  assign intr_vector = {
      intr_mbx_pcie1_mbx_abort, // IDs [129 +: 1]
      intr_mbx_pcie1_mbx_ready, // IDs [128 +: 1]
      intr_mbx_pcie0_mbx_abort, // IDs [127 +: 1]
      intr_mbx_pcie0_mbx_ready, // IDs [126 +: 1]
      intr_mbx_jtag_mbx_abort, // IDs [125 +: 1]
      intr_mbx_jtag_mbx_ready, // IDs [124 +: 1]
      intr_mbx6_mbx_abort, // IDs [123 +: 1]
      intr_mbx6_mbx_ready, // IDs [122 +: 1]
      intr_mbx5_mbx_abort, // IDs [121 +: 1]
      intr_mbx5_mbx_ready, // IDs [120 +: 1]
      intr_mbx4_mbx_abort, // IDs [119 +: 1]
      intr_mbx4_mbx_ready, // IDs [118 +: 1]
      intr_mbx3_mbx_abort, // IDs [117 +: 1]
      intr_mbx3_mbx_ready, // IDs [116 +: 1]
      intr_mbx2_mbx_abort, // IDs [115 +: 1]
      intr_mbx2_mbx_ready, // IDs [114 +: 1]
      intr_mbx1_mbx_abort, // IDs [113 +: 1]
      intr_mbx1_mbx_ready, // IDs [112 +: 1]
      intr_mbx0_mbx_abort, // IDs [111 +: 1]
      intr_mbx0_mbx_ready, // IDs [110 +: 1]
      intr_dma_dma_memory_buffer_limit, // IDs [109 +: 1]
      intr_dma_dma_error, // IDs [108 +: 1]
      intr_dma_dma_done, // IDs [107 +: 1]
      intr_edn1_edn_fatal_err, // IDs [106 +: 1]
      intr_edn1_edn_cmd_req_done, // IDs [105 +: 1]
      intr_edn0_edn_fatal_err, // IDs [104 +: 1]
      intr_edn0_edn_cmd_req_done, // IDs [103 +: 1]
      intr_csrng_cs_fatal_err, // IDs [102 +: 1]
      intr_csrng_cs_hw_inst_exc, // IDs [101 +: 1]
      intr_csrng_cs_entropy_req, // IDs [100 +: 1]
      intr_csrng_cs_cmd_req_done, // IDs [99 +: 1]
      intr_keymgr_dpe_op_done, // IDs [98 +: 1]
      intr_otbn_done, // IDs [97 +: 1]
      intr_kmac_kmac_err, // IDs [96 +: 1]
      intr_kmac_fifo_empty, // IDs [95 +: 1]
      intr_kmac_kmac_done, // IDs [94 +: 1]
      intr_hmac_hmac_err, // IDs [93 +: 1]
      intr_hmac_fifo_empty, // IDs [92 +: 1]
      intr_hmac_hmac_done, // IDs [91 +: 1]
      intr_soc_proxy_external, // IDs [83 +: 8]
      intr_sensor_ctrl_init_status_change, // IDs [82 +: 1]
      intr_sensor_ctrl_io_status_change, // IDs [81 +: 1]
      intr_aon_timer_aon_wdog_timer_bark, // IDs [80 +: 1]
      intr_aon_timer_aon_wkup_timer_expired, // IDs [79 +: 1]
      intr_adc_ctrl_aon_match_done, // IDs [78 +: 1]
      intr_pwrmgr_aon_wakeup, // IDs [77 +: 1]
      intr_spi_host0_spi_event, // IDs [76 +: 1]
      intr_spi_host0_error, // IDs [75 +: 1]
      intr_alert_handler_classd, // IDs [74 +: 1]
      intr_alert_handler_classc, // IDs [73 +: 1]
      intr_alert_handler_classb, // IDs [72 +: 1]
      intr_alert_handler_classa, // IDs [71 +: 1]
      intr_otp_ctrl_otp_error, // IDs [70 +: 1]
      intr_otp_ctrl_otp_operation_done, // IDs [69 +: 1]
      intr_rv_timer_timer_expired_hart0_timer0, // IDs [68 +: 1]
      intr_i2c0_host_timeout, // IDs [67 +: 1]
      intr_i2c0_unexp_stop, // IDs [66 +: 1]
      intr_i2c0_acq_full, // IDs [65 +: 1]
      intr_i2c0_tx_overflow, // IDs [64 +: 1]
      intr_i2c0_tx_stretch, // IDs [63 +: 1]
      intr_i2c0_cmd_complete, // IDs [62 +: 1]
      intr_i2c0_sda_unstable, // IDs [61 +: 1]
      intr_i2c0_stretch_timeout, // IDs [60 +: 1]
      intr_i2c0_sda_interference, // IDs [59 +: 1]
      intr_i2c0_scl_interference, // IDs [58 +: 1]
      intr_i2c0_nak, // IDs [57 +: 1]
      intr_i2c0_rx_overflow, // IDs [56 +: 1]
      intr_i2c0_fmt_overflow, // IDs [55 +: 1]
      intr_i2c0_rx_threshold, // IDs [54 +: 1]
      intr_i2c0_fmt_threshold, // IDs [53 +: 1]
      intr_spi_device_tpm_header_not_empty, // IDs [52 +: 1]
      intr_spi_device_readbuf_flip, // IDs [51 +: 1]
      intr_spi_device_readbuf_watermark, // IDs [50 +: 1]
      intr_spi_device_upload_payload_overflow, // IDs [49 +: 1]
      intr_spi_device_upload_payload_not_empty, // IDs [48 +: 1]
      intr_spi_device_upload_cmdfifo_not_empty, // IDs [47 +: 1]
      intr_spi_device_generic_tx_underflow, // IDs [46 +: 1]
      intr_spi_device_generic_rx_overflow, // IDs [45 +: 1]
      intr_spi_device_generic_rx_error, // IDs [44 +: 1]
      intr_spi_device_generic_tx_watermark, // IDs [43 +: 1]
      intr_spi_device_generic_rx_watermark, // IDs [42 +: 1]
      intr_spi_device_generic_rx_full, // IDs [41 +: 1]
      intr_gpio_gpio, // IDs [9 +: 32]
      intr_uart0_rx_parity_err, // IDs [8 +: 1]
      intr_uart0_rx_timeout, // IDs [7 +: 1]
      intr_uart0_rx_break_err, // IDs [6 +: 1]
      intr_uart0_rx_frame_err, // IDs [5 +: 1]
      intr_uart0_rx_overflow, // IDs [4 +: 1]
      intr_uart0_tx_empty, // IDs [3 +: 1]
      intr_uart0_rx_watermark, // IDs [2 +: 1]
      intr_uart0_tx_watermark, // IDs [1 +: 1]
      1'b 0 // ID [0 +: 1] is a special case and tied to zero.
  };

  // TL-UL Crossbar
  xbar_main u_xbar_main (
    .clk_main_i (clkmgr_aon_clocks.clk_main_infra),
    .clk_fixed_i (clkmgr_aon_clocks.clk_io_div4_infra),
    .clk_usb_i (clkmgr_aon_clocks.clk_usb_infra),
    .rst_main_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),
    .rst_fixed_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),
    .rst_usb_ni (rstmgr_aon_resets.rst_lc_usb_n[rstmgr_pkg::Domain0Sel]),

    // port: tl_rv_core_ibex__corei
    .tl_rv_core_ibex__corei_i(main_tl_rv_core_ibex__corei_req),
    .tl_rv_core_ibex__corei_o(main_tl_rv_core_ibex__corei_rsp),

    // port: tl_rv_core_ibex__cored
    .tl_rv_core_ibex__cored_i(main_tl_rv_core_ibex__cored_req),
    .tl_rv_core_ibex__cored_o(main_tl_rv_core_ibex__cored_rsp),

    // port: tl_rv_dm__sba
    .tl_rv_dm__sba_i(main_tl_rv_dm__sba_req),
    .tl_rv_dm__sba_o(main_tl_rv_dm__sba_rsp),

    // port: tl_dma__host
    .tl_dma__host_i(main_tl_dma__host_req),
    .tl_dma__host_o(main_tl_dma__host_rsp),

    // port: tl_mbx0__sram
    .tl_mbx0__sram_i(main_tl_mbx0__sram_req),
    .tl_mbx0__sram_o(main_tl_mbx0__sram_rsp),

    // port: tl_mbx1__sram
    .tl_mbx1__sram_i(main_tl_mbx1__sram_req),
    .tl_mbx1__sram_o(main_tl_mbx1__sram_rsp),

    // port: tl_mbx2__sram
    .tl_mbx2__sram_i(main_tl_mbx2__sram_req),
    .tl_mbx2__sram_o(main_tl_mbx2__sram_rsp),

    // port: tl_mbx3__sram
    .tl_mbx3__sram_i(main_tl_mbx3__sram_req),
    .tl_mbx3__sram_o(main_tl_mbx3__sram_rsp),

    // port: tl_mbx4__sram
    .tl_mbx4__sram_i(main_tl_mbx4__sram_req),
    .tl_mbx4__sram_o(main_tl_mbx4__sram_rsp),

    // port: tl_mbx5__sram
    .tl_mbx5__sram_i(main_tl_mbx5__sram_req),
    .tl_mbx5__sram_o(main_tl_mbx5__sram_rsp),

    // port: tl_mbx6__sram
    .tl_mbx6__sram_i(main_tl_mbx6__sram_req),
    .tl_mbx6__sram_o(main_tl_mbx6__sram_rsp),

    // port: tl_mbx_jtag__sram
    .tl_mbx_jtag__sram_i(main_tl_mbx_jtag__sram_req),
    .tl_mbx_jtag__sram_o(main_tl_mbx_jtag__sram_rsp),

    // port: tl_mbx_pcie0__sram
    .tl_mbx_pcie0__sram_i(main_tl_mbx_pcie0__sram_req),
    .tl_mbx_pcie0__sram_o(main_tl_mbx_pcie0__sram_rsp),

    // port: tl_mbx_pcie1__sram
    .tl_mbx_pcie1__sram_i(main_tl_mbx_pcie1__sram_req),
    .tl_mbx_pcie1__sram_o(main_tl_mbx_pcie1__sram_rsp),

    // port: tl_rv_dm__regs
    .tl_rv_dm__regs_o(rv_dm_regs_tl_d_req),
    .tl_rv_dm__regs_i(rv_dm_regs_tl_d_rsp),

    // port: tl_rv_dm__mem
    .tl_rv_dm__mem_o(rv_dm_mem_tl_d_req),
    .tl_rv_dm__mem_i(rv_dm_mem_tl_d_rsp),

    // port: tl_rom_ctrl0__rom
    .tl_rom_ctrl0__rom_o(rom_ctrl0_rom_tl_req),
    .tl_rom_ctrl0__rom_i(rom_ctrl0_rom_tl_rsp),

    // port: tl_rom_ctrl0__regs
    .tl_rom_ctrl0__regs_o(rom_ctrl0_regs_tl_req),
    .tl_rom_ctrl0__regs_i(rom_ctrl0_regs_tl_rsp),

    // port: tl_rom_ctrl1__rom
    .tl_rom_ctrl1__rom_o(rom_ctrl1_rom_tl_req),
    .tl_rom_ctrl1__rom_i(rom_ctrl1_rom_tl_rsp),

    // port: tl_rom_ctrl1__regs
    .tl_rom_ctrl1__regs_o(rom_ctrl1_regs_tl_req),
    .tl_rom_ctrl1__regs_i(rom_ctrl1_regs_tl_rsp),

    // port: tl_peri
    .tl_peri_o(main_tl_peri_req),
    .tl_peri_i(main_tl_peri_rsp),

    // port: tl_soc_proxy__core
    .tl_soc_proxy__core_o(soc_proxy_core_tl_req),
    .tl_soc_proxy__core_i(soc_proxy_core_tl_rsp),

    // port: tl_soc_proxy__ctn
    .tl_soc_proxy__ctn_o(soc_proxy_ctn_tl_req),
    .tl_soc_proxy__ctn_i(soc_proxy_ctn_tl_rsp),

    // port: tl_hmac
    .tl_hmac_o(hmac_tl_req),
    .tl_hmac_i(hmac_tl_rsp),

    // port: tl_kmac
    .tl_kmac_o(kmac_tl_req),
    .tl_kmac_i(kmac_tl_rsp),

    // port: tl_aes
    .tl_aes_o(aes_tl_req),
    .tl_aes_i(aes_tl_rsp),

    // port: tl_csrng
    .tl_csrng_o(csrng_tl_req),
    .tl_csrng_i(csrng_tl_rsp),

    // port: tl_edn0
    .tl_edn0_o(edn0_tl_req),
    .tl_edn0_i(edn0_tl_rsp),

    // port: tl_edn1
    .tl_edn1_o(edn1_tl_req),
    .tl_edn1_i(edn1_tl_rsp),

    // port: tl_rv_plic
    .tl_rv_plic_o(rv_plic_tl_req),
    .tl_rv_plic_i(rv_plic_tl_rsp),

    // port: tl_otbn
    .tl_otbn_o(otbn_tl_req),
    .tl_otbn_i(otbn_tl_rsp),

    // port: tl_keymgr_dpe
    .tl_keymgr_dpe_o(keymgr_dpe_tl_req),
    .tl_keymgr_dpe_i(keymgr_dpe_tl_rsp),

    // port: tl_rv_core_ibex__cfg
    .tl_rv_core_ibex__cfg_o(rv_core_ibex_cfg_tl_d_req),
    .tl_rv_core_ibex__cfg_i(rv_core_ibex_cfg_tl_d_rsp),

    // port: tl_sram_ctrl_main__regs
    .tl_sram_ctrl_main__regs_o(sram_ctrl_main_regs_tl_req),
    .tl_sram_ctrl_main__regs_i(sram_ctrl_main_regs_tl_rsp),

    // port: tl_sram_ctrl_main__ram
    .tl_sram_ctrl_main__ram_o(sram_ctrl_main_ram_tl_req),
    .tl_sram_ctrl_main__ram_i(sram_ctrl_main_ram_tl_rsp),

    // port: tl_sram_ctrl_mbox__regs
    .tl_sram_ctrl_mbox__regs_o(sram_ctrl_mbox_regs_tl_req),
    .tl_sram_ctrl_mbox__regs_i(sram_ctrl_mbox_regs_tl_rsp),

    // port: tl_sram_ctrl_mbox__ram
    .tl_sram_ctrl_mbox__ram_o(sram_ctrl_mbox_ram_tl_req),
    .tl_sram_ctrl_mbox__ram_i(sram_ctrl_mbox_ram_tl_rsp),

    // port: tl_dma
    .tl_dma_o(dma_tl_d_req),
    .tl_dma_i(dma_tl_d_rsp),

    // port: tl_mbx0__core
    .tl_mbx0__core_o(mbx0_core_tl_d_req),
    .tl_mbx0__core_i(mbx0_core_tl_d_rsp),

    // port: tl_mbx1__core
    .tl_mbx1__core_o(mbx1_core_tl_d_req),
    .tl_mbx1__core_i(mbx1_core_tl_d_rsp),

    // port: tl_mbx2__core
    .tl_mbx2__core_o(mbx2_core_tl_d_req),
    .tl_mbx2__core_i(mbx2_core_tl_d_rsp),

    // port: tl_mbx3__core
    .tl_mbx3__core_o(mbx3_core_tl_d_req),
    .tl_mbx3__core_i(mbx3_core_tl_d_rsp),

    // port: tl_mbx4__core
    .tl_mbx4__core_o(mbx4_core_tl_d_req),
    .tl_mbx4__core_i(mbx4_core_tl_d_rsp),

    // port: tl_mbx5__core
    .tl_mbx5__core_o(mbx5_core_tl_d_req),
    .tl_mbx5__core_i(mbx5_core_tl_d_rsp),

    // port: tl_mbx6__core
    .tl_mbx6__core_o(mbx6_core_tl_d_req),
    .tl_mbx6__core_i(mbx6_core_tl_d_rsp),

    // port: tl_mbx_jtag__core
    .tl_mbx_jtag__core_o(mbx_jtag_core_tl_d_req),
    .tl_mbx_jtag__core_i(mbx_jtag_core_tl_d_rsp),

    // port: tl_mbx_pcie0__core
    .tl_mbx_pcie0__core_o(mbx_pcie0_core_tl_d_req),
    .tl_mbx_pcie0__core_i(mbx_pcie0_core_tl_d_rsp),

    // port: tl_mbx_pcie1__core
    .tl_mbx_pcie1__core_o(mbx_pcie1_core_tl_d_req),
    .tl_mbx_pcie1__core_i(mbx_pcie1_core_tl_d_rsp),


    .scanmode_i
  );
  xbar_peri u_xbar_peri (
    .clk_peri_i (clkmgr_aon_clocks.clk_io_div4_infra),
    .rst_peri_ni (rstmgr_aon_resets.rst_lc_io_div4_n[rstmgr_pkg::Domain0Sel]),

    // port: tl_main
    .tl_main_i(main_tl_peri_req),
    .tl_main_o(main_tl_peri_rsp),

    // port: tl_uart0
    .tl_uart0_o(uart0_tl_req),
    .tl_uart0_i(uart0_tl_rsp),

    // port: tl_i2c0
    .tl_i2c0_o(i2c0_tl_req),
    .tl_i2c0_i(i2c0_tl_rsp),

    // port: tl_gpio
    .tl_gpio_o(gpio_tl_req),
    .tl_gpio_i(gpio_tl_rsp),

    // port: tl_spi_host0
    .tl_spi_host0_o(spi_host0_tl_req),
    .tl_spi_host0_i(spi_host0_tl_rsp),

    // port: tl_spi_device
    .tl_spi_device_o(spi_device_tl_req),
    .tl_spi_device_i(spi_device_tl_rsp),

    // port: tl_rv_timer
    .tl_rv_timer_o(rv_timer_tl_req),
    .tl_rv_timer_i(rv_timer_tl_rsp),

    // port: tl_pwrmgr_aon
    .tl_pwrmgr_aon_o(pwrmgr_aon_tl_req),
    .tl_pwrmgr_aon_i(pwrmgr_aon_tl_rsp),

    // port: tl_rstmgr_aon
    .tl_rstmgr_aon_o(rstmgr_aon_tl_req),
    .tl_rstmgr_aon_i(rstmgr_aon_tl_rsp),

    // port: tl_clkmgr_aon
    .tl_clkmgr_aon_o(clkmgr_aon_tl_req),
    .tl_clkmgr_aon_i(clkmgr_aon_tl_rsp),

    // port: tl_pinmux_aon
    .tl_pinmux_aon_o(pinmux_aon_tl_req),
    .tl_pinmux_aon_i(pinmux_aon_tl_rsp),

    // port: tl_otp_ctrl__core
    .tl_otp_ctrl__core_o(otp_ctrl_core_tl_req),
    .tl_otp_ctrl__core_i(otp_ctrl_core_tl_rsp),

    // port: tl_otp_ctrl__prim
    .tl_otp_ctrl__prim_o(otp_ctrl_prim_tl_req),
    .tl_otp_ctrl__prim_i(otp_ctrl_prim_tl_rsp),

    // port: tl_lc_ctrl
    .tl_lc_ctrl_o(lc_ctrl_tl_req),
    .tl_lc_ctrl_i(lc_ctrl_tl_rsp),

    // port: tl_sensor_ctrl
    .tl_sensor_ctrl_o(sensor_ctrl_tl_req),
    .tl_sensor_ctrl_i(sensor_ctrl_tl_rsp),

    // port: tl_alert_handler
    .tl_alert_handler_o(alert_handler_tl_req),
    .tl_alert_handler_i(alert_handler_tl_rsp),

    // port: tl_sram_ctrl_ret_aon__regs
    .tl_sram_ctrl_ret_aon__regs_o(sram_ctrl_ret_aon_regs_tl_req),
    .tl_sram_ctrl_ret_aon__regs_i(sram_ctrl_ret_aon_regs_tl_rsp),

    // port: tl_sram_ctrl_ret_aon__ram
    .tl_sram_ctrl_ret_aon__ram_o(sram_ctrl_ret_aon_ram_tl_req),
    .tl_sram_ctrl_ret_aon__ram_i(sram_ctrl_ret_aon_ram_tl_rsp),

    // port: tl_aon_timer_aon
    .tl_aon_timer_aon_o(aon_timer_aon_tl_req),
    .tl_aon_timer_aon_i(aon_timer_aon_tl_rsp),

    // port: tl_adc_ctrl_aon
    .tl_adc_ctrl_aon_o(adc_ctrl_aon_tl_req),
    .tl_adc_ctrl_aon_i(adc_ctrl_aon_tl_rsp),

    // port: tl_ast
    .tl_ast_o(ast_tl_req_o),
    .tl_ast_i(ast_tl_rsp_i),


    .scanmode_i
  );
  xbar_mbx u_xbar_mbx (
    .clk_mbx_i (clkmgr_aon_clocks.clk_main_infra),
    .rst_mbx_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),

    // port: tl_mbx
    .tl_mbx_i(mbx_tl_req_i),
    .tl_mbx_o(mbx_tl_rsp_o),

    // port: tl_mbx0__soc
    .tl_mbx0__soc_o(mbx0_soc_tl_d_req),
    .tl_mbx0__soc_i(mbx0_soc_tl_d_rsp),

    // port: tl_mbx1__soc
    .tl_mbx1__soc_o(mbx1_soc_tl_d_req),
    .tl_mbx1__soc_i(mbx1_soc_tl_d_rsp),

    // port: tl_mbx2__soc
    .tl_mbx2__soc_o(mbx2_soc_tl_d_req),
    .tl_mbx2__soc_i(mbx2_soc_tl_d_rsp),

    // port: tl_mbx3__soc
    .tl_mbx3__soc_o(mbx3_soc_tl_d_req),
    .tl_mbx3__soc_i(mbx3_soc_tl_d_rsp),

    // port: tl_mbx4__soc
    .tl_mbx4__soc_o(mbx4_soc_tl_d_req),
    .tl_mbx4__soc_i(mbx4_soc_tl_d_rsp),

    // port: tl_mbx5__soc
    .tl_mbx5__soc_o(mbx5_soc_tl_d_req),
    .tl_mbx5__soc_i(mbx5_soc_tl_d_rsp),

    // port: tl_mbx6__soc
    .tl_mbx6__soc_o(mbx6_soc_tl_d_req),
    .tl_mbx6__soc_i(mbx6_soc_tl_d_rsp),

    // port: tl_mbx_pcie0__soc
    .tl_mbx_pcie0__soc_o(mbx_pcie0_soc_tl_d_req),
    .tl_mbx_pcie0__soc_i(mbx_pcie0_soc_tl_d_rsp),

    // port: tl_mbx_pcie1__soc
    .tl_mbx_pcie1__soc_o(mbx_pcie1_soc_tl_d_req),
    .tl_mbx_pcie1__soc_i(mbx_pcie1_soc_tl_d_rsp),


    .scanmode_i
  );
  xbar_dbg u_xbar_dbg (
    .clk_dbg_i (clkmgr_aon_clocks.clk_main_infra),
    .rst_dbg_ni (rstmgr_aon_resets.rst_lc_n[rstmgr_pkg::Domain0Sel]),

    // port: tl_dbg
    .tl_dbg_i(mbx_jtag_dmi_req_i),
    .tl_dbg_o(mbx_jtag_dmi_rsp_o),

    // port: tl_mbx_jtag__soc
    .tl_mbx_jtag__soc_o(mbx_jtag_soc_tl_d_req),
    .tl_mbx_jtag__soc_i(mbx_jtag_soc_tl_d_rsp),


    .scanmode_i
  );

  // Pinmux connections
  // All muxed inputs
  assign cio_gpio_gpio_p2d[0] = mio_p2d[MioInGpioGpio0];
  assign cio_gpio_gpio_p2d[1] = mio_p2d[MioInGpioGpio1];
  assign cio_gpio_gpio_p2d[2] = mio_p2d[MioInGpioGpio2];
  assign cio_gpio_gpio_p2d[3] = mio_p2d[MioInGpioGpio3];
  assign cio_gpio_gpio_p2d[4] = mio_p2d[MioInGpioGpio4];
  assign cio_gpio_gpio_p2d[5] = mio_p2d[MioInGpioGpio5];
  assign cio_gpio_gpio_p2d[6] = mio_p2d[MioInGpioGpio6];
  assign cio_gpio_gpio_p2d[7] = mio_p2d[MioInGpioGpio7];
  assign cio_gpio_gpio_p2d[8] = mio_p2d[MioInGpioGpio8];
  assign cio_gpio_gpio_p2d[9] = mio_p2d[MioInGpioGpio9];
  assign cio_gpio_gpio_p2d[10] = mio_p2d[MioInGpioGpio10];
  assign cio_gpio_gpio_p2d[11] = mio_p2d[MioInGpioGpio11];
  assign cio_gpio_gpio_p2d[12] = mio_p2d[MioInGpioGpio12];
  assign cio_gpio_gpio_p2d[13] = mio_p2d[MioInGpioGpio13];
  assign cio_gpio_gpio_p2d[14] = mio_p2d[MioInGpioGpio14];
  assign cio_gpio_gpio_p2d[15] = mio_p2d[MioInGpioGpio15];
  assign cio_gpio_gpio_p2d[16] = mio_p2d[MioInGpioGpio16];
  assign cio_gpio_gpio_p2d[17] = mio_p2d[MioInGpioGpio17];
  assign cio_gpio_gpio_p2d[18] = mio_p2d[MioInGpioGpio18];
  assign cio_gpio_gpio_p2d[19] = mio_p2d[MioInGpioGpio19];
  assign cio_gpio_gpio_p2d[20] = mio_p2d[MioInGpioGpio20];
  assign cio_gpio_gpio_p2d[21] = mio_p2d[MioInGpioGpio21];
  assign cio_gpio_gpio_p2d[22] = mio_p2d[MioInGpioGpio22];
  assign cio_gpio_gpio_p2d[23] = mio_p2d[MioInGpioGpio23];
  assign cio_gpio_gpio_p2d[24] = mio_p2d[MioInGpioGpio24];
  assign cio_gpio_gpio_p2d[25] = mio_p2d[MioInGpioGpio25];
  assign cio_gpio_gpio_p2d[26] = mio_p2d[MioInGpioGpio26];
  assign cio_gpio_gpio_p2d[27] = mio_p2d[MioInGpioGpio27];
  assign cio_gpio_gpio_p2d[28] = mio_p2d[MioInGpioGpio28];
  assign cio_gpio_gpio_p2d[29] = mio_p2d[MioInGpioGpio29];
  assign cio_gpio_gpio_p2d[30] = mio_p2d[MioInGpioGpio30];
  assign cio_gpio_gpio_p2d[31] = mio_p2d[MioInGpioGpio31];
  assign cio_i2c0_sda_p2d = mio_p2d[MioInI2c0Sda];
  assign cio_i2c0_scl_p2d = mio_p2d[MioInI2c0Scl];
  assign cio_uart0_rx_p2d = mio_p2d[MioInUart0Rx];
  assign cio_spi_device_tpm_csb_p2d = mio_p2d[MioInSpiDeviceTpmCsb];

  // All muxed outputs
  assign mio_d2p[MioOutGpioGpio0] = cio_gpio_gpio_d2p[0];
  assign mio_d2p[MioOutGpioGpio1] = cio_gpio_gpio_d2p[1];
  assign mio_d2p[MioOutGpioGpio2] = cio_gpio_gpio_d2p[2];
  assign mio_d2p[MioOutGpioGpio3] = cio_gpio_gpio_d2p[3];
  assign mio_d2p[MioOutGpioGpio4] = cio_gpio_gpio_d2p[4];
  assign mio_d2p[MioOutGpioGpio5] = cio_gpio_gpio_d2p[5];
  assign mio_d2p[MioOutGpioGpio6] = cio_gpio_gpio_d2p[6];
  assign mio_d2p[MioOutGpioGpio7] = cio_gpio_gpio_d2p[7];
  assign mio_d2p[MioOutGpioGpio8] = cio_gpio_gpio_d2p[8];
  assign mio_d2p[MioOutGpioGpio9] = cio_gpio_gpio_d2p[9];
  assign mio_d2p[MioOutGpioGpio10] = cio_gpio_gpio_d2p[10];
  assign mio_d2p[MioOutGpioGpio11] = cio_gpio_gpio_d2p[11];
  assign mio_d2p[MioOutGpioGpio12] = cio_gpio_gpio_d2p[12];
  assign mio_d2p[MioOutGpioGpio13] = cio_gpio_gpio_d2p[13];
  assign mio_d2p[MioOutGpioGpio14] = cio_gpio_gpio_d2p[14];
  assign mio_d2p[MioOutGpioGpio15] = cio_gpio_gpio_d2p[15];
  assign mio_d2p[MioOutGpioGpio16] = cio_gpio_gpio_d2p[16];
  assign mio_d2p[MioOutGpioGpio17] = cio_gpio_gpio_d2p[17];
  assign mio_d2p[MioOutGpioGpio18] = cio_gpio_gpio_d2p[18];
  assign mio_d2p[MioOutGpioGpio19] = cio_gpio_gpio_d2p[19];
  assign mio_d2p[MioOutGpioGpio20] = cio_gpio_gpio_d2p[20];
  assign mio_d2p[MioOutGpioGpio21] = cio_gpio_gpio_d2p[21];
  assign mio_d2p[MioOutGpioGpio22] = cio_gpio_gpio_d2p[22];
  assign mio_d2p[MioOutGpioGpio23] = cio_gpio_gpio_d2p[23];
  assign mio_d2p[MioOutGpioGpio24] = cio_gpio_gpio_d2p[24];
  assign mio_d2p[MioOutGpioGpio25] = cio_gpio_gpio_d2p[25];
  assign mio_d2p[MioOutGpioGpio26] = cio_gpio_gpio_d2p[26];
  assign mio_d2p[MioOutGpioGpio27] = cio_gpio_gpio_d2p[27];
  assign mio_d2p[MioOutGpioGpio28] = cio_gpio_gpio_d2p[28];
  assign mio_d2p[MioOutGpioGpio29] = cio_gpio_gpio_d2p[29];
  assign mio_d2p[MioOutGpioGpio30] = cio_gpio_gpio_d2p[30];
  assign mio_d2p[MioOutGpioGpio31] = cio_gpio_gpio_d2p[31];
  assign mio_d2p[MioOutI2c0Sda] = cio_i2c0_sda_d2p;
  assign mio_d2p[MioOutI2c0Scl] = cio_i2c0_scl_d2p;
  assign mio_d2p[MioOutUart0Tx] = cio_uart0_tx_d2p;
  assign mio_d2p[MioOutSensorCtrlAstDebugOut0] = cio_sensor_ctrl_ast_debug_out_d2p[0];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut1] = cio_sensor_ctrl_ast_debug_out_d2p[1];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut2] = cio_sensor_ctrl_ast_debug_out_d2p[2];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut3] = cio_sensor_ctrl_ast_debug_out_d2p[3];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut4] = cio_sensor_ctrl_ast_debug_out_d2p[4];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut5] = cio_sensor_ctrl_ast_debug_out_d2p[5];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut6] = cio_sensor_ctrl_ast_debug_out_d2p[6];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut7] = cio_sensor_ctrl_ast_debug_out_d2p[7];
  assign mio_d2p[MioOutSensorCtrlAstDebugOut8] = cio_sensor_ctrl_ast_debug_out_d2p[8];
  assign mio_d2p[MioOutOtpCtrlTest0] = cio_otp_ctrl_test_d2p[0];

  // All muxed output enables
  assign mio_en_d2p[MioOutGpioGpio0] = cio_gpio_gpio_en_d2p[0];
  assign mio_en_d2p[MioOutGpioGpio1] = cio_gpio_gpio_en_d2p[1];
  assign mio_en_d2p[MioOutGpioGpio2] = cio_gpio_gpio_en_d2p[2];
  assign mio_en_d2p[MioOutGpioGpio3] = cio_gpio_gpio_en_d2p[3];
  assign mio_en_d2p[MioOutGpioGpio4] = cio_gpio_gpio_en_d2p[4];
  assign mio_en_d2p[MioOutGpioGpio5] = cio_gpio_gpio_en_d2p[5];
  assign mio_en_d2p[MioOutGpioGpio6] = cio_gpio_gpio_en_d2p[6];
  assign mio_en_d2p[MioOutGpioGpio7] = cio_gpio_gpio_en_d2p[7];
  assign mio_en_d2p[MioOutGpioGpio8] = cio_gpio_gpio_en_d2p[8];
  assign mio_en_d2p[MioOutGpioGpio9] = cio_gpio_gpio_en_d2p[9];
  assign mio_en_d2p[MioOutGpioGpio10] = cio_gpio_gpio_en_d2p[10];
  assign mio_en_d2p[MioOutGpioGpio11] = cio_gpio_gpio_en_d2p[11];
  assign mio_en_d2p[MioOutGpioGpio12] = cio_gpio_gpio_en_d2p[12];
  assign mio_en_d2p[MioOutGpioGpio13] = cio_gpio_gpio_en_d2p[13];
  assign mio_en_d2p[MioOutGpioGpio14] = cio_gpio_gpio_en_d2p[14];
  assign mio_en_d2p[MioOutGpioGpio15] = cio_gpio_gpio_en_d2p[15];
  assign mio_en_d2p[MioOutGpioGpio16] = cio_gpio_gpio_en_d2p[16];
  assign mio_en_d2p[MioOutGpioGpio17] = cio_gpio_gpio_en_d2p[17];
  assign mio_en_d2p[MioOutGpioGpio18] = cio_gpio_gpio_en_d2p[18];
  assign mio_en_d2p[MioOutGpioGpio19] = cio_gpio_gpio_en_d2p[19];
  assign mio_en_d2p[MioOutGpioGpio20] = cio_gpio_gpio_en_d2p[20];
  assign mio_en_d2p[MioOutGpioGpio21] = cio_gpio_gpio_en_d2p[21];
  assign mio_en_d2p[MioOutGpioGpio22] = cio_gpio_gpio_en_d2p[22];
  assign mio_en_d2p[MioOutGpioGpio23] = cio_gpio_gpio_en_d2p[23];
  assign mio_en_d2p[MioOutGpioGpio24] = cio_gpio_gpio_en_d2p[24];
  assign mio_en_d2p[MioOutGpioGpio25] = cio_gpio_gpio_en_d2p[25];
  assign mio_en_d2p[MioOutGpioGpio26] = cio_gpio_gpio_en_d2p[26];
  assign mio_en_d2p[MioOutGpioGpio27] = cio_gpio_gpio_en_d2p[27];
  assign mio_en_d2p[MioOutGpioGpio28] = cio_gpio_gpio_en_d2p[28];
  assign mio_en_d2p[MioOutGpioGpio29] = cio_gpio_gpio_en_d2p[29];
  assign mio_en_d2p[MioOutGpioGpio30] = cio_gpio_gpio_en_d2p[30];
  assign mio_en_d2p[MioOutGpioGpio31] = cio_gpio_gpio_en_d2p[31];
  assign mio_en_d2p[MioOutI2c0Sda] = cio_i2c0_sda_en_d2p;
  assign mio_en_d2p[MioOutI2c0Scl] = cio_i2c0_scl_en_d2p;
  assign mio_en_d2p[MioOutUart0Tx] = cio_uart0_tx_en_d2p;
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut0] = cio_sensor_ctrl_ast_debug_out_en_d2p[0];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut1] = cio_sensor_ctrl_ast_debug_out_en_d2p[1];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut2] = cio_sensor_ctrl_ast_debug_out_en_d2p[2];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut3] = cio_sensor_ctrl_ast_debug_out_en_d2p[3];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut4] = cio_sensor_ctrl_ast_debug_out_en_d2p[4];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut5] = cio_sensor_ctrl_ast_debug_out_en_d2p[5];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut6] = cio_sensor_ctrl_ast_debug_out_en_d2p[6];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut7] = cio_sensor_ctrl_ast_debug_out_en_d2p[7];
  assign mio_en_d2p[MioOutSensorCtrlAstDebugOut8] = cio_sensor_ctrl_ast_debug_out_en_d2p[8];
  assign mio_en_d2p[MioOutOtpCtrlTest0] = cio_otp_ctrl_test_en_d2p[0];

  // All dedicated inputs
  logic [11:0] unused_dio_p2d;
  assign unused_dio_p2d = dio_p2d;
  assign cio_spi_host0_sd_p2d[0] = dio_p2d[DioSpiHost0Sd0];
  assign cio_spi_host0_sd_p2d[1] = dio_p2d[DioSpiHost0Sd1];
  assign cio_spi_host0_sd_p2d[2] = dio_p2d[DioSpiHost0Sd2];
  assign cio_spi_host0_sd_p2d[3] = dio_p2d[DioSpiHost0Sd3];
  assign cio_spi_device_sd_p2d[0] = dio_p2d[DioSpiDeviceSd0];
  assign cio_spi_device_sd_p2d[1] = dio_p2d[DioSpiDeviceSd1];
  assign cio_spi_device_sd_p2d[2] = dio_p2d[DioSpiDeviceSd2];
  assign cio_spi_device_sd_p2d[3] = dio_p2d[DioSpiDeviceSd3];
  assign cio_spi_device_sck_p2d = dio_p2d[DioSpiDeviceSck];
  assign cio_spi_device_csb_p2d = dio_p2d[DioSpiDeviceCsb];

    // All dedicated outputs
  assign dio_d2p[DioSpiHost0Sd0] = cio_spi_host0_sd_d2p[0];
  assign dio_d2p[DioSpiHost0Sd1] = cio_spi_host0_sd_d2p[1];
  assign dio_d2p[DioSpiHost0Sd2] = cio_spi_host0_sd_d2p[2];
  assign dio_d2p[DioSpiHost0Sd3] = cio_spi_host0_sd_d2p[3];
  assign dio_d2p[DioSpiDeviceSd0] = cio_spi_device_sd_d2p[0];
  assign dio_d2p[DioSpiDeviceSd1] = cio_spi_device_sd_d2p[1];
  assign dio_d2p[DioSpiDeviceSd2] = cio_spi_device_sd_d2p[2];
  assign dio_d2p[DioSpiDeviceSd3] = cio_spi_device_sd_d2p[3];
  assign dio_d2p[DioSpiDeviceSck] = 1'b0;
  assign dio_d2p[DioSpiDeviceCsb] = 1'b0;
  assign dio_d2p[DioSpiHost0Sck] = cio_spi_host0_sck_d2p;
  assign dio_d2p[DioSpiHost0Csb] = cio_spi_host0_csb_d2p;

  // All dedicated output enables
  assign dio_en_d2p[DioSpiHost0Sd0] = cio_spi_host0_sd_en_d2p[0];
  assign dio_en_d2p[DioSpiHost0Sd1] = cio_spi_host0_sd_en_d2p[1];
  assign dio_en_d2p[DioSpiHost0Sd2] = cio_spi_host0_sd_en_d2p[2];
  assign dio_en_d2p[DioSpiHost0Sd3] = cio_spi_host0_sd_en_d2p[3];
  assign dio_en_d2p[DioSpiDeviceSd0] = cio_spi_device_sd_en_d2p[0];
  assign dio_en_d2p[DioSpiDeviceSd1] = cio_spi_device_sd_en_d2p[1];
  assign dio_en_d2p[DioSpiDeviceSd2] = cio_spi_device_sd_en_d2p[2];
  assign dio_en_d2p[DioSpiDeviceSd3] = cio_spi_device_sd_en_d2p[3];
  assign dio_en_d2p[DioSpiDeviceSck] = 1'b0;
  assign dio_en_d2p[DioSpiDeviceCsb] = 1'b0;
  assign dio_en_d2p[DioSpiHost0Sck] = cio_spi_host0_sck_en_d2p;
  assign dio_en_d2p[DioSpiHost0Csb] = cio_spi_host0_csb_en_d2p;


  // make sure scanmode_i is never X (including during reset)
  `ASSERT_KNOWN(scanmodeKnown, scanmode_i, clk_main_i, 0)

endmodule
