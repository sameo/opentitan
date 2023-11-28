// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
// Register Top module auto-generated by `reggen`

`include "prim_assert.sv"

module ast_reg_top (
  input clk_i,
  input rst_ni,
  input  tlul_pkg::tl_h2d_t tl_i,
  output tlul_pkg::tl_d2h_t tl_o,
  // To HW
  output ast_reg_pkg::ast_reg2hw_t reg2hw, // Write
  input  ast_reg_pkg::ast_hw2reg_t hw2reg, // Read

  // Integrity check errors
  output logic intg_err_o,

  // Config
  input devmode_i // If 1, explicit error return for unmapped register access
);

  import ast_reg_pkg::* ;

  localparam int AW = 10;
  localparam int DW = 32;
  localparam int DBW = DW/8;                    // Byte Width

  // register signals
  logic           reg_we;
  logic           reg_re;
  logic [AW-1:0]  reg_addr;
  logic [DW-1:0]  reg_wdata;
  logic [DBW-1:0] reg_be;
  logic [DW-1:0]  reg_rdata;
  logic           reg_error;

  logic          addrmiss, wr_err;

  logic [DW-1:0] reg_rdata_next;
  logic reg_busy;

  tlul_pkg::tl_h2d_t tl_reg_h2d;
  tlul_pkg::tl_d2h_t tl_reg_d2h;


  // incoming payload check
  logic intg_err;
  tlul_cmd_intg_chk u_chk (
    .tl_i(tl_i),
    .err_o(intg_err)
  );

  // also check for spurious write enables
  logic reg_we_err;
  logic [35:0] reg_we_check;
  prim_reg_we_check #(
    .OneHotWidth(36)
  ) u_prim_reg_we_check (
    .clk_i(clk_i),
    .rst_ni(rst_ni),
    .oh_i  (reg_we_check),
    .en_i  (reg_we && !addrmiss),
    .err_o (reg_we_err)
  );

  logic err_q;
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      err_q <= '0;
    end else if (intg_err || reg_we_err) begin
      err_q <= 1'b1;
    end
  end

  // integrity error output is permanent and should be used for alert generation
  // register errors are transactional
  assign intg_err_o = err_q | intg_err | reg_we_err;

  // outgoing integrity generation
  tlul_pkg::tl_d2h_t tl_o_pre;
  tlul_rsp_intg_gen #(
    .EnableRspIntgGen(1),
    .EnableDataIntgGen(1)
  ) u_rsp_intg_gen (
    .tl_i(tl_o_pre),
    .tl_o(tl_o)
  );

  assign tl_reg_h2d = tl_i;
  assign tl_o_pre   = tl_reg_d2h;

  tlul_adapter_reg #(
    .RegAw(AW),
    .RegDw(DW),
    .EnableDataIntgGen(0)
  ) u_reg_if (
    .clk_i  (clk_i),
    .rst_ni (rst_ni),

    .tl_i (tl_reg_h2d),
    .tl_o (tl_reg_d2h),

    .en_ifetch_i(prim_mubi_pkg::MuBi4False),
    .intg_error_o(),

    .we_o    (reg_we),
    .re_o    (reg_re),
    .addr_o  (reg_addr),
    .wdata_o (reg_wdata),
    .be_o    (reg_be),
    .busy_i  (reg_busy),
    .rdata_i (reg_rdata),
    .error_i (reg_error)
  );

  // cdc oversampling signals

  assign reg_rdata = reg_rdata_next ;
  assign reg_error = (devmode_i & addrmiss) | wr_err | intg_err;

  // Define SW related signals
  // Format: <reg>_<field>_{wd|we|qs}
  //        or <reg>_{wd|we|qs} if field == 1 or 0
  logic [31:0] rega0_qs;
  logic [31:0] rega1_qs;
  logic rega2_we;
  logic [31:0] rega2_qs;
  logic [31:0] rega2_wd;
  logic rega3_we;
  logic [31:0] rega3_qs;
  logic [31:0] rega3_wd;
  logic rega4_we;
  logic [31:0] rega4_qs;
  logic [31:0] rega4_wd;
  logic rega5_we;
  logic [31:0] rega5_qs;
  logic [31:0] rega5_wd;
  logic rega6_we;
  logic [31:0] rega6_qs;
  logic [31:0] rega6_wd;
  logic rega7_we;
  logic [31:0] rega7_qs;
  logic [31:0] rega7_wd;
  logic rega8_we;
  logic [31:0] rega8_qs;
  logic [31:0] rega8_wd;
  logic rega9_we;
  logic [31:0] rega9_qs;
  logic [31:0] rega9_wd;
  logic rega10_we;
  logic [31:0] rega10_qs;
  logic [31:0] rega10_wd;
  logic rega11_we;
  logic [31:0] rega11_qs;
  logic [31:0] rega11_wd;
  logic rega12_we;
  logic [31:0] rega12_qs;
  logic [31:0] rega12_wd;
  logic rega13_we;
  logic [31:0] rega13_qs;
  logic [31:0] rega13_wd;
  logic rega14_we;
  logic [31:0] rega14_qs;
  logic [31:0] rega14_wd;
  logic rega15_we;
  logic [31:0] rega15_qs;
  logic [31:0] rega15_wd;
  logic rega16_we;
  logic [31:0] rega16_qs;
  logic [31:0] rega16_wd;
  logic rega17_we;
  logic [31:0] rega17_qs;
  logic [31:0] rega17_wd;
  logic rega18_we;
  logic [31:0] rega18_qs;
  logic [31:0] rega18_wd;
  logic rega19_we;
  logic [31:0] rega19_qs;
  logic [31:0] rega19_wd;
  logic rega20_we;
  logic [31:0] rega20_qs;
  logic [31:0] rega20_wd;
  logic rega21_we;
  logic [31:0] rega21_qs;
  logic [31:0] rega21_wd;
  logic rega22_we;
  logic [31:0] rega22_qs;
  logic [31:0] rega22_wd;
  logic rega23_we;
  logic [31:0] rega23_qs;
  logic [31:0] rega23_wd;
  logic rega24_we;
  logic [31:0] rega24_qs;
  logic [31:0] rega24_wd;
  logic rega25_we;
  logic [31:0] rega25_qs;
  logic [31:0] rega25_wd;
  logic rega26_we;
  logic [31:0] rega26_qs;
  logic [31:0] rega26_wd;
  logic rega27_we;
  logic [31:0] rega27_qs;
  logic [31:0] rega27_wd;
  logic [31:0] rega28_qs;
  logic rega29_we;
  logic [31:0] rega29_qs;
  logic [31:0] rega29_wd;
  logic regal_we;
  logic [31:0] regal_wd;
  logic regb_0_we;
  logic [31:0] regb_0_qs;
  logic [31:0] regb_0_wd;
  logic regb_1_we;
  logic [31:0] regb_1_qs;
  logic [31:0] regb_1_wd;
  logic regb_2_we;
  logic [31:0] regb_2_qs;
  logic [31:0] regb_2_wd;
  logic regb_3_we;
  logic [31:0] regb_3_qs;
  logic [31:0] regb_3_wd;
  logic regb_4_we;
  logic [31:0] regb_4_qs;
  logic [31:0] regb_4_wd;

  // Register instances
  // R[rega0]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRO),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_rega0 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (1'b0),
    .wd     ('0),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega0.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega0_qs)
  );


  // R[rega1]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRO),
    .RESVAL  (32'h1),
    .Mubi    (1'b0)
  ) u_rega1 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (1'b0),
    .wd     ('0),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega1.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega1_qs)
  );


  // R[rega2]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h2),
    .Mubi    (1'b0)
  ) u_rega2 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega2_we),
    .wd     (rega2_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega2.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega2_qs)
  );


  // R[rega3]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h3),
    .Mubi    (1'b0)
  ) u_rega3 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega3_we),
    .wd     (rega3_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega3.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega3_qs)
  );


  // R[rega4]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h4),
    .Mubi    (1'b0)
  ) u_rega4 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega4_we),
    .wd     (rega4_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega4.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega4_qs)
  );


  // R[rega5]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h5),
    .Mubi    (1'b0)
  ) u_rega5 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega5_we),
    .wd     (rega5_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega5.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega5_qs)
  );


  // R[rega6]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h6),
    .Mubi    (1'b0)
  ) u_rega6 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega6_we),
    .wd     (rega6_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega6.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega6_qs)
  );


  // R[rega7]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h7),
    .Mubi    (1'b0)
  ) u_rega7 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega7_we),
    .wd     (rega7_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega7.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega7_qs)
  );


  // R[rega8]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h8),
    .Mubi    (1'b0)
  ) u_rega8 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega8_we),
    .wd     (rega8_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega8.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega8_qs)
  );


  // R[rega9]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h9),
    .Mubi    (1'b0)
  ) u_rega9 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega9_we),
    .wd     (rega9_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega9.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega9_qs)
  );


  // R[rega10]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'ha),
    .Mubi    (1'b0)
  ) u_rega10 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega10_we),
    .wd     (rega10_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega10.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega10_qs)
  );


  // R[rega11]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'hb),
    .Mubi    (1'b0)
  ) u_rega11 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega11_we),
    .wd     (rega11_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega11.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega11_qs)
  );


  // R[rega12]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'hc),
    .Mubi    (1'b0)
  ) u_rega12 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega12_we),
    .wd     (rega12_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega12.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega12_qs)
  );


  // R[rega13]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'hd),
    .Mubi    (1'b0)
  ) u_rega13 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega13_we),
    .wd     (rega13_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega13.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega13_qs)
  );


  // R[rega14]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'he),
    .Mubi    (1'b0)
  ) u_rega14 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega14_we),
    .wd     (rega14_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega14.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega14_qs)
  );


  // R[rega15]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'hf),
    .Mubi    (1'b0)
  ) u_rega15 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega15_we),
    .wd     (rega15_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega15.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega15_qs)
  );


  // R[rega16]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h10),
    .Mubi    (1'b0)
  ) u_rega16 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega16_we),
    .wd     (rega16_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega16.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega16_qs)
  );


  // R[rega17]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h11),
    .Mubi    (1'b0)
  ) u_rega17 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega17_we),
    .wd     (rega17_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega17.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega17_qs)
  );


  // R[rega18]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h12),
    .Mubi    (1'b0)
  ) u_rega18 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega18_we),
    .wd     (rega18_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega18.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega18_qs)
  );


  // R[rega19]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h13),
    .Mubi    (1'b0)
  ) u_rega19 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega19_we),
    .wd     (rega19_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega19.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega19_qs)
  );


  // R[rega20]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h14),
    .Mubi    (1'b0)
  ) u_rega20 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega20_we),
    .wd     (rega20_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega20.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega20_qs)
  );


  // R[rega21]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h15),
    .Mubi    (1'b0)
  ) u_rega21 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega21_we),
    .wd     (rega21_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega21.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega21_qs)
  );


  // R[rega22]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h16),
    .Mubi    (1'b0)
  ) u_rega22 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega22_we),
    .wd     (rega22_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega22.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega22_qs)
  );


  // R[rega23]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h17),
    .Mubi    (1'b0)
  ) u_rega23 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega23_we),
    .wd     (rega23_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega23.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega23_qs)
  );


  // R[rega24]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h18),
    .Mubi    (1'b0)
  ) u_rega24 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega24_we),
    .wd     (rega24_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega24.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega24_qs)
  );


  // R[rega25]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h19),
    .Mubi    (1'b0)
  ) u_rega25 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega25_we),
    .wd     (rega25_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega25.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega25_qs)
  );


  // R[rega26]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h1a),
    .Mubi    (1'b0)
  ) u_rega26 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega26_we),
    .wd     (rega26_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega26.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega26_qs)
  );


  // R[rega27]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h1b),
    .Mubi    (1'b0)
  ) u_rega27 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega27_we),
    .wd     (rega27_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega27.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega27_qs)
  );


  // R[rega28]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRO),
    .RESVAL  (32'h1c),
    .Mubi    (1'b0)
  ) u_rega28 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (1'b0),
    .wd     ('0),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega28.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega28_qs)
  );


  // R[rega29]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h1d),
    .Mubi    (1'b0)
  ) u_rega29 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (rega29_we),
    .wd     (rega29_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.rega29.q),
    .ds     (),

    // to register interface (read)
    .qs     (rega29_qs)
  );


  // R[regal]: V(True)
  logic regal_qe;
  logic [0:0] regal_flds_we;
  assign regal_qe = &regal_flds_we;
  prim_subreg_ext #(
    .DW    (32)
  ) u_regal (
    .re     (1'b0),
    .we     (regal_we),
    .wd     (regal_wd),
    .d      (hw2reg.regal.d),
    .qre    (),
    .qe     (regal_flds_we[0]),
    .q      (reg2hw.regal.q),
    .ds     (),
    .qs     ()
  );
  assign reg2hw.regal.qe = regal_qe;


  // Subregister 0 of Multireg regb
  // R[regb_0]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_regb_0 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (regb_0_we),
    .wd     (regb_0_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.regb[0].q),
    .ds     (),

    // to register interface (read)
    .qs     (regb_0_qs)
  );


  // Subregister 1 of Multireg regb
  // R[regb_1]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_regb_1 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (regb_1_we),
    .wd     (regb_1_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.regb[1].q),
    .ds     (),

    // to register interface (read)
    .qs     (regb_1_qs)
  );


  // Subregister 2 of Multireg regb
  // R[regb_2]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_regb_2 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (regb_2_we),
    .wd     (regb_2_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.regb[2].q),
    .ds     (),

    // to register interface (read)
    .qs     (regb_2_qs)
  );


  // Subregister 3 of Multireg regb
  // R[regb_3]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_regb_3 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (regb_3_we),
    .wd     (regb_3_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.regb[3].q),
    .ds     (),

    // to register interface (read)
    .qs     (regb_3_qs)
  );


  // Subregister 4 of Multireg regb
  // R[regb_4]: V(False)
  prim_subreg #(
    .DW      (32),
    .SwAccess(prim_subreg_pkg::SwAccessRW),
    .RESVAL  (32'h0),
    .Mubi    (1'b0)
  ) u_regb_4 (
    .clk_i   (clk_i),
    .rst_ni  (rst_ni),

    // from register interface
    .we     (regb_4_we),
    .wd     (regb_4_wd),

    // from internal hardware
    .de     (1'b0),
    .d      ('0),

    // to internal hardware
    .qe     (),
    .q      (reg2hw.regb[4].q),
    .ds     (),

    // to register interface (read)
    .qs     (regb_4_qs)
  );



  logic [35:0] addr_hit;
  always_comb begin
    addr_hit = '0;
    addr_hit[ 0] = (reg_addr == AST_REGA0_OFFSET);
    addr_hit[ 1] = (reg_addr == AST_REGA1_OFFSET);
    addr_hit[ 2] = (reg_addr == AST_REGA2_OFFSET);
    addr_hit[ 3] = (reg_addr == AST_REGA3_OFFSET);
    addr_hit[ 4] = (reg_addr == AST_REGA4_OFFSET);
    addr_hit[ 5] = (reg_addr == AST_REGA5_OFFSET);
    addr_hit[ 6] = (reg_addr == AST_REGA6_OFFSET);
    addr_hit[ 7] = (reg_addr == AST_REGA7_OFFSET);
    addr_hit[ 8] = (reg_addr == AST_REGA8_OFFSET);
    addr_hit[ 9] = (reg_addr == AST_REGA9_OFFSET);
    addr_hit[10] = (reg_addr == AST_REGA10_OFFSET);
    addr_hit[11] = (reg_addr == AST_REGA11_OFFSET);
    addr_hit[12] = (reg_addr == AST_REGA12_OFFSET);
    addr_hit[13] = (reg_addr == AST_REGA13_OFFSET);
    addr_hit[14] = (reg_addr == AST_REGA14_OFFSET);
    addr_hit[15] = (reg_addr == AST_REGA15_OFFSET);
    addr_hit[16] = (reg_addr == AST_REGA16_OFFSET);
    addr_hit[17] = (reg_addr == AST_REGA17_OFFSET);
    addr_hit[18] = (reg_addr == AST_REGA18_OFFSET);
    addr_hit[19] = (reg_addr == AST_REGA19_OFFSET);
    addr_hit[20] = (reg_addr == AST_REGA20_OFFSET);
    addr_hit[21] = (reg_addr == AST_REGA21_OFFSET);
    addr_hit[22] = (reg_addr == AST_REGA22_OFFSET);
    addr_hit[23] = (reg_addr == AST_REGA23_OFFSET);
    addr_hit[24] = (reg_addr == AST_REGA24_OFFSET);
    addr_hit[25] = (reg_addr == AST_REGA25_OFFSET);
    addr_hit[26] = (reg_addr == AST_REGA26_OFFSET);
    addr_hit[27] = (reg_addr == AST_REGA27_OFFSET);
    addr_hit[28] = (reg_addr == AST_REGA28_OFFSET);
    addr_hit[29] = (reg_addr == AST_REGA29_OFFSET);
    addr_hit[30] = (reg_addr == AST_REGAL_OFFSET);
    addr_hit[31] = (reg_addr == AST_REGB_0_OFFSET);
    addr_hit[32] = (reg_addr == AST_REGB_1_OFFSET);
    addr_hit[33] = (reg_addr == AST_REGB_2_OFFSET);
    addr_hit[34] = (reg_addr == AST_REGB_3_OFFSET);
    addr_hit[35] = (reg_addr == AST_REGB_4_OFFSET);
  end

  assign addrmiss = (reg_re || reg_we) ? ~|addr_hit : 1'b0 ;

  // Check sub-word write is permitted
  always_comb begin
    wr_err = (reg_we &
              ((addr_hit[ 0] & (|(AST_PERMIT[ 0] & ~reg_be))) |
               (addr_hit[ 1] & (|(AST_PERMIT[ 1] & ~reg_be))) |
               (addr_hit[ 2] & (|(AST_PERMIT[ 2] & ~reg_be))) |
               (addr_hit[ 3] & (|(AST_PERMIT[ 3] & ~reg_be))) |
               (addr_hit[ 4] & (|(AST_PERMIT[ 4] & ~reg_be))) |
               (addr_hit[ 5] & (|(AST_PERMIT[ 5] & ~reg_be))) |
               (addr_hit[ 6] & (|(AST_PERMIT[ 6] & ~reg_be))) |
               (addr_hit[ 7] & (|(AST_PERMIT[ 7] & ~reg_be))) |
               (addr_hit[ 8] & (|(AST_PERMIT[ 8] & ~reg_be))) |
               (addr_hit[ 9] & (|(AST_PERMIT[ 9] & ~reg_be))) |
               (addr_hit[10] & (|(AST_PERMIT[10] & ~reg_be))) |
               (addr_hit[11] & (|(AST_PERMIT[11] & ~reg_be))) |
               (addr_hit[12] & (|(AST_PERMIT[12] & ~reg_be))) |
               (addr_hit[13] & (|(AST_PERMIT[13] & ~reg_be))) |
               (addr_hit[14] & (|(AST_PERMIT[14] & ~reg_be))) |
               (addr_hit[15] & (|(AST_PERMIT[15] & ~reg_be))) |
               (addr_hit[16] & (|(AST_PERMIT[16] & ~reg_be))) |
               (addr_hit[17] & (|(AST_PERMIT[17] & ~reg_be))) |
               (addr_hit[18] & (|(AST_PERMIT[18] & ~reg_be))) |
               (addr_hit[19] & (|(AST_PERMIT[19] & ~reg_be))) |
               (addr_hit[20] & (|(AST_PERMIT[20] & ~reg_be))) |
               (addr_hit[21] & (|(AST_PERMIT[21] & ~reg_be))) |
               (addr_hit[22] & (|(AST_PERMIT[22] & ~reg_be))) |
               (addr_hit[23] & (|(AST_PERMIT[23] & ~reg_be))) |
               (addr_hit[24] & (|(AST_PERMIT[24] & ~reg_be))) |
               (addr_hit[25] & (|(AST_PERMIT[25] & ~reg_be))) |
               (addr_hit[26] & (|(AST_PERMIT[26] & ~reg_be))) |
               (addr_hit[27] & (|(AST_PERMIT[27] & ~reg_be))) |
               (addr_hit[28] & (|(AST_PERMIT[28] & ~reg_be))) |
               (addr_hit[29] & (|(AST_PERMIT[29] & ~reg_be))) |
               (addr_hit[30] & (|(AST_PERMIT[30] & ~reg_be))) |
               (addr_hit[31] & (|(AST_PERMIT[31] & ~reg_be))) |
               (addr_hit[32] & (|(AST_PERMIT[32] & ~reg_be))) |
               (addr_hit[33] & (|(AST_PERMIT[33] & ~reg_be))) |
               (addr_hit[34] & (|(AST_PERMIT[34] & ~reg_be))) |
               (addr_hit[35] & (|(AST_PERMIT[35] & ~reg_be)))));
  end

  // Generate write-enables
  assign rega2_we = addr_hit[2] & reg_we & !reg_error;

  assign rega2_wd = reg_wdata[31:0];
  assign rega3_we = addr_hit[3] & reg_we & !reg_error;

  assign rega3_wd = reg_wdata[31:0];
  assign rega4_we = addr_hit[4] & reg_we & !reg_error;

  assign rega4_wd = reg_wdata[31:0];
  assign rega5_we = addr_hit[5] & reg_we & !reg_error;

  assign rega5_wd = reg_wdata[31:0];
  assign rega6_we = addr_hit[6] & reg_we & !reg_error;

  assign rega6_wd = reg_wdata[31:0];
  assign rega7_we = addr_hit[7] & reg_we & !reg_error;

  assign rega7_wd = reg_wdata[31:0];
  assign rega8_we = addr_hit[8] & reg_we & !reg_error;

  assign rega8_wd = reg_wdata[31:0];
  assign rega9_we = addr_hit[9] & reg_we & !reg_error;

  assign rega9_wd = reg_wdata[31:0];
  assign rega10_we = addr_hit[10] & reg_we & !reg_error;

  assign rega10_wd = reg_wdata[31:0];
  assign rega11_we = addr_hit[11] & reg_we & !reg_error;

  assign rega11_wd = reg_wdata[31:0];
  assign rega12_we = addr_hit[12] & reg_we & !reg_error;

  assign rega12_wd = reg_wdata[31:0];
  assign rega13_we = addr_hit[13] & reg_we & !reg_error;

  assign rega13_wd = reg_wdata[31:0];
  assign rega14_we = addr_hit[14] & reg_we & !reg_error;

  assign rega14_wd = reg_wdata[31:0];
  assign rega15_we = addr_hit[15] & reg_we & !reg_error;

  assign rega15_wd = reg_wdata[31:0];
  assign rega16_we = addr_hit[16] & reg_we & !reg_error;

  assign rega16_wd = reg_wdata[31:0];
  assign rega17_we = addr_hit[17] & reg_we & !reg_error;

  assign rega17_wd = reg_wdata[31:0];
  assign rega18_we = addr_hit[18] & reg_we & !reg_error;

  assign rega18_wd = reg_wdata[31:0];
  assign rega19_we = addr_hit[19] & reg_we & !reg_error;

  assign rega19_wd = reg_wdata[31:0];
  assign rega20_we = addr_hit[20] & reg_we & !reg_error;

  assign rega20_wd = reg_wdata[31:0];
  assign rega21_we = addr_hit[21] & reg_we & !reg_error;

  assign rega21_wd = reg_wdata[31:0];
  assign rega22_we = addr_hit[22] & reg_we & !reg_error;

  assign rega22_wd = reg_wdata[31:0];
  assign rega23_we = addr_hit[23] & reg_we & !reg_error;

  assign rega23_wd = reg_wdata[31:0];
  assign rega24_we = addr_hit[24] & reg_we & !reg_error;

  assign rega24_wd = reg_wdata[31:0];
  assign rega25_we = addr_hit[25] & reg_we & !reg_error;

  assign rega25_wd = reg_wdata[31:0];
  assign rega26_we = addr_hit[26] & reg_we & !reg_error;

  assign rega26_wd = reg_wdata[31:0];
  assign rega27_we = addr_hit[27] & reg_we & !reg_error;

  assign rega27_wd = reg_wdata[31:0];
  assign rega29_we = addr_hit[29] & reg_we & !reg_error;

  assign rega29_wd = reg_wdata[31:0];
  assign regal_we = addr_hit[30] & reg_we & !reg_error;

  assign regal_wd = reg_wdata[31:0];
  assign regb_0_we = addr_hit[31] & reg_we & !reg_error;

  assign regb_0_wd = reg_wdata[31:0];
  assign regb_1_we = addr_hit[32] & reg_we & !reg_error;

  assign regb_1_wd = reg_wdata[31:0];
  assign regb_2_we = addr_hit[33] & reg_we & !reg_error;

  assign regb_2_wd = reg_wdata[31:0];
  assign regb_3_we = addr_hit[34] & reg_we & !reg_error;

  assign regb_3_wd = reg_wdata[31:0];
  assign regb_4_we = addr_hit[35] & reg_we & !reg_error;

  assign regb_4_wd = reg_wdata[31:0];

  // Assign write-enables to checker logic vector.
  always_comb begin
    reg_we_check = '0;
    reg_we_check[0] = 1'b0;
    reg_we_check[1] = 1'b0;
    reg_we_check[2] = rega2_we;
    reg_we_check[3] = rega3_we;
    reg_we_check[4] = rega4_we;
    reg_we_check[5] = rega5_we;
    reg_we_check[6] = rega6_we;
    reg_we_check[7] = rega7_we;
    reg_we_check[8] = rega8_we;
    reg_we_check[9] = rega9_we;
    reg_we_check[10] = rega10_we;
    reg_we_check[11] = rega11_we;
    reg_we_check[12] = rega12_we;
    reg_we_check[13] = rega13_we;
    reg_we_check[14] = rega14_we;
    reg_we_check[15] = rega15_we;
    reg_we_check[16] = rega16_we;
    reg_we_check[17] = rega17_we;
    reg_we_check[18] = rega18_we;
    reg_we_check[19] = rega19_we;
    reg_we_check[20] = rega20_we;
    reg_we_check[21] = rega21_we;
    reg_we_check[22] = rega22_we;
    reg_we_check[23] = rega23_we;
    reg_we_check[24] = rega24_we;
    reg_we_check[25] = rega25_we;
    reg_we_check[26] = rega26_we;
    reg_we_check[27] = rega27_we;
    reg_we_check[28] = 1'b0;
    reg_we_check[29] = rega29_we;
    reg_we_check[30] = regal_we;
    reg_we_check[31] = regb_0_we;
    reg_we_check[32] = regb_1_we;
    reg_we_check[33] = regb_2_we;
    reg_we_check[34] = regb_3_we;
    reg_we_check[35] = regb_4_we;
  end

  // Read data return
  always_comb begin
    reg_rdata_next = '0;
    unique case (1'b1)
      addr_hit[0]: begin
        reg_rdata_next[31:0] = rega0_qs;
      end

      addr_hit[1]: begin
        reg_rdata_next[31:0] = rega1_qs;
      end

      addr_hit[2]: begin
        reg_rdata_next[31:0] = rega2_qs;
      end

      addr_hit[3]: begin
        reg_rdata_next[31:0] = rega3_qs;
      end

      addr_hit[4]: begin
        reg_rdata_next[31:0] = rega4_qs;
      end

      addr_hit[5]: begin
        reg_rdata_next[31:0] = rega5_qs;
      end

      addr_hit[6]: begin
        reg_rdata_next[31:0] = rega6_qs;
      end

      addr_hit[7]: begin
        reg_rdata_next[31:0] = rega7_qs;
      end

      addr_hit[8]: begin
        reg_rdata_next[31:0] = rega8_qs;
      end

      addr_hit[9]: begin
        reg_rdata_next[31:0] = rega9_qs;
      end

      addr_hit[10]: begin
        reg_rdata_next[31:0] = rega10_qs;
      end

      addr_hit[11]: begin
        reg_rdata_next[31:0] = rega11_qs;
      end

      addr_hit[12]: begin
        reg_rdata_next[31:0] = rega12_qs;
      end

      addr_hit[13]: begin
        reg_rdata_next[31:0] = rega13_qs;
      end

      addr_hit[14]: begin
        reg_rdata_next[31:0] = rega14_qs;
      end

      addr_hit[15]: begin
        reg_rdata_next[31:0] = rega15_qs;
      end

      addr_hit[16]: begin
        reg_rdata_next[31:0] = rega16_qs;
      end

      addr_hit[17]: begin
        reg_rdata_next[31:0] = rega17_qs;
      end

      addr_hit[18]: begin
        reg_rdata_next[31:0] = rega18_qs;
      end

      addr_hit[19]: begin
        reg_rdata_next[31:0] = rega19_qs;
      end

      addr_hit[20]: begin
        reg_rdata_next[31:0] = rega20_qs;
      end

      addr_hit[21]: begin
        reg_rdata_next[31:0] = rega21_qs;
      end

      addr_hit[22]: begin
        reg_rdata_next[31:0] = rega22_qs;
      end

      addr_hit[23]: begin
        reg_rdata_next[31:0] = rega23_qs;
      end

      addr_hit[24]: begin
        reg_rdata_next[31:0] = rega24_qs;
      end

      addr_hit[25]: begin
        reg_rdata_next[31:0] = rega25_qs;
      end

      addr_hit[26]: begin
        reg_rdata_next[31:0] = rega26_qs;
      end

      addr_hit[27]: begin
        reg_rdata_next[31:0] = rega27_qs;
      end

      addr_hit[28]: begin
        reg_rdata_next[31:0] = rega28_qs;
      end

      addr_hit[29]: begin
        reg_rdata_next[31:0] = rega29_qs;
      end

      addr_hit[30]: begin
        reg_rdata_next[31:0] = '0;
      end

      addr_hit[31]: begin
        reg_rdata_next[31:0] = regb_0_qs;
      end

      addr_hit[32]: begin
        reg_rdata_next[31:0] = regb_1_qs;
      end

      addr_hit[33]: begin
        reg_rdata_next[31:0] = regb_2_qs;
      end

      addr_hit[34]: begin
        reg_rdata_next[31:0] = regb_3_qs;
      end

      addr_hit[35]: begin
        reg_rdata_next[31:0] = regb_4_qs;
      end

      default: begin
        reg_rdata_next = '1;
      end
    endcase
  end

  // shadow busy
  logic shadow_busy;
  assign shadow_busy = 1'b0;

  // register busy
  assign reg_busy = shadow_busy;

  // Unused signal tieoff

  // wdata / byte enable are not always fully used
  // add a blanket unused statement to handle lint waivers
  logic unused_wdata;
  logic unused_be;
  assign unused_wdata = ^reg_wdata;
  assign unused_be = ^reg_be;

  // Assertions for Register Interface
  `ASSERT_PULSE(wePulse, reg_we, clk_i, !rst_ni)
  `ASSERT_PULSE(rePulse, reg_re, clk_i, !rst_ni)

  `ASSERT(reAfterRv, $rose(reg_re || reg_we) |=> tl_o_pre.d_valid, clk_i, !rst_ni)

  `ASSERT(en2addrHit, (reg_we || reg_re) |-> $onehot0(addr_hit), clk_i, !rst_ni)

  // this is formulated as an assumption such that the FPV testbenches do disprove this
  // property by mistake
  //`ASSUME(reqParity, tl_reg_h2d.a_valid |-> tl_reg_h2d.a_user.chk_en == tlul_pkg::CheckDis)

endmodule
