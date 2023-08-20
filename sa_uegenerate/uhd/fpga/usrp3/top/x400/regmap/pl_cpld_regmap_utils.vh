//
// Copyright 2022 Ettus Research, A National Instruments Company
//
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Module: pl_cpld_regmap_utils.vh
// Description:
// The constants in this file are autogenerated by XmlParse.

//===============================================================================
// A numerically ordered list of registers and their HDL source files
//===============================================================================

  // BASE     : 0x0 (cpld_interface.v)
  // MB_CPLD  : 0x8000 (cpld_interface.v)
  // DB0_CPLD : 0x10000 (cpld_interface.v)
  // DB1_CPLD : 0x18000 (cpld_interface.v)

//===============================================================================
// RegTypes
//===============================================================================

//===============================================================================
// Register Group PL_CPLD_WINDOWS
//===============================================================================

  // BASE Window (from cpld_interface.v)
  localparam BASE = 'h0; // Window Offset
  localparam BASE_SIZE = 'h40;  // size in bytes

  // MB_CPLD Window (from cpld_interface.v)
  localparam MB_CPLD = 'h8000; // Window Offset
  localparam MB_CPLD_SIZE = 'h8000;  // size in bytes

  // DB0_CPLD Window (from cpld_interface.v)
  localparam DB0_CPLD = 'h10000; // Window Offset
  localparam DB0_CPLD_SIZE = 'h8000;  // size in bytes

  // DB1_CPLD Window (from cpld_interface.v)
  localparam DB1_CPLD = 'h18000; // Window Offset
  localparam DB1_CPLD_SIZE = 'h8000;  // size in bytes