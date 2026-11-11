// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{DecodeOptions, EnumValue, Message, MessageField};

mod demo_fixture_types;

// This support module is split into audit-sized include files while keeping
// the sibling demo_fixture_types module declaration at its original path.
include!("demo_fixture_witness/part_01.rs");
include!("demo_fixture_witness/part_02.rs");
include!("demo_fixture_witness/part_03.rs");
