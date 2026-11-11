// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build a complete common-credential-root proving operation from trusted wallet records.

// This module is split into audit-sized include files so release-readiness
// can enforce source-size limits without changing the public Rust module path.
include!("selected_record_builder/part_01.rs");
include!("selected_record_builder/part_02.rs");
include!("selected_record_builder/part_03.rs");

#[cfg(test)]
mod tests;

#[cfg(test)]
mod claim_path_tests;
