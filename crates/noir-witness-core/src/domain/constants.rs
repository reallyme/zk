// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pub const FIELD_ELEMENT_BYTES: usize = 32;
pub const FIELD_ELEMENT_BYTES_U32: u32 = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const SIGNATURE_BYTES_U32: u32 = 64;
pub const SALT_BYTES: usize = 16;
pub const SALT_BYTES_U32: u32 = 16;
pub const MAX_CLAIM_VALUE_BYTES: usize = 64;
pub const MAX_CLAIM_VALUE_BYTES_U32: u32 = 64;
/// Fixed height of every credential claim tree. The claim circuits accept only
/// paths of exactly this length, so a shorter or longer path is never valid.
pub const CLAIM_TREE_DEPTH: usize = 6;
pub const CLAIM_TREE_DEPTH_U32: u32 = 6;
pub const MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH: usize = 20;
pub const MAX_COMMON_CREDENTIAL_ROOT_STATUS_DEPTH_U32: u32 = 20;
