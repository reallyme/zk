// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_proto_codec::{
    capability_registry::MAX_ZK_CAPABILITY_REGISTRY_BYTES, vector::MAX_ZK_PROVING_VECTOR_SET_BYTES,
};

/// Maximum files accepted in one normalized Noir source tree.
pub const MAX_NOIR_SOURCE_FILES: usize = 128;

/// Maximum aggregate Noir source bytes accepted for one circuit.
pub const MAX_NOIR_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// Maximum canonical capability-registry bytes accepted for hashing.
pub const MAX_CAPABILITY_REGISTRY_BYTES: usize = MAX_ZK_CAPABILITY_REGISTRY_BYTES;

/// Maximum bytes accepted for one vector-set protobuf file.
pub const MAX_VECTOR_FILE_BYTES: usize = MAX_ZK_PROVING_VECTOR_SET_BYTES;
