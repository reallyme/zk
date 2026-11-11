// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical release-wide semantic-capability registry.

use buffa::{DecodeOptions, Message, MessageField};
use reallyme_zk_api::{
    capabilities::circuit_ref_capabilities,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::Digest32;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;

use crate::{
    artifact::{capabilities_to_proto, circuit_ref_to_proto},
    domain::{capabilities_from_proto, circuit_ref_from_proto_message},
};

/// Canonical capability-registry wire format.
pub const CAPABILITY_REGISTRY_FORMAT_VERSION: u32 = 1;

/// Maximum accepted canonical capability-registry bytes.
pub const MAX_ZK_CAPABILITY_REGISTRY_BYTES: usize = 64 * 1024;

const REGISTRY_RECURSION_LIMIT: u32 = 16;
const REGISTRY_UNKNOWN_FIELD_LIMIT: usize = 0;
const REGISTRY_ELEMENT_MEMORY_LIMIT: usize = MAX_ZK_CAPABILITY_REGISTRY_BYTES;

/// Validated canonical registry bytes and their release-wide SHA-256 identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalCapabilityRegistry {
    canonical_bytes: Vec<u8>,
    sha256: Digest32,
}

impl CanonicalCapabilityRegistry {
    /// Canonical protobuf bytes hashed into every artifact manifest.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes.as_slice()
    }

    /// SHA-256 identity shared by every artifact in one release.
    #[must_use]
    pub const fn sha256(&self) -> Digest32 {
        self.sha256
    }

    /// Number of exact circuit entries required by this registry version.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        ZkCircuitRef::ALL.len()
    }
}

/// Generates the canonical registry exclusively from `reallyme-zk-api`.
pub fn build_capability_registry() -> Result<CanonicalCapabilityRegistry, ZkError> {
    let registry = registry_to_proto()?;
    decode_capability_registry(&registry.encode_to_vec())
}

/// Strictly decodes and validates canonical capability-registry bytes.
pub fn decode_capability_registry(bytes: &[u8]) -> Result<CanonicalCapabilityRegistry, ZkError> {
    if bytes.is_empty() {
        return Err(ZkError::new(ZkErrorReason::EmptyInput));
    }
    if bytes.len() > MAX_ZK_CAPABILITY_REGISTRY_BYTES {
        return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
    }

    let registry = DecodeOptions::new()
        .with_recursion_limit(REGISTRY_RECURSION_LIMIT)
        .with_unknown_field_limit(REGISTRY_UNKNOWN_FIELD_LIMIT)
        .with_element_memory_limit(REGISTRY_ELEMENT_MEMORY_LIMIT)
        .with_max_message_size(MAX_ZK_CAPABILITY_REGISTRY_BYTES)
        .decode_from_slice::<pb::ZkCapabilityRegistry>(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::MalformedProtobuf))?;
    if registry.encode_to_vec().as_slice() != bytes {
        return Err(ZkError::new(ZkErrorReason::MalformedProtobuf));
    }

    validate_registry(registry)?;
    let mut canonical_bytes = Vec::new();
    canonical_bytes
        .try_reserve_exact(bytes.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    canonical_bytes.extend_from_slice(bytes);
    Ok(CanonicalCapabilityRegistry {
        canonical_bytes,
        sha256: Digest32::sha256(bytes),
    })
}

fn registry_to_proto() -> Result<pb::ZkCapabilityRegistry, ZkError> {
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(ZkCircuitRef::ALL.len())
        .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
    for circuit_ref in ZkCircuitRef::ALL {
        entries.push(pb::ZkCapabilityRegistryEntry {
            circuit_ref: MessageField::some(circuit_ref_to_proto(*circuit_ref)),
            capabilities: MessageField::some(capabilities_to_proto(circuit_ref_capabilities(
                *circuit_ref,
            )?)),
            __buffa_unknown_fields: Default::default(),
        });
    }
    Ok(pb::ZkCapabilityRegistry {
        format_version: CAPABILITY_REGISTRY_FORMAT_VERSION,
        entries,
        __buffa_unknown_fields: Default::default(),
    })
}

fn validate_registry(registry: pb::ZkCapabilityRegistry) -> Result<(), ZkError> {
    if registry.format_version != CAPABILITY_REGISTRY_FORMAT_VERSION
        || registry.entries.len() != ZkCircuitRef::ALL.len()
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }

    for (entry, expected_ref) in registry.entries.into_iter().zip(ZkCircuitRef::ALL) {
        let circuit_ref = circuit_ref_from_proto_message(entry.circuit_ref)?;
        if circuit_ref != *expected_ref {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        let capabilities = entry
            .capabilities
            .into_option()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        let _validated = capabilities_from_proto(capabilities, circuit_ref)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
