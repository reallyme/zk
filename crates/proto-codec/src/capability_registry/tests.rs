// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::Message;

use super::{
    build_capability_registry, capabilities_from_proto, circuit_ref_from_proto_message,
    decode_capability_registry, registry_to_proto, Digest32, MessageField, ZkCircuitRef, ZkError,
    ZkErrorReason, MAX_ZK_CAPABILITY_REGISTRY_BYTES,
};

#[test]
fn generated_registry_is_canonical_and_complete() -> Result<(), ZkError> {
    let encoded = registry_to_proto()?;
    for (entry, expected) in encoded.entries.into_iter().zip(ZkCircuitRef::ALL) {
        let decoded = circuit_ref_from_proto_message(entry.circuit_ref)?;
        assert_eq!(decoded, *expected);
        let capabilities = entry
            .capabilities
            .into_option()
            .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
        assert!(
            capabilities_from_proto(capabilities, decoded).is_ok(),
            "capability round trip failed for {decoded:?}"
        );
    }
    let first = build_capability_registry()?;
    let second = build_capability_registry()?;

    assert_eq!(first, second);
    assert_eq!(first.entry_count(), ZkCircuitRef::ALL.len());
    assert_eq!(first.sha256(), Digest32::sha256(first.canonical_bytes()));
    Ok(())
}

#[test]
fn decoder_rejects_missing_and_reordered_entries() -> Result<(), ZkError> {
    let mut missing = registry_to_proto()?;
    let _removed = missing.entries.pop();
    let mut reordered = registry_to_proto()?;
    reordered.entries.swap(0, 1);

    assert_eq!(
        decode_capability_registry(&missing.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    assert_eq!(
        decode_capability_registry(&reordered.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    Ok(())
}

#[test]
fn decoder_rejects_capability_drift() -> Result<(), ZkError> {
    let mut registry = registry_to_proto()?;
    let first = registry
        .entries
        .first_mut()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    let mut capabilities = first
        .capabilities
        .take()
        .ok_or(ZkError::new(ZkErrorReason::ArtifactMismatch))?;
    capabilities.may_be_correlated = !capabilities.may_be_correlated;
    first.capabilities = MessageField::some(capabilities);

    assert_eq!(
        decode_capability_registry(&registry.encode_to_vec())
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::ArtifactMismatch)
    );
    Ok(())
}

#[test]
fn decoder_rejects_malformed_and_oversized_inputs() {
    assert_eq!(
        decode_capability_registry(&[0xff])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MalformedProtobuf)
    );
    assert_eq!(
        decode_capability_registry(&vec![0_u8; MAX_ZK_CAPABILITY_REGISTRY_BYTES + 1])
            .err()
            .map(|error| error.reason()),
        Some(ZkErrorReason::MessageTooLarge)
    );
}
