// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cross-representation fixtures for the canonical provider envelope.

#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]

use core::fmt::Debug;

use buffa::{DecodeOptions, Message};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    zk_provider_operation_request::Operation, ZkProviderOperationRequest,
    ZkProviderOperationResponse,
};
use reallyme_zk_proto_codec::protojson::{
    zk_proto_from_json, zk_proto_to_json, ZkProtoJson, ZkProtoJsonError, MAX_ZK_PROTO_MESSAGE_BYTES,
};

const ARTIFACT_OPERATION_PROTOJSON: &[u8] =
    include_bytes!("../../proto/tests/fixtures/protojson/artifact-operation.json");
const ARTIFACT_OPERATION_PROTOBUF: &[u8] = &[
    0x2a, 0x0c, 0x0a, 0x08, 0x08, 0x01, 0x10, 0x01, 0x18, 0x04, 0x20, 0x01, 0x10, 0x01,
];
const BACKEND_UNAVAILABLE_PROTOJSON: &[u8] =
    include_bytes!("../../proto/tests/fixtures/protojson/backend-unavailable-response.json");
const BACKEND_UNAVAILABLE_PROTOBUF: &[u8] = &[
    0x0a, 0x20, 0xbe, 0x44, 0x02, 0x0d, 0x61, 0xb8, 0x94, 0xdf, 0x0d, 0xb8, 0x8a, 0x02, 0xe1, 0x93,
    0x72, 0x31, 0x7b, 0xa5, 0xea, 0x8b, 0x54, 0xcc, 0x1e, 0x8a, 0xb1, 0x28, 0xbd, 0x54, 0x7c, 0x7f,
    0x24, 0xab, 0x1a, 0x04, 0x08, 0x0b, 0x40, 0x01,
];
const FIXTURE_RECURSION_LIMIT: u32 = 32;
const FIXTURE_UNKNOWN_FIELD_LIMIT: usize = 0;

fn assert_protojson_golden<M>(fixture: &[u8])
where
    M: Debug + PartialEq + ZkProtoJson,
{
    let decoded: M = zk_proto_from_json(fixture).unwrap();
    let encoded = zk_proto_to_json(&decoded).unwrap();
    let round_trip: M = zk_proto_from_json(encoded.as_bytes()).unwrap();
    assert_eq!(round_trip, decoded);

    let fixture_value: serde_json::Value = serde_json::from_slice(fixture).unwrap();
    let encoded_value: serde_json::Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(encoded_value, fixture_value);
}

#[test]
fn protobuf_wire_fixtures_match_protojson_contracts() {
    assert_eq!(
        include_str!("../../proto/tests/fixtures/protobuf/artifact-operation.pb.hex").trim(),
        "2a0c0a0808011001180420011001"
    );
    assert_eq!(
        include_str!("../../proto/tests/fixtures/protobuf/backend-unavailable-response.pb.hex")
            .trim(),
        "0a20be44020d61b894df0db88a02e19372317ba5ea8b54cc1e8ab128bd547c7f24ab1a04080b4001"
    );

    assert_protojson_golden::<ZkProviderOperationRequest>(ARTIFACT_OPERATION_PROTOJSON);
    assert_protojson_golden::<ZkProviderOperationResponse>(BACKEND_UNAVAILABLE_PROTOJSON);

    let binary_request: ZkProviderOperationRequest = DecodeOptions::new()
        .with_recursion_limit(FIXTURE_RECURSION_LIMIT)
        .with_max_message_size(MAX_ZK_PROTO_MESSAGE_BYTES)
        .with_unknown_field_limit(FIXTURE_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(ARTIFACT_OPERATION_PROTOBUF)
        .unwrap();
    let json_request: ZkProviderOperationRequest =
        zk_proto_from_json(ARTIFACT_OPERATION_PROTOJSON).unwrap();
    assert_eq!(json_request, binary_request);
    let mut encoded_request = Vec::new();
    json_request
        .try_encode_bounded(
            u32::try_from(MAX_ZK_PROTO_MESSAGE_BYTES).unwrap(),
            &mut encoded_request,
        )
        .unwrap();
    assert_eq!(encoded_request, ARTIFACT_OPERATION_PROTOBUF);

    let binary_response: ZkProviderOperationResponse = DecodeOptions::new()
        .with_recursion_limit(FIXTURE_RECURSION_LIMIT)
        .with_max_message_size(MAX_ZK_PROTO_MESSAGE_BYTES)
        .with_unknown_field_limit(FIXTURE_UNKNOWN_FIELD_LIMIT)
        .decode_from_slice(BACKEND_UNAVAILABLE_PROTOBUF)
        .unwrap();
    let json_response: ZkProviderOperationResponse =
        zk_proto_from_json(BACKEND_UNAVAILABLE_PROTOJSON).unwrap();
    assert_eq!(json_response, binary_response);
    let mut encoded_response = Vec::new();
    json_response
        .try_encode_bounded(
            u32::try_from(MAX_ZK_PROTO_MESSAGE_BYTES).unwrap(),
            &mut encoded_response,
        )
        .unwrap();
    assert_eq!(encoded_response, BACKEND_UNAVAILABLE_PROTOBUF);
}

#[test]
fn malicious_protojson_fixtures_fail_closed() {
    let duplicate =
        include_bytes!("../../proto/tests/fixtures/protojson/malicious-duplicate-field.json");
    let unknown_enum =
        include_bytes!("../../proto/tests/fixtures/protojson/malicious-unknown-enum.json");

    assert_eq!(
        zk_proto_from_json::<ZkProviderOperationRequest>(duplicate),
        Err(ZkProtoJsonError::JsonDeserialize)
    );
    assert_eq!(
        zk_proto_from_json::<ZkProviderOperationRequest>(unknown_enum),
        Err(ZkProtoJsonError::JsonDeserialize)
    );
}

#[test]
fn generic_protojson_cannot_bypass_binary_only_proving_policy() {
    let secret_json = br#"{"proveClaimProofBundle":{"witnessBundle":{"stageWitnesses":[]}}}"#;
    assert_eq!(
        zk_proto_from_json::<ZkProviderOperationRequest>(secret_json),
        Err(ZkProtoJsonError::SecretOperationUnsupported)
    );

    let mut deeply_nested_secret_json = String::from("{\"proveStage\":");
    deeply_nested_secret_json.extend(std::iter::repeat_n('[', 1_000));
    deeply_nested_secret_json.push('0');
    deeply_nested_secret_json.extend(std::iter::repeat_n(']', 1_000));
    deeply_nested_secret_json.push('}');
    assert_eq!(
        zk_proto_from_json::<ZkProviderOperationRequest>(deeply_nested_secret_json.as_bytes()),
        Err(ZkProtoJsonError::SecretOperationUnsupported)
    );

    let secret_request = ZkProviderOperationRequest {
        operation: Some(Operation::ProveClaimProofBundle(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    assert_eq!(
        zk_proto_to_json(&secret_request).err(),
        Some(ZkProtoJsonError::SecretOperationUnsupported)
    );
    assert_eq!(
        zk_proto_to_json(&ZkProviderOperationRequest::default()).err(),
        Some(ZkProtoJsonError::JsonSerialize)
    );
}

#[test]
fn release_stage_witness_protojson_round_trips() -> Result<(), ZkProtoJsonError> {
    let request = ZkProviderOperationRequest {
        operation: Some(Operation::ReleaseStageWitness(Box::default())),
        __buffa_unknown_fields: Default::default(),
    };
    let json = zk_proto_to_json(&request)?;
    let decoded = zk_proto_from_json::<ZkProviderOperationRequest>(json.as_bytes())?;
    assert_eq!(decoded, request);
    Ok(())
}
