// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Bounded Buffa ProtoJSON for the approved public ZK message surface.

use std::io::{Error as IoError, ErrorKind as IoErrorKind, Write};

use buffa::Message;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use serde::de::DeserializeOwned;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Maximum accepted or generated ProtoJSON at the canonical ZK boundary.
///
/// Production proofs are approximately 15 KiB and complete bundles remain
/// well below this ceiling. Keeping this boundary small prevents Serde's
/// in-memory representation from amplifying a large attacker-controlled JSON
/// document before the protobuf budget can be applied.
pub const MAX_ZK_PROTO_JSON_BYTES: usize = 2 * 1024 * 1024;

/// Maximum protobuf encoding admitted after ProtoJSON deserialization.
pub const MAX_ZK_PROTO_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
const MAX_JSON_NESTING_DEPTH: usize = 64;
const MAX_JSON_CONTAINER_ELEMENTS: usize = 4 * 1024;
const MAX_JSON_TOTAL_VALUES: usize = 64 * 1024;

mod budget;
use budget::preflight_json_budget;

/// Stable, privacy-safe ProtoJSON boundary failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ZkProtoJsonError {
    /// The JSON representation exceeds the configured resource ceiling.
    #[error("ZK ProtoJSON exceeds the configured size limit")]
    JsonTooLarge,
    /// Generated ProtoJSON deserialization rejected the input.
    #[error("ZK ProtoJSON decoding failed")]
    JsonDeserialize,
    /// Generated ProtoJSON serialization failed.
    #[error("ZK ProtoJSON encoding failed")]
    JsonSerialize,
    /// The decoded message exceeds the canonical protobuf ceiling.
    #[error("ZK protobuf exceeds the configured size limit")]
    ProtobufTooLarge,
    /// The message would transport witness-bearing proving material as JSON.
    #[error("ZK proving operations require binary protobuf transport")]
    SecretOperationUnsupported,
}

mod private {
    use super::ZkProtoJsonError;

    pub trait Sealed {
        fn validate_json_input(_json: &[u8]) -> Result<(), ZkProtoJsonError> {
            Ok(())
        }

        fn validate_json_output(&self) -> Result<(), ZkProtoJsonError> {
            Ok(())
        }
    }
}

/// Generated ZK messages approved for the public ProtoJSON boundary.
///
/// The trait is sealed so unrelated Serde types cannot be mistaken for
/// schema-owned ZK DTOs at SDK, service, or package boundaries.
/// Proof-bearing verification-vector sets are intentionally binary-only:
///
/// ```compile_fail
/// let vectors = reallyme_zk_proto::generated::proto::reallyme::zk::v1::ZkVerificationVectorSet::default();
/// let _ = reallyme_zk_proto_codec::protojson::zk_proto_to_json(&vectors);
/// ```
pub trait ZkProtoJson: Message + serde::Serialize + DeserializeOwned + private::Sealed {}

macro_rules! impl_zk_proto_json {
    ($($message:path),+ $(,)?) => {
        $(
            impl private::Sealed for $message {}
            impl ZkProtoJson for $message {}
        )+
    };
}

impl_zk_proto_json!(
    pb::ZkArtifactManifest,
    pb::ZkCapabilityRegistry,
    pb::ZkProofPackage,
    pb::ZkClaimProofBundle,
    pb::ZkVerification,
    pb::ZkError,
    pb::ZkProviderOperationResponse,
    pb::ZkReleaseIndex,
);

impl private::Sealed for pb::ZkProviderOperationRequest {
    fn validate_json_input(json: &[u8]) -> Result<(), ZkProtoJsonError> {
        enforce_operation_request_json_policy(json)
    }

    fn validate_json_output(&self) -> Result<(), ZkProtoJsonError> {
        use pb::zk_provider_operation_request::Operation;

        match self.operation.as_ref() {
            Some(
                Operation::ProveClaimProofBundle(_)
                | Operation::ProveRetainedClaimProofBundle(_)
                | Operation::ProveStage(_)
                | Operation::WitnessStage(_)
                | Operation::ProveCommonCredentialRootStage(_)
                | Operation::ProveCommonCredentialRootPresentation(_)
                | Operation::ProvePersonaCredentialEvidenceStage(_)
                | Operation::ProvePersonaCredentialEvidenceCurrentState(_)
                | Operation::ProvePersonaCredentialEvidenceIssuerEnvelope(_)
                | Operation::ProvePersonaCredentialEvidenceClaimRoot(_)
                | Operation::ProvePersonaCredentialEvidenceSignedValidity(_)
                | Operation::ProvePersonaCredentialEvidenceSelectedClaim(_)
                | Operation::PreparePersonaCredentialEvidencePresentationSigning(_)
                | Operation::AssemblePersonaCredentialEvidencePresentation(_),
            ) => Err(ZkProtoJsonError::SecretOperationUnsupported),
            Some(
                Operation::VerifyClaimProofBundle(_)
                | Operation::VerifyStatusQualifiedClaimProofBundle(_)
                | Operation::VerifyStage(_)
                | Operation::GetArtifactManifest(_)
                | Operation::ReleaseStageWitness(_)
                | Operation::VerifyCommonCredentialRoot(_)
                | Operation::VerifyPersonaCredentialEvidenceStage(_),
            ) => Ok(()),
            None => Err(ZkProtoJsonError::JsonSerialize),
        }
    }
}

impl ZkProtoJson for pb::ZkProviderOperationRequest {}

struct BoundedJsonWriter {
    bytes: Zeroizing<Vec<u8>>,
    exact_length: usize,
}

impl BoundedJsonWriter {
    fn with_exact_length(exact_length: usize) -> Result<Self, ZkProtoJsonError> {
        if exact_length > MAX_ZK_PROTO_JSON_BYTES {
            return Err(ZkProtoJsonError::JsonTooLarge);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(exact_length)
            .map_err(|_| ZkProtoJsonError::JsonSerialize)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
            exact_length,
        })
    }

    fn into_string(mut self) -> Result<Zeroizing<String>, ZkProtoJsonError> {
        match String::from_utf8(core::mem::take(&mut *self.bytes)) {
            Ok(json) => Ok(Zeroizing::new(json)),
            Err(error) => {
                let mut invalid_bytes = error.into_bytes();
                invalid_bytes.zeroize();
                Err(ZkProtoJsonError::JsonSerialize)
            }
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| IoError::from(IoErrorKind::InvalidData))?;
        if next_len > self.exact_length {
            return Err(IoError::from(IoErrorKind::InvalidData));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct CountingJsonWriter {
    length: usize,
}

impl Write for CountingJsonWriter {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        self.length = self
            .length
            .checked_add(input.len())
            .ok_or_else(|| IoError::from(IoErrorKind::InvalidData))?;
        if self.length > MAX_ZK_PROTO_JSON_BYTES {
            return Err(IoError::from(IoErrorKind::InvalidData));
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn require_bounded_protobuf<M: Message>(message: &M) -> Result<(), ZkProtoJsonError> {
    let maximum = u32::try_from(MAX_ZK_PROTO_MESSAGE_BYTES)
        .map_err(|_| ZkProtoJsonError::ProtobufTooLarge)?;
    let encoded_len = message
        .try_encoded_len()
        .map_err(|_| ZkProtoJsonError::ProtobufTooLarge)?;
    if encoded_len > maximum {
        return Err(ZkProtoJsonError::ProtobufTooLarge);
    }
    let encoded_len =
        usize::try_from(encoded_len).map_err(|_| ZkProtoJsonError::ProtobufTooLarge)?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| ZkProtoJsonError::ProtobufTooLarge)?;
    message
        .try_encode_bounded(maximum, &mut *encoded)
        .map(|_| ())
        .map_err(|_| ZkProtoJsonError::ProtobufTooLarge)
}

/// Serializes an approved generated ZK message using bounded Buffa ProtoJSON.
///
/// The returned string owns its allocation through `Zeroizing` because proofs,
/// public inputs, session bindings, and error-adjacent DTOs may be sensitive.
pub fn zk_proto_to_json<M: ZkProtoJson>(
    message: &M,
) -> Result<Zeroizing<String>, ZkProtoJsonError> {
    <M as private::Sealed>::validate_json_output(message)?;
    require_bounded_protobuf(message)?;
    let mut counter = CountingJsonWriter { length: 0 };
    serde_json::to_writer(&mut counter, message).map_err(|_| ZkProtoJsonError::JsonSerialize)?;
    let mut writer = BoundedJsonWriter::with_exact_length(counter.length)?;
    serde_json::to_writer(&mut writer, message).map_err(|_| ZkProtoJsonError::JsonSerialize)?;
    if writer.bytes.len() != counter.length {
        return Err(ZkProtoJsonError::JsonSerialize);
    }
    writer.into_string()
}

/// Deserializes one approved generated ZK message using Buffa ProtoJSON.
///
/// Unknown fields, duplicate oneof selections, unknown enum names, and invalid
/// base64 are rejected by the hardened generated implementation. A bounded
/// protobuf encode after parsing prevents a compact JSON document from
/// materializing an oversized protobuf message.
pub fn zk_proto_from_json<M: ZkProtoJson>(json: &[u8]) -> Result<M, ZkProtoJsonError> {
    if json.len() > MAX_ZK_PROTO_JSON_BYTES {
        return Err(ZkProtoJsonError::JsonTooLarge);
    }
    // Reject secret-bearing operations before the structural scanner retains
    // any copy of their JSON tokens in ordinary allocations.
    <M as private::Sealed>::validate_json_input(json)?;
    preflight_json_budget(json)?;
    let message: M = serde_json::from_slice(json).map_err(|_| ZkProtoJsonError::JsonDeserialize)?;
    require_bounded_protobuf(&message)?;
    let canonical = zk_proto_to_json(&message)?;
    let canonical_input = match json.strip_suffix(b"\n") {
        Some(without_line_feed) => without_line_feed,
        None => json,
    };
    if canonical.as_bytes() != canonical_input {
        return Err(ZkProtoJsonError::JsonDeserialize);
    }
    Ok(message)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonOperationPolicy {
    Allowed,
    SecretBearing,
}

fn enforce_operation_request_json_policy(bytes: &[u8]) -> Result<(), ZkProtoJsonError> {
    if bytes.len() > MAX_ZK_PROTO_JSON_BYTES {
        return Err(ZkProtoJsonError::JsonTooLarge);
    }

    let mut cursor = skip_json_whitespace(bytes, 0)?;
    if bytes.get(cursor) != Some(&b'{') {
        return Err(ZkProtoJsonError::JsonDeserialize);
    }
    cursor = skip_json_whitespace(bytes, advance_json_cursor(cursor)?)?;
    if bytes.get(cursor) != Some(&b'"') {
        return Err(ZkProtoJsonError::JsonDeserialize);
    }

    let key_start = advance_json_cursor(cursor)?;
    cursor = key_start;
    while let Some(byte) = bytes.get(cursor) {
        match byte {
            b'"' => break,
            b'\\' | 0x00..=0x1f => return Err(ZkProtoJsonError::JsonDeserialize),
            _ => cursor = advance_json_cursor(cursor)?,
        }
    }
    if bytes.get(cursor) != Some(&b'"') {
        return Err(ZkProtoJsonError::JsonDeserialize);
    }

    let policy = classify_json_operation(&bytes[key_start..cursor])
        .ok_or(ZkProtoJsonError::JsonDeserialize)?;
    if policy == JsonOperationPolicy::SecretBearing {
        return Err(ZkProtoJsonError::SecretOperationUnsupported);
    }

    cursor = skip_json_whitespace(bytes, advance_json_cursor(cursor)?)?;
    if bytes.get(cursor) != Some(&b':') {
        return Err(ZkProtoJsonError::JsonDeserialize);
    }
    ensure_single_top_level_member(bytes, advance_json_cursor(cursor)?)
}

fn ensure_single_top_level_member(bytes: &[u8], mut cursor: usize) -> Result<(), ZkProtoJsonError> {
    let mut nested_depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;

    while let Some(byte) = bytes.get(cursor) {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            } else if *byte <= 0x1f {
                return Err(ZkProtoJsonError::JsonDeserialize);
            }
            cursor = advance_json_cursor(cursor)?;
            continue;
        }

        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                nested_depth = nested_depth
                    .checked_add(1)
                    .ok_or(ZkProtoJsonError::JsonDeserialize)?;
            }
            b'}' if nested_depth == 0 => {
                cursor = skip_json_whitespace(bytes, advance_json_cursor(cursor)?)?;
                return if cursor == bytes.len() {
                    Ok(())
                } else {
                    Err(ZkProtoJsonError::JsonDeserialize)
                };
            }
            b'}' | b']' => {
                nested_depth = nested_depth
                    .checked_sub(1)
                    .ok_or(ZkProtoJsonError::JsonDeserialize)?;
            }
            b',' if nested_depth == 0 => return Err(ZkProtoJsonError::JsonDeserialize),
            _ => {}
        }
        cursor = advance_json_cursor(cursor)?;
    }

    Err(ZkProtoJsonError::JsonDeserialize)
}

fn classify_json_operation(key: &[u8]) -> Option<JsonOperationPolicy> {
    match key {
        b"verifyClaimProofBundle"
        | b"verifyStage"
        | b"getArtifactManifest"
        | b"releaseStageWitness" => Some(JsonOperationPolicy::Allowed),
        b"proveClaimProofBundle"
        | b"proveRetainedClaimProofBundle"
        | b"proveStage"
        | b"witnessStage"
        | b"proveCommonCredentialRootStage"
        | b"proveCommonCredentialRootPresentation"
        | b"provePersonaCredentialEvidenceStage"
        | b"provePersonaCredentialEvidenceCurrentState"
        | b"preparePersonaCredentialEvidencePresentationSigning"
        | b"assemblePersonaCredentialEvidencePresentation" => {
            Some(JsonOperationPolicy::SecretBearing)
        }
        _ => None,
    }
}

fn advance_json_cursor(cursor: usize) -> Result<usize, ZkProtoJsonError> {
    cursor
        .checked_add(1)
        .ok_or(ZkProtoJsonError::JsonDeserialize)
}

fn skip_json_whitespace(bytes: &[u8], mut cursor: usize) -> Result<usize, ZkProtoJsonError> {
    while matches!(bytes.get(cursor), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        cursor = advance_json_cursor(cursor)?;
    }
    Ok(cursor)
}

#[cfg(test)]
mod tests;
