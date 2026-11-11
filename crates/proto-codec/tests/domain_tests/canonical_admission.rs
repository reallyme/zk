// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Routes generated messages through the public canonical byte decoders.
//!
//! Generated-message converters are crate-private, so these helpers encode a
//! message and admit it exactly as an external caller must.

use buffa::Message;
use reallyme_zk_api::{
    claim_bundle::ZkClaimProofBundle,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_artifacts::ProductionArtifactManifest;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1::{
    __buffa::oneof::{
        zk_provider_operation_response::Outcome, zk_provider_operation_result::Result as Payload,
    },
    ZkArtifactManifest, ZkClaimProofBundle as ProtoClaimProofBundle, ZkError as ProtoZkError,
    ZkProviderOperationResponse, ZkProviderOperationResult,
};
use reallyme_zk_proto_codec::{
    artifact::decode_artifact_manifest,
    result::{
        decode_operation_response, ZkProviderOperationOutcome,
        ZkProviderOperationResult as DomainResult,
    },
};

const REQUEST_SHA256: [u8; 32] = [7; 32];

fn response_bytes(outcome: Outcome) -> Vec<u8> {
    ZkProviderOperationResponse {
        outcome: Some(outcome),
        request_sha256: REQUEST_SHA256.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec()
}

/// Admits one artifact manifest through its canonical byte decoder.
pub(super) fn admit_artifact_manifest(
    manifest: ZkArtifactManifest,
) -> Result<ProductionArtifactManifest, ZkError> {
    decode_artifact_manifest(&manifest.encode_to_vec())
}

/// Admits one claim proof bundle as a canonical provider success response.
pub(super) fn admit_claim_proof_bundle(
    bundle: ProtoClaimProofBundle,
) -> Result<ZkClaimProofBundle, ZkError> {
    let bytes = response_bytes(Outcome::Result(Box::new(ZkProviderOperationResult {
        result: Some(Payload::ClaimProofBundle(Box::new(bundle))),
        __buffa_unknown_fields: Default::default(),
    })));
    match decode_operation_response(&bytes)?.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            DomainResult::ClaimProofBundle(bundle) => Ok(bundle),
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

/// Admits one structured error as a canonical provider failure response.
pub(super) fn admit_error(error: ProtoZkError) -> Result<ZkError, ZkError> {
    let bytes = response_bytes(Outcome::Error(Box::new(error)));
    match decode_operation_response(&bytes)?.into_outcome() {
        ZkProviderOperationOutcome::Failure(error) => Ok(error),
        ZkProviderOperationOutcome::Success(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}
