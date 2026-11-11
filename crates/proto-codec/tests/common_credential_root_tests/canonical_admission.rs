// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Routes generated messages through the public canonical byte decoders.
//!
//! Generated-message converters are crate-private, so these helpers encode a
//! message and admit it exactly as an external caller must.

use buffa::{EnumValue, Message, MessageField};
use reallyme_zk_api::{
    common_root::ZkCommonCredentialRootPersonaMode,
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    common_credential_root::{
        decode_common_credential_root_raw_public_inputs, ZkCommonCredentialRootJoinPolicyOwner,
        ZkCommonCredentialRootPresentation, ZkCommonCredentialRootRawPublicInputPackage,
    },
    operation::{decode_operation_request, ZkProviderOperation},
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};

use super::presentation;

const REQUEST_SHA256: [u8; 32] = [7; 32];

/// Admits one raw public-input message through its canonical byte decoder.
pub(super) fn admit_raw_public_inputs(
    message: pb::ZkCommonCredentialRootRawPublicInputs,
) -> Result<ZkCommonCredentialRootRawPublicInputPackage, ZkError> {
    decode_common_credential_root_raw_public_inputs(&message.encode_to_vec())
}

/// Admits one presentation as a canonical provider success response.
pub(super) fn admit_presentation(
    message: pb::ZkCommonCredentialRootPresentation,
) -> Result<ZkCommonCredentialRootPresentation, ZkError> {
    use pb::__buffa::oneof::{
        zk_provider_operation_response::Outcome, zk_provider_operation_result::Result as Payload,
    };

    let bytes = pb::ZkProviderOperationResponse {
        outcome: Some(Outcome::Result(Box::new(pb::ZkProviderOperationResult {
            result: Some(Payload::CommonCredentialRootPresentation(Box::new(message))),
            __buffa_unknown_fields: Default::default(),
        }))),
        request_sha256: REQUEST_SHA256.to_vec(),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec();
    match decode_operation_response(&bytes)?.into_outcome() {
        ZkProviderOperationOutcome::Success(result) => match *result {
            ZkProviderOperationResult::CommonCredentialRootPresentation(presentation) => {
                Ok(*presentation)
            }
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        },
        ZkProviderOperationOutcome::Failure(_) => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}

/// Admits one join policy inside a canonical verification request.
///
/// The request carries a valid presentation so the policy under test is the
/// only component that can be rejected.
pub(super) fn admit_join_policy(
    policy: pb::ZkCommonCredentialRootJoinPolicy,
) -> Result<ZkCommonCredentialRootJoinPolicyOwner, ZkError> {
    use pb::__buffa::oneof::zk_provider_operation_request::Operation;

    let bytes = pb::ZkProviderOperationRequest {
        operation: Some(Operation::VerifyCommonCredentialRoot(Box::new(
            pb::ZkCommonCredentialRootVerifyOperation {
                presentation: MessageField::some(presentation(
                    ZkCommonCredentialRootPersonaMode::PrivatePersona,
                )),
                join_policy: MessageField::some(policy),
                expected_proof_suite: EnumValue::from(
                    pb::ZkProofSuite::ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
                __buffa_unknown_fields: Default::default(),
            },
        ))),
        __buffa_unknown_fields: Default::default(),
    }
    .encode_to_vec();
    match decode_operation_request(&bytes)? {
        ZkProviderOperation::VerifyCommonCredentialRoot { join_policy, .. } => Ok(*join_policy),
        _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
    }
}
