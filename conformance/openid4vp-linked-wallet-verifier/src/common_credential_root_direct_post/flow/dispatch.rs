// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use buffa::{Message, MessageField};
use reallyme_zk_api::common_root::ZkCommonCredentialRootProofSlot;
use reallyme_zk_platform_ffi::reallyme_zk_platform_dispatch;
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::{
    common_credential_root::ZkCommonCredentialRootPresentation,
    operation::ZkSensitiveProviderRequest,
    platform_abi::{
        reallyme_zk_platform_buffer_destroy, ReallyMeZkPlatformBuffer,
        REALLYME_ZK_PLATFORM_STATUS_OK,
    },
    result::{decode_operation_response, ZkProviderOperationOutcome, ZkProviderOperationResult},
};
use zeroize::Zeroizing;

use crate::error::HarnessError;

use super::PlatformContextGuard;

pub(super) fn prove_common_credential_root_presentation(
    context: &PlatformContextGuard,
    requests: &[ZkSensitiveProviderRequest],
) -> Result<ZkCommonCredentialRootPresentation, HarnessError> {
    let operation = complete_common_credential_root_presentation_operation(requests)?;
    let result = dispatch_success(context, ZkSensitiveProviderRequest::new(operation))?;
    match result {
        ZkProviderOperationResult::CommonCredentialRootPresentation(presentation) => {
            Ok(*presentation)
        }
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}

fn complete_common_credential_root_presentation_operation(
    requests: &[ZkSensitiveProviderRequest],
) -> Result<pb::ZkProviderOperationRequest, HarnessError> {
    if requests.len() != ZkCommonCredentialRootProofSlot::ALL.len() {
        return Err(HarnessError::InvalidLength);
    }
    let root_attestation = stage(requests, 0)?;
    let root_status = stage(requests, 1)?;
    let lineage_0 = stage(requests, 2)?;
    let lineage_1 = stage(requests, 3)?;
    let selected_claim_0 = stage(requests, 4)?;
    let selected_claim_1 = stage(requests, 5)?;
    let session = stage(requests, 6)?;
    let issuer_credential_status_0 = stage(requests, 7)?;
    let issuer_credential_status_1 = stage(requests, 8)?;
    Ok(pb::ZkProviderOperationRequest {
        operation: Some(
            pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                Box::new(pb::ZkCommonCredentialRootPresentationProveOperation {
                    persona_mode: root_attestation.persona_mode,
                    proof_suite: root_attestation.proof_suite,
                    expected_binding: root_attestation.expected_binding.clone(),
                    root_attestation: MessageField::some(root_attestation),
                    root_status: MessageField::some(root_status),
                    lineage_0: MessageField::some(lineage_0),
                    lineage_1: MessageField::some(lineage_1),
                    selected_claim_0: MessageField::some(selected_claim_0),
                    selected_claim_1: MessageField::some(selected_claim_1),
                    session: MessageField::some(session),
                    issuer_credential_status_0: MessageField::some(issuer_credential_status_0),
                    issuer_credential_status_1: MessageField::some(issuer_credential_status_1),
                    __buffa_unknown_fields: Default::default(),
                }),
            ),
        ),
        __buffa_unknown_fields: Default::default(),
    })
}

fn stage(
    requests: &[ZkSensitiveProviderRequest],
    index: usize,
) -> Result<pb::ZkCommonCredentialRootStageProveOperation, HarnessError> {
    let request = requests.get(index).ok_or(HarnessError::InvalidLength)?;
    match request.request().operation.as_ref() {
        Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
            stage,
        )) => Ok((**stage).clone()),
        _ => Err(HarnessError::MissingField),
    }
}

pub(super) fn common_credential_root_presentation_expiry(
    requests: &[ZkSensitiveProviderRequest],
) -> Result<u64, HarnessError> {
    let root_attestation = stage(requests, 0)?;
    match root_attestation.input.as_ref() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(
            input,
        )) => Ok(input
            .presentation
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .expiry_unix),
        _ => Err(HarnessError::MissingField),
    }
}

pub(super) fn dispatch_success(
    context: &PlatformContextGuard,
    request: ZkSensitiveProviderRequest,
) -> Result<ZkProviderOperationResult, HarnessError> {
    let request = Zeroizing::new(request.request().encode_to_vec());
    let result =
        unsafe { reallyme_zk_platform_dispatch(context.as_ptr(), request.as_ptr(), request.len()) };
    let output = PlatformOutputGuard::new(result.output);
    if result.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    let buffer = output.as_buffer()?;
    if buffer.ptr.is_null() || buffer.len == 0 {
        return Err(HarnessError::MissingField);
    }
    let response_bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
    let outcome = decode_operation_response(response_bytes)
        .map_err(|_| HarnessError::InvalidLength)?
        .into_outcome();
    let destroy_status = output.destroy()?;
    if destroy_status.status_code != REALLYME_ZK_PLATFORM_STATUS_OK {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    match outcome {
        ZkProviderOperationOutcome::Success(result) => Ok(*result),
        ZkProviderOperationOutcome::Failure(error) => Err(HarnessError::Zk(error)),
    }
}

struct PlatformOutputGuard {
    buffer: Option<ReallyMeZkPlatformBuffer>,
}

impl PlatformOutputGuard {
    const fn new(buffer: ReallyMeZkPlatformBuffer) -> Self {
        Self {
            buffer: Some(buffer),
        }
    }

    fn as_buffer(&self) -> Result<&ReallyMeZkPlatformBuffer, HarnessError> {
        self.buffer.as_ref().ok_or(HarnessError::MissingField)
    }

    fn destroy(
        mut self,
    ) -> Result<reallyme_zk_proto_codec::platform_abi::ReallyMeZkPlatformStatus, HarnessError> {
        let buffer = self.buffer.take().ok_or(HarnessError::MissingField)?;
        Ok(unsafe { reallyme_zk_platform_buffer_destroy(buffer) })
    }
}

impl Drop for PlatformOutputGuard {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let _status = unsafe { reallyme_zk_platform_buffer_destroy(buffer) };
        }
    }
}
