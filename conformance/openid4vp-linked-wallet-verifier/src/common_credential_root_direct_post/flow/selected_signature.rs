// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkSensitiveProviderRequest;

use crate::error::HarnessError;

use super::{dispatch::dispatch_success, PlatformContextGuard};

pub(super) fn expect_selected_issuer_signature_substitutions_reject(
    context: &PlatformContextGuard,
    request: &pb::ZkProviderOperationRequest,
) -> Result<(), HarnessError> {
    for mutation in [
        SelectedIssuerSignatureSubstitution::RootBinding,
        SelectedIssuerSignatureSubstitution::SubjectBinding,
    ] {
        let mut mutated = request.clone();
        substitute_selected_issuer_signature(&mut mutated, mutation)?;
        if dispatch_success(context, ZkSensitiveProviderRequest::new(mutated)).is_ok() {
            return Err(HarnessError::InvalidPresentationAccepted);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum SelectedIssuerSignatureSubstitution {
    RootBinding,
    SubjectBinding,
}

fn substitute_selected_issuer_signature(
    request: &mut pb::ZkProviderOperationRequest,
    substitution: SelectedIssuerSignatureSubstitution,
) -> Result<(), HarnessError> {
    let operation = match request.operation.as_mut() {
        Some(
            pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                operation,
            ),
        ) => operation.as_mut(),
        _ => return Err(HarnessError::MissingField),
    };
    match substitution {
        SelectedIssuerSignatureSubstitution::RootBinding => {
            let replacement = lineage_root_binding_signature(
                operation
                    .lineage_1
                    .as_option()
                    .ok_or(HarnessError::MissingField)?,
            )?;
            let target = lineage_root_binding_signature_mut(
                operation
                    .lineage_0
                    .as_option_mut()
                    .ok_or(HarnessError::MissingField)?,
            )?;
            target.value = replacement;
        }
        SelectedIssuerSignatureSubstitution::SubjectBinding => {
            let replacement = selected_claim_subject_binding_signature(
                operation
                    .selected_claim_1
                    .as_option()
                    .ok_or(HarnessError::MissingField)?,
            )?;
            let target = selected_claim_subject_binding_signature_mut(
                operation
                    .selected_claim_0
                    .as_option_mut()
                    .ok_or(HarnessError::MissingField)?,
            )?;
            target.value = replacement;
        }
    }
    Ok(())
}

fn lineage_root_binding_signature(
    stage: &pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<Vec<u8>, HarnessError> {
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(input)) =
        stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    Ok(input
        .witness
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .issuer_root_binding_signature
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value
        .clone())
}

fn lineage_root_binding_signature_mut(
    stage: &mut pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<&mut pb::ZkInputBytes64, HarnessError> {
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(input)) =
        stage.input.as_mut()
    else {
        return Err(HarnessError::MissingField);
    };
    input
        .witness
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?
        .issuer_root_binding_signature
        .as_option_mut()
        .ok_or(HarnessError::MissingField)
}

fn selected_claim_subject_binding_signature(
    stage: &pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<Vec<u8>, HarnessError> {
    match stage.input.as_ref() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => Ok(input
            .link
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .issuer_subject_binding_signature
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .value
            .clone()),
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaClaim(
            input,
        )) => Ok(input
            .link
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .issuer_subject_binding_signature
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .value
            .clone()),
        _ => Err(HarnessError::MissingField),
    }
}

fn selected_claim_subject_binding_signature_mut(
    stage: &mut pb::ZkCommonCredentialRootStageProveOperation,
) -> Result<&mut pb::ZkInputBytes64, HarnessError> {
    match stage.input.as_mut() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(
            input,
        )) => input
            .link
            .as_option_mut()
            .ok_or(HarnessError::MissingField)?
            .issuer_subject_binding_signature
            .as_option_mut()
            .ok_or(HarnessError::MissingField),
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::PublicPersonaClaim(
            input,
        )) => input
            .link
            .as_option_mut()
            .ok_or(HarnessError::MissingField)?
            .issuer_subject_binding_signature
            .as_option_mut()
            .ok_or(HarnessError::MissingField),
        _ => Err(HarnessError::MissingField),
    }
}
