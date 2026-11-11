// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use super::{fixture_io::repo_root, CommonCredentialRootFixture};
use crate::{
    common_credential_root_issuance::{
        bind_verified_selected_records_into_stage_requests,
        issue_and_transport_into_stage_requests,
        issue_verified_selected_records_for_stage_requests,
        trusted_common_credential_root_source_from_verified_stage_requests,
    },
    common_credential_root_stage_builder::common_credential_root_stage_requests_for_verified,
    error::HarnessError,
};
use buffa::{DecodeOptions, Message, MessageField};
use reallyme_credential_status::{StatusList, StatusListSignature};
use reallyme_zk_api::{
    common_root::{
        common_credential_root_issuer_status_root, ZkCommonCredentialRootAttestationTrustPolicy,
    },
    errors::ZkErrorReason,
    proofs::ZkSessionBinding,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::{
    decode_operation_request, ZkProviderOperation, ZkSensitiveProviderRequest,
};

#[test]
fn issued_credentials_admit_exact_signed_status_roots() -> Result<(), HarnessError> {
    let root = repo_root()?;
    let fixture_root = root.join("circuits");
    let fixture = CommonCredentialRootFixture::read_from(&fixture_root)?;
    let stage_root = root.join("vectors/common-credential-root-stage-requests-v1");
    let template = std::fs::read(stage_root.join("sha256-private-6.pb"))?;
    let template = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(&template)
        .map_err(|_| HarnessError::InvalidLength)?;
    let Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(stage)) =
        template.operation.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaSession(
        session,
    )) = stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let presentation = session
        .session_context
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let binding = ZkSessionBinding {
        nonce_hash: presentation
            .challenge
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_| HarnessError::InvalidLength)?,
        audience_hash: presentation
            .audience_hash
            .as_option()
            .ok_or(HarnessError::MissingField)?
            .value
            .as_slice()
            .try_into()
            .map_err(|_| HarnessError::InvalidLength)?,
        transaction_data_hash: Some(
            presentation
                .transaction_data_hash
                .as_option()
                .ok_or(HarnessError::MissingField)?
                .value
                .as_slice()
                .try_into()
                .map_err(|_| HarnessError::InvalidLength)?,
        ),
    };
    let stage_requests = common_credential_root_stage_requests_for_verified(&stage_root, binding);
    assert!(
        stage_requests.is_ok(),
        "stage binding: {:?}",
        stage_requests.as_ref().err()
    );
    let mut requests = stage_requests?;
    let now_unix = fixture.verification_time()?;
    let trusted_status = fixture.verified_status_snapshot(now_unix)?;
    let trusted_source = trusted_common_credential_root_source_from_verified_stage_requests(
        &requests,
        attestation_trust(&fixture),
        trusted_status,
        now_unix,
    )?;
    let issued = issue_and_transport_into_stage_requests(&mut requests, &trusted_source, now_unix);
    assert!(
        issued.is_ok(),
        "issuance boundary: {:?}",
        issued.as_ref().err()
    );
    let lists = issued?;
    let policy = fixture.verification_policy(&lists, now_unix);
    assert!(
        policy.is_ok(),
        "status trust boundary: {:?}",
        policy.as_ref().err()
    );
    let expected = policy?.issuer_status_expectations(now_unix)?;
    for (list, admitted) in lists.iter().zip(expected.iter()) {
        let root = common_credential_root_issuer_status_root(&list.encoded_list, list.length)
            .map_err(|_| HarnessError::InvalidPresentationAccepted)?;
        if root != admitted.root || list.length != admitted.length {
            return Err(HarnessError::InvalidPresentationAccepted);
        }
    }
    let mut forged = [copy_public_status(&lists[0]), copy_public_status(&lists[1])];
    let first_byte = forged[0]
        .encoded_list
        .first_mut()
        .ok_or(HarnessError::InvalidLength)?;
    *first_byte ^= 1;
    assert!(fixture.verification_policy(&forged, now_unix).is_err());
    let swapped = [copy_public_status(&lists[1]), copy_public_status(&lists[0])];
    assert!(fixture.verification_policy(&swapped, now_unix).is_err());
    Ok(())
}

#[test]
fn live_selected_records_compose_a_complete_common_credential_root_presentation(
) -> Result<(), HarnessError> {
    let root = repo_root()?;
    let fixture_root = root.join("circuits");
    let fixture = CommonCredentialRootFixture::read_from(&fixture_root)?;
    let stage_root = root.join("vectors/common-credential-root-stage-requests-v1");
    let binding = session_binding_from_stage_template(&stage_root)?;
    let mut requests = common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    let now_unix = fixture.verification_time()?;
    let trusted_status = fixture.verified_status_snapshot(now_unix)?;
    let trusted_source = trusted_common_credential_root_source_from_verified_stage_requests(
        &requests,
        attestation_trust(&fixture),
        trusted_status,
        now_unix,
    )?;
    let _lists = issue_and_transport_into_stage_requests(&mut requests, &trusted_source, now_unix)?;
    let operation = complete_common_credential_root_presentation_operation(&requests)?;
    let encoded = operation.encode_to_vec();
    let decoded = decode_operation_request(&encoded)?;
    let ZkProviderOperation::ProveCommonCredentialRootPresentation {
        expected_binding,
        stages,
        ..
    } = decoded
    else {
        return Err(HarnessError::InvalidPresentationAccepted);
    };
    if expected_binding != binding || stages.len() != 9 {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    let mut replayed = complete_common_credential_root_presentation_operation(&requests)?;
    presentation_operation_mut(&mut replayed)?
        .expected_binding
        .get_or_insert_default()
        .nonce_hash[0] ^= 1;
    assert_zk_reason(
        decode_operation_request(&replayed.encode_to_vec()),
        ZkErrorReason::BindingMismatch,
    )?;

    let mut missing_selected_material =
        complete_common_credential_root_presentation_operation(&requests)?;
    presentation_operation_mut(&mut missing_selected_material)?
        .selected_claim_1
        .take();
    assert_zk_reason(
        decode_operation_request(&missing_selected_material.encode_to_vec()),
        ZkErrorReason::MissingStage,
    )?;
    Ok(())
}

#[test]
fn live_selected_records_require_trusted_root_source() -> Result<(), HarnessError> {
    let root = repo_root()?;
    let fixture_root = root.join("circuits");
    let fixture = CommonCredentialRootFixture::read_from(&fixture_root)?;
    let stage_root = root.join("vectors/common-credential-root-stage-requests-v1");
    let binding = session_binding_from_stage_template(&stage_root)?;
    let requests = common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    let root_attestation = stage(&requests, 0)?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(input)) =
        root_attestation.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let request_time = input.request_unix;
    let now_unix = fixture.verification_time()?;
    let trusted_status = fixture.verified_status_snapshot(now_unix)?;
    let trusted_source = trusted_common_credential_root_source_from_verified_stage_requests(
        &requests,
        attestation_trust(&fixture),
        trusted_status,
        now_unix,
    )?;

    let selected = issue_verified_selected_records_for_stage_requests(&requests, request_time)?;
    let mut missing_trust_requests =
        common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    match bind_verified_selected_records_into_stage_requests(
        &mut missing_trust_requests,
        selected,
        None,
        request_time,
        now_unix,
    ) {
        Err(HarnessError::MissingField) => {}
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }

    let selected = issue_verified_selected_records_for_stage_requests(&requests, request_time)?;
    let mut wrong_trust_requests =
        common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    forge_root_attestation_stage_root(&mut wrong_trust_requests)?;
    match bind_verified_selected_records_into_stage_requests(
        &mut wrong_trust_requests,
        selected,
        Some(&trusted_source),
        request_time,
        now_unix,
    ) {
        Err(HarnessError::InvalidPresentationAccepted) => {}
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }

    let mut forged_signer_requests =
        common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    forge_root_attestation_signer(&mut forged_signer_requests)?;
    match trusted_common_credential_root_source_from_verified_stage_requests(
        &forged_signer_requests,
        attestation_trust(&fixture),
        trusted_status,
        now_unix,
    ) {
        Err(HarnessError::HolderAssurance(_)) => {}
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }

    let mut forged_stage_root_requests =
        common_credential_root_stage_requests_for_verified(&stage_root, binding)?;
    forge_root_attestation_stage_root(&mut forged_stage_root_requests)?;
    match issue_and_transport_into_stage_requests(
        &mut forged_stage_root_requests,
        &trusted_source,
        now_unix,
    ) {
        Err(HarnessError::InvalidPresentationAccepted) => {}
        _ => return Err(HarnessError::InvalidPresentationAccepted),
    }
    Ok(())
}

fn copy_public_status(list: &StatusList) -> StatusList {
    StatusList {
        issuer: list.issuer.clone(),
        purpose: list.purpose,
        issued_at: list.issued_at,
        next_update: list.next_update,
        encoded_list: list.encoded_list.clone(),
        length: list.length,
        list_id: list.list_id,
        signature: StatusListSignature {
            alg: list.signature.alg,
            sig_bytes: list.signature.sig_bytes.clone(),
        },
    }
}

fn attestation_trust(
    fixture: &CommonCredentialRootFixture,
) -> ZkCommonCredentialRootAttestationTrustPolicy {
    ZkCommonCredentialRootAttestationTrustPolicy {
        signer: fixture.attestation_signer,
        assurance_policy_id: fixture.assurance_policy_id,
    }
}

fn session_binding_from_stage_template(
    stage_root: &std::path::Path,
) -> Result<ZkSessionBinding, HarnessError> {
    let template = std::fs::read(stage_root.join("sha256-private-6.pb"))?;
    let template = DecodeOptions::new()
        .decode_from_slice::<pb::ZkProviderOperationRequest>(&template)
        .map_err(|_| HarnessError::InvalidLength)?;
    let Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(stage)) =
        template.operation.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaSession(
        session,
    )) = stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let presentation = session
        .session_context
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    Ok(ZkSessionBinding {
        nonce_hash: bytes32(&presentation.challenge)?,
        audience_hash: bytes32(&presentation.audience_hash)?,
        transaction_data_hash: Some(bytes32(&presentation.transaction_data_hash)?),
    })
}

fn complete_common_credential_root_presentation_operation(
    requests: &[ZkSensitiveProviderRequest],
) -> Result<pb::ZkProviderOperationRequest, HarnessError> {
    if requests.len() != 9 {
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

fn presentation_operation_mut(
    request: &mut pb::ZkProviderOperationRequest,
) -> Result<&mut pb::ZkCommonCredentialRootPresentationProveOperation, HarnessError> {
    match request.operation.as_mut() {
        Some(
            pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootPresentation(
                operation,
            ),
        ) => Ok(operation.as_mut()),
        _ => Err(HarnessError::MissingField),
    }
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

fn forge_root_attestation_stage_root(
    requests: &mut [ZkSensitiveProviderRequest],
) -> Result<(), HarnessError> {
    let input = root_attestation_input_mut(requests)?;
    let root = input
        .root
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    let byte = root.value.first_mut().ok_or(HarnessError::InvalidLength)?;
    *byte ^= 1;
    Ok(())
}

fn forge_root_attestation_signer(
    requests: &mut [ZkSensitiveProviderRequest],
) -> Result<(), HarnessError> {
    let input = root_attestation_input_mut(requests)?;
    let signer = input
        .reallyme_public_key
        .as_option_mut()
        .ok_or(HarnessError::MissingField)?;
    let x = signer.x.as_option_mut().ok_or(HarnessError::MissingField)?;
    let byte = x.value.first_mut().ok_or(HarnessError::InvalidLength)?;
    *byte ^= 1;
    Ok(())
}

fn root_attestation_input_mut(
    requests: &mut [ZkSensitiveProviderRequest],
) -> Result<&mut pb::ZkCommonCredentialRootAttestationInput, HarnessError> {
    let request = requests.get_mut(0).ok_or(HarnessError::InvalidLength)?;
    match request.request_mut().operation.as_mut() {
        Some(pb::zk_provider_operation_request::Operation::ProveCommonCredentialRootStage(
            stage,
        )) => match stage.input.as_mut() {
            Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(
                input,
            )) => Ok(input),
            _ => Err(HarnessError::MissingField),
        },
        _ => Err(HarnessError::MissingField),
    }
}

fn bytes32(
    field: &MessageField<pb::ZkInputBytes32, buffa::Inline<pb::ZkInputBytes32>>,
) -> Result<[u8; 32], HarnessError> {
    field
        .as_option()
        .ok_or(HarnessError::MissingField)?
        .value
        .as_slice()
        .try_into()
        .map_err(|_| HarnessError::InvalidLength)
}

fn assert_zk_reason(
    result: Result<ZkProviderOperation, reallyme_zk_api::errors::ZkError>,
    expected: ZkErrorReason,
) -> Result<(), HarnessError> {
    match result {
        Err(error) if error.reason() == expected => Ok(()),
        _ => Err(HarnessError::InvalidPresentationAccepted),
    }
}
