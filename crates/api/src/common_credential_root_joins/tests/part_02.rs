// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#[test]
fn stage_salt_owner_dispenses_each_salt_bearing_slot_once(
) -> Result<(), ZkCommonCredentialRootJoinGenerationError> {
    let root = [0x55; 32];
    let attestation_id = [0x44; 32];
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: TRANSACTION,
    };
    let mut rng = FixedRng { byte: 0x6a };
    let material = derive_common_credential_root_presentation_material(
        &mut rng,
        derivation_inputs(&root, &attestation_id, request),
    )?;
    let mut owner = material.into_stage_salt_owner();

    for slot in [
        ZkCommonCredentialRootProofSlot::RootAttestation,
        ZkCommonCredentialRootProofSlot::RootStatus,
        ZkCommonCredentialRootProofSlot::Lineage0,
        ZkCommonCredentialRootProofSlot::Lineage1,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
        ZkCommonCredentialRootProofSlot::SelectedClaim1,
    ] {
        let mut destination = [0_u8; 32];
        assert!(owner
            .copy_for_stage_witness(slot, request, &mut destination)
            .is_ok());
        assert_eq!(destination, [0x6a; 32]);
    }

    let mut destination = [0_u8; 32];
    assert!(matches!(
        owner.copy_for_stage_witness(
            ZkCommonCredentialRootProofSlot::Session,
            request,
            &mut destination
        ),
        Err(ZkCommonCredentialRootStageSaltError::UnsaltedSlot)
    ));
    assert!(owner.finish().is_ok());
    Ok(())
}

#[test]
fn stage_salt_owner_rejects_reuse_wrong_binding_and_incomplete_finish(
) -> Result<(), ZkCommonCredentialRootJoinGenerationError> {
    let root = [0x55; 32];
    let attestation_id = [0x44; 32];
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: TRANSACTION,
    };
    let mut rng = FixedRng { byte: 0x6a };
    let material = derive_common_credential_root_presentation_material(
        &mut rng,
        derivation_inputs(&root, &attestation_id, request),
    )?;
    let mut owner = material.into_stage_salt_owner();
    let mut destination = [0_u8; 32];

    let mut wrong_request = request;
    wrong_request.challenge = [0x12; 32];
    assert!(matches!(
        owner.copy_for_stage_witness(
            ZkCommonCredentialRootProofSlot::RootAttestation,
            wrong_request,
            &mut destination
        ),
        Err(ZkCommonCredentialRootStageSaltError::BindingMismatch)
    ));
    assert!(owner
        .copy_for_stage_witness(
            ZkCommonCredentialRootProofSlot::RootAttestation,
            request,
            &mut destination,
        )
        .is_ok());
    assert!(matches!(
        owner.copy_for_stage_witness(
            ZkCommonCredentialRootProofSlot::RootAttestation,
            request,
            &mut destination,
        ),
        Err(ZkCommonCredentialRootStageSaltError::ReusedSlot)
    ));
    assert!(matches!(
        owner.finish(),
        Err(ZkCommonCredentialRootStageSaltError::Incomplete)
    ));
    Ok(())
}

#[test]
fn stage_input_composer_emits_typed_slots_and_one_shot_salts(
) -> Result<(), ZkCommonCredentialRootJoinGenerationError> {
    let root = [0x55; 32];
    let attestation_id = [0x44; 32];
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: TRANSACTION,
    };
    let mut rng = FixedRng { byte: 0x6a };
    let material = derive_common_credential_root_presentation_material(
        &mut rng,
        derivation_inputs(&root, &attestation_id, request),
    )?;
    let joins = material.joins();
    let mut composer = material.into_stage_input_composer();

    for slot in ZkCommonCredentialRootProofSlot::ALL {
        let mut input = match composer.compose_stage(*slot) {
            Ok(input) => input,
            Err(error) => {
                assert_eq!(
                    error,
                    super::ZkCommonCredentialRootStageInputError::Salt {
                        reason: ZkCommonCredentialRootStageSaltError::Incomplete
                    }
                );
                return Ok(());
            }
        };
        assert_eq!(input.slot(), *slot);
        assert!(input.request() == request);
        match &mut input {
            ZkCommonCredentialRootStageInputMaterial::RootAttestation(stage)
            | ZkCommonCredentialRootStageInputMaterial::RootStatus(stage) => {
                assert!(stage.request() == request);
                assert_eq!(stage.root_join(), joins.root_join);
                assert_eq!(stage.attestation_join(), joins.attestation_join);
                assert_root_join_salt_once(stage);
            }
            ZkCommonCredentialRootStageInputMaterial::Lineage(stage) => {
                assert_eq!(
                    (stage.slot(), stage.credential_index()),
                    match *slot {
                        ZkCommonCredentialRootProofSlot::Lineage0 =>
                            (ZkCommonCredentialRootProofSlot::Lineage0, 0),
                        ZkCommonCredentialRootProofSlot::Lineage1 =>
                            (ZkCommonCredentialRootProofSlot::Lineage1, 1),
                        _ => (*slot, usize::MAX),
                    }
                );
                assert!(stage.request() == request);
                assert_eq!(stage.root_join(), joins.root_join);
                assert_eq!(
                    stage.subject_join(),
                    joins.subject_joins[stage.credential_index()]
                );
                assert_lineage_join_salt_once(stage);
            }
            ZkCommonCredentialRootStageInputMaterial::SelectedClaim(stage) => {
                assert_eq!(
                    (stage.slot(), stage.credential_index()),
                    match *slot {
                        ZkCommonCredentialRootProofSlot::SelectedClaim0 => {
                            (ZkCommonCredentialRootProofSlot::SelectedClaim0, 0)
                        }
                        ZkCommonCredentialRootProofSlot::SelectedClaim1 => {
                            (ZkCommonCredentialRootProofSlot::SelectedClaim1, 1)
                        }
                        _ => (*slot, usize::MAX),
                    }
                );
                assert!(stage.request() == request);
                assert_eq!(
                    stage.subject_join(),
                    joins.subject_joins[stage.credential_index()]
                );
                assert_selected_claim_join_salt_once(stage);
            }
            ZkCommonCredentialRootStageInputMaterial::Session(stage) => {
                assert!(stage.request() == request);
            }
            ZkCommonCredentialRootStageInputMaterial::IssuerCredentialStatus(stage) => {
                assert!(stage.request() == request);
                assert_eq!(stage.slot(), *slot);
                assert_eq!(
                    stage.credential_index(),
                    if *slot == ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 {
                        0
                    } else {
                        1
                    }
                );
            }
        }
    }

    assert!(composer.finish().is_ok());
    Ok(())
}

#[test]
fn stage_input_composer_rejects_reuse_and_incomplete_finish(
) -> Result<(), ZkCommonCredentialRootJoinGenerationError> {
    let root = [0x55; 32];
    let attestation_id = [0x44; 32];
    let request = ZkCommonCredentialRootRequestJoinContext {
        challenge: CHALLENGE,
        audience_hash: AUDIENCE,
        transaction_data_hash: TRANSACTION,
    };
    let mut rng = FixedRng { byte: 0x6a };
    let material = derive_common_credential_root_presentation_material(
        &mut rng,
        derivation_inputs(&root, &attestation_id, request),
    )?;
    let mut composer = material.into_stage_input_composer();
    assert!(composer
        .compose_stage(ZkCommonCredentialRootProofSlot::RootAttestation)
        .is_ok());
    assert!(matches!(
        composer.compose_stage(ZkCommonCredentialRootProofSlot::RootAttestation),
        Err(super::ZkCommonCredentialRootStageInputError::Salt {
            reason: ZkCommonCredentialRootStageSaltError::ReusedSlot
        })
    ));
    assert!(matches!(
        composer.finish(),
        Err(super::ZkCommonCredentialRootStageInputError::Salt {
            reason: ZkCommonCredentialRootStageSaltError::Incomplete
        })
    ));
    Ok(())
}

fn assert_root_join_salt_once(stage: &mut super::ZkCommonCredentialRootRootStageInput) {
    let mut destination = [0_u8; 32];
    assert!(stage.copy_join_salt_once(&mut destination).is_ok());
    assert_eq!(destination, [0x6a; 32]);
    assert!(matches!(
        stage.copy_join_salt_once(&mut destination),
        Err(ZkCommonCredentialRootStageSaltError::ReusedSlot)
    ));
}

fn assert_lineage_join_salt_once(stage: &mut super::ZkCommonCredentialRootLineageStageInput) {
    let mut destination = [0_u8; 32];
    assert!(stage.copy_join_salt_once(&mut destination).is_ok());
    assert_eq!(destination, [0x6a; 32]);
    assert!(matches!(
        stage.copy_join_salt_once(&mut destination),
        Err(ZkCommonCredentialRootStageSaltError::ReusedSlot)
    ));
}

fn assert_selected_claim_join_salt_once(
    stage: &mut super::ZkCommonCredentialRootSelectedClaimStageInput,
) {
    let mut destination = [0_u8; 32];
    assert!(stage.copy_join_salt_once(&mut destination).is_ok());
    assert_eq!(destination, [0x6a; 32]);
    assert!(matches!(
        stage.copy_join_salt_once(&mut destination),
        Err(ZkCommonCredentialRootStageSaltError::ReusedSlot)
    ));
}
