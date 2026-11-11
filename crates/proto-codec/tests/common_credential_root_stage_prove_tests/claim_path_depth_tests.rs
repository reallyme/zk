// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every claim tree has a fixed depth, so common-credential-root lineage and
//! selected-claim stage inputs are admitted only with a full-depth path.

use buffa::MessageField;
use reallyme_zk_api::{
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::{ZkError, ZkErrorReason},
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::{decode_operation_request, ZkProviderOperation};

use super::{common_credential_root_stage_request, input_bytes32, input_presentation};

const CLAIM_TREE_DEPTH: u32 = 6;

fn input_bytes64(byte: u8) -> pb::ZkInputBytes64 {
    pb::ZkInputBytes64 {
        value: vec![byte; 64],
        __buffa_unknown_fields: Default::default(),
    }
}

fn input_key(byte: u8) -> pb::ZkInputP256PublicKey {
    pb::ZkInputP256PublicKey {
        x: MessageField::some(input_bytes32(byte)),
        y: MessageField::some(input_bytes32(byte.wrapping_add(1))),
        __buffa_unknown_fields: Default::default(),
    }
}

fn claim_path(path_length: u32, sibling_count: usize) -> pb::ZkInputMerklePath {
    pb::ZkInputMerklePath {
        path_length,
        siblings: vec![input_bytes32(0x51); sibling_count],
        __buffa_unknown_fields: Default::default(),
    }
}

fn lineage_input(
    path_length: u32,
    sibling_count: usize,
) -> pb::zk_common_credential_root_stage_prove_operation::Input {
    pb::zk_common_credential_root_stage_prove_operation::Input::Lineage(Box::new(
        pb::ZkCommonCredentialRootLineageInput {
            presentation: MessageField::some(input_presentation()),
            root_join: MessageField::some(input_bytes32(4)),
            slot: MessageField::some(pb::ZkInputCommonCredentialRootLineageSlot {
                issuer_public_key: MessageField::some(input_key(5)),
                expiry_unix: 1_800_000_120,
                credential_binding: MessageField::some(input_bytes32(7)),
                subject_join: MessageField::some(input_bytes32(8)),
                __buffa_unknown_fields: Default::default(),
            }),
            root: MessageField::some(input_bytes32(9)),
            join_salt: MessageField::some(input_bytes32(10)),
            witness: MessageField::some(pb::ZkInputCommonCredentialRootLineageWitness {
                envelope_hash: MessageField::some(input_bytes32(11)),
                merkle_root: MessageField::some(input_bytes32(12)),
                issuer_root_binding_signature: MessageField::some(input_bytes64(13)),
                subject_public_key: MessageField::some(input_key(14)),
                relationship_did_hash: MessageField::some(input_bytes32(16)),
                relationship_nonce: MessageField::some(input_bytes32(17)),
                claim_salt: MessageField::some(pb::ZkInputBytes16 {
                    value: vec![18; 16],
                    __buffa_unknown_fields: Default::default(),
                }),
                merkle_leaf_index: 0,
                merkle_path: MessageField::some(claim_path(path_length, sibling_count)),
                __buffa_unknown_fields: Default::default(),
            }),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

fn private_persona_claim_input(
    path_length: u32,
    sibling_count: usize,
) -> pb::zk_common_credential_root_stage_prove_operation::Input {
    let mut value = vec![0_u8; 64];
    value[0] = 0x61;
    pb::zk_common_credential_root_stage_prove_operation::Input::PrivatePersonaClaim(Box::new(
        pb::ZkCommonCredentialRootPrivatePersonaClaimInput {
            issuer_context: MessageField::some(pb::ZkInputIssuerContext {
                issuer_public_key: MessageField::some(input_key(5)),
                challenge: MessageField::some(input_bytes32(1)),
                audience_hash: MessageField::some(input_bytes32(2)),
                expiry_unix: 1_800_000_120,
                transaction_data_hash: MessageField::some(input_bytes32(3)),
                __buffa_unknown_fields: Default::default(),
            }),
            session_binding: MessageField::some(input_bytes32(4)),
            subject_join: MessageField::some(input_bytes32(8)),
            disclosure: MessageField::some(pb::ZkInputClaimDisclosure {
                credential_binding: MessageField::some(input_bytes32(7)),
                value_length: 1,
                value: MessageField::some(pb::ZkInputBytes64 {
                    value,
                    __buffa_unknown_fields: Default::default(),
                }),
                claim_name_hash: MessageField::some(input_bytes32(19)),
                __buffa_unknown_fields: Default::default(),
            }),
            proof: MessageField::some(pb::ZkInputMerkleClaimProof {
                envelope_hash: MessageField::some(input_bytes32(11)),
                merkle_root: MessageField::some(input_bytes32(12)),
                claim_salt: MessageField::some(pb::ZkInputBytes16 {
                    value: vec![18; 16],
                    __buffa_unknown_fields: Default::default(),
                }),
                leaf_index: 0,
                path: MessageField::some(claim_path(path_length, sibling_count)),
                __buffa_unknown_fields: Default::default(),
            }),
            link: MessageField::some(pb::ZkInputPersonaClaimLink {
                issuer_subject_binding_signature: MessageField::some(input_bytes64(20)),
                subject_public_key: MessageField::some(input_key(14)),
                persona_public_key: MessageField::some(input_key(21)),
                subject_link_signature: MessageField::some(input_bytes64(23)),
                __buffa_unknown_fields: Default::default(),
            }),
            join_salt: MessageField::some(input_bytes32(10)),
            __buffa_unknown_fields: Default::default(),
        },
    ))
}

type StageInputBuilder =
    fn(u32, usize) -> pb::zk_common_credential_root_stage_prove_operation::Input;

const CLAIM_PATH_STAGES: [(StageInputBuilder, ZkCommonCredentialRootProofSlot); 2] = [
    (lineage_input, ZkCommonCredentialRootProofSlot::Lineage0),
    (
        private_persona_claim_input,
        ZkCommonCredentialRootProofSlot::SelectedClaim0,
    ),
];

fn admission(
    build: StageInputBuilder,
    slot: ZkCommonCredentialRootProofSlot,
    path_length: u32,
    sibling_count: usize,
) -> Result<Result<ZkProviderOperation, ZkErrorReason>, ZkError> {
    let encoded = common_credential_root_stage_request(
        build(path_length, sibling_count),
        ZkCommonCredentialRootPersonaMode::PrivatePersona,
        slot,
    )?;
    Ok(decode_operation_request(encoded.as_slice()).map_err(|error| error.reason()))
}

#[test]
fn claim_path_stages_admit_the_fixed_claim_tree_depth() -> Result<(), ZkError> {
    for (build, slot) in CLAIM_PATH_STAGES {
        assert!(matches!(
            admission(build, slot, CLAIM_TREE_DEPTH, 6)?,
            Ok(ZkProviderOperation::ProveCommonCredentialRootStage { .. })
        ));
    }
    Ok(())
}

#[test]
fn claim_path_stages_reject_short_claim_paths() -> Result<(), ZkError> {
    for (build, slot) in CLAIM_PATH_STAGES {
        for (path_length, sibling_count) in [(0_u32, 0_usize), (1, 1), (5, 5)] {
            assert!(matches!(
                admission(build, slot, path_length, sibling_count)?,
                Err(ZkErrorReason::InvalidProofEncoding)
            ));
        }
    }
    Ok(())
}

#[test]
fn claim_path_stages_reject_over_depth_claim_paths() -> Result<(), ZkError> {
    for (build, slot) in CLAIM_PATH_STAGES {
        for (path_length, sibling_count) in [(7_u32, 7_usize), (7, 6), (6, 7)] {
            assert!(matches!(
                admission(build, slot, path_length, sibling_count)?,
                Err(ZkErrorReason::ClaimPayloadTooLarge)
            ));
        }
    }
    Ok(())
}

#[test]
fn claim_path_stages_require_declared_length_and_siblings_to_agree() -> Result<(), ZkError> {
    for (build, slot) in CLAIM_PATH_STAGES {
        for (path_length, sibling_count) in [(6_u32, 5_usize), (5, 6), (6, 0), (0, 6)] {
            assert!(matches!(
                admission(build, slot, path_length, sibling_count)?,
                Err(ZkErrorReason::InvalidProofEncoding)
            ));
        }
    }
    Ok(())
}
