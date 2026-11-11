// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Common-credential-root proof composition, joins, commitments, and assurance.

pub use crate::common_credential_root::{
    ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot,
    ZkCommonCredentialRootRawPublicInputs, ZkCommonCredentialRootSourceStage,
    COMMON_CREDENTIAL_ROOT_V1_CLAIM_ENCODING, COMMON_CREDENTIAL_ROOT_V1_MAX_RAW_PUBLIC_INPUT_BYTES,
    COMMON_CREDENTIAL_ROOT_V1_PROOF_COUNT,
};
pub use crate::common_credential_root_active_set::{
    ZkCommonCredentialRootActiveSet, ZkCommonCredentialRootActiveSetError,
    ZkCommonCredentialRootActiveSetOpening, ZkCommonCredentialRootActiveSetReason,
};
pub use crate::common_credential_root_active_status::{
    verify_common_credential_root_active_status_membership,
    ZkCommonCredentialRootActiveStatusError, ZkCommonCredentialRootActiveStatusReason,
    COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH, COMMON_CREDENTIAL_ROOT_V1_STATUS_LEAVES,
};
pub use crate::common_credential_root_attestation::{
    ZkRootAssuranceAttestation, ZkRootAssuranceAttestationError, ZkRootAssuranceAttestationReason,
};
pub use crate::common_credential_root_claim_commitment::{
    build_common_credential_root_poseidon2_claims_commitment,
    build_common_credential_root_sha256_claims_commitment,
    verify_common_credential_root_poseidon2_issuer_claims_root,
    verify_common_credential_root_sha256_issuer_claims_root,
    ZkCommonCredentialRootApprovedIssuerRoot, ZkCommonCredentialRootClaim,
    ZkCommonCredentialRootClaimCommitmentError, ZkCommonCredentialRootClaimCommitmentReason,
    ZkCommonCredentialRootClaimOpening, ZkCommonCredentialRootClaimsCommitment,
};
pub use crate::common_credential_root_credential_binding::{
    derive_common_credential_root_credential_binding, ZkCommonCredentialRootCredentialBindingInputs,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use crate::common_credential_root_holder_assurance::{
    ZkCommonCredentialRootHolderAssurance, ZkCommonCredentialRootHolderAssuranceError,
    ZkCommonCredentialRootHolderAssuranceReason,
};
pub use crate::common_credential_root_issuer_status::{
    common_credential_root_issuer_status_opening, common_credential_root_issuer_status_root,
    verify_common_credential_root_issuer_status_opening, ZkCommonCredentialRootIssuerStatusError,
    ZkCommonCredentialRootIssuerStatusOpening, ZkCommonCredentialRootIssuerStatusReason,
    COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_CHUNK_BYTES,
    COMMON_CREDENTIAL_ROOT_ISSUER_STATUS_MAX_DEPTH,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use crate::common_credential_root_joins::verify_common_credential_root_attestation_material;
pub use crate::common_credential_root_joins::{
    check_common_credential_root_v1_joins, common_credential_root_attestation_signing_digest,
    common_credential_root_root_commitment, derive_common_credential_root_attestation_id,
    derive_common_credential_root_attestation_id_from_commitment,
    derive_common_credential_root_presentation_joins,
    derive_common_credential_root_presentation_material,
    normalize_common_credential_root_p256_signature_low_s,
    ZkCommonCredentialRootAttestationCommitmentMaterial, ZkCommonCredentialRootAttestationMaterial,
    ZkCommonCredentialRootAttestationTrustPolicy, ZkCommonCredentialRootClaimExpectation,
    ZkCommonCredentialRootIssuerCredentialStatusStageInput,
    ZkCommonCredentialRootIssuerStatusExpectation, ZkCommonCredentialRootJoinDerivationInputs,
    ZkCommonCredentialRootJoinGenerationError, ZkCommonCredentialRootJoinPolicy,
    ZkCommonCredentialRootLineageStageInput, ZkCommonCredentialRootPresentationJoins,
    ZkCommonCredentialRootPresentationMaterial, ZkCommonCredentialRootPresentationSalt,
    ZkCommonCredentialRootPublicInputs, ZkCommonCredentialRootRequestJoinContext,
    ZkCommonCredentialRootRootStageInput, ZkCommonCredentialRootSelectedClaimStageInput,
    ZkCommonCredentialRootSessionStageInput, ZkCommonCredentialRootStageInputComposer,
    ZkCommonCredentialRootStageInputError, ZkCommonCredentialRootStageInputMaterial,
    ZkCommonCredentialRootStageJoinSalt, ZkCommonCredentialRootStageSaltError,
    ZkCommonCredentialRootStageSaltOwner, ZkCommonCredentialRootSubjectPublicKey,
};
pub use crate::common_credential_root_lineage::{
    derive_common_credential_root_v1_lineage, ZkCommonCredentialRootDerivedLineage,
    ZkCommonCredentialRootLineageError, ZkCommonCredentialRootLineageReason,
    ZkCommonCredentialRootPrivateLineageMaterial,
    MAX_COMMON_CREDENTIAL_ROOT_RELATIONSHIP_DID_BYTES,
};
pub use crate::common_credential_root_persona::{
    common_credential_root_poseidon2_persona_session_authorization,
    common_credential_root_poseidon2_persona_session_binding,
    common_credential_root_poseidon2_subject_persona_link,
    common_credential_root_sha256_compressed_persona_key,
    common_credential_root_sha256_persona_session_authorization,
    common_credential_root_sha256_persona_session_binding,
    common_credential_root_sha256_subject_persona_link,
};
#[cfg(any(feature = "native", feature = "wasm"))]
pub use crate::common_credential_root_status_snapshot::verify_root_status_snapshot;
pub use crate::common_credential_root_status_snapshot::{
    ZkRootStatusSnapshot, ZkRootStatusSnapshotError, ZkRootStatusSnapshotReason,
    ZkRootStatusTrustPolicy, ZkRootStatusVerificationError, ZkRootStatusVerificationReason,
    ZkVerifiedRootStatusSnapshot,
};
pub use crate::common_credential_root_verification::{
    verify_common_credential_root_with, ZkCommonCredentialRootProof,
    ZkCommonCredentialRootVerification, ZkCommonCredentialRootVerifier,
    ZkCommonCredentialRootVerifyRequest,
};
