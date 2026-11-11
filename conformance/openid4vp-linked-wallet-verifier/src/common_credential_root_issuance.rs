// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Cryptographic SSI issuance and OpenID4VCI transport for linked ZK tests.
//!
//! The issuer signs the exact commitment root and subject key consumed by the
//! common-credential-root witnesses. No stage may retain the synthetic envelope digest
//! after transport: the wallet reconstructs and validates issuer material from
//! the Credential Response before proof generation.

use reallyme_credential::committed::proof_binding::CredentialProofBinding;
use reallyme_credential::CredentialEnvelope;
use reallyme_credential_status::StatusList;
use reallyme_identity::zk::validate_zk_common_root_issuance;
use reallyme_zk_api::common_root::{
    ZkCommonCredentialRootAttestationMaterial, ZkCommonCredentialRootAttestationTrustPolicy,
    ZkCommonCredentialRootClaimsCommitment, ZkCommonCredentialRootHolderAssurance,
    ZkCommonCredentialRootPrivateLineageMaterial, ZkVerifiedRootStatusSnapshot,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use reallyme_zk_proto_codec::operation::ZkSensitiveProviderRequest;
use zeroize::Zeroizing;

use crate::error::HarnessError;

mod binding;
mod crypto;
mod issue;
mod selected_record;
mod transport;
mod validation;

use binding::{bind_issuer_status, bind_lineage, bind_selected_claim};
use crypto::{issuance_policy, issuer_key, stage, verified_proof};
use issue::issue_and_transport_credentials_for_stage_requests;
pub(crate) use selected_record::{
    selected_record_presentation_request_from_verified_records, SelectedRecordPresentationClock,
};
pub(crate) use validation::sign_test_status_list;
use validation::{reject_revoked_and_stale_wallet_receipts, validate_wallet_receipt};

const PROFILE_ID: &str = "reallyme.zk.common-root.v1";
pub(crate) const STATUS_LIST_IDS: [[u8; 32]; 2] = [[0x55; 32], [0x56; 32]];
const STATUS_LIST_INDEX: u64 = 9;
pub(crate) const STATUS_ISSUER_URLS: [&str; 2] = [
    "https://university.example/status/1",
    "https://employer.example/status/1",
];
const ISSUER_SCALARS: [u8; 2] = [11, 17];
const SUBJECT_SCALARS: [u8; 2] = [13, 19];
const PERSONA_SCALAR: u8 = 23;
const MAX_CREDENTIAL_PROTO_BYTES: usize = 1024 * 1024;
const MAX_STATUS_PROTO_BYTES: usize = 128 * 1024;
const MAX_WIRE_PROTO_BYTES: usize = MAX_CREDENTIAL_PROTO_BYTES + MAX_STATUS_PROTO_BYTES + 1024;
const PROTO_RECURSION_LIMIT: u32 = 32;
const STATUS_PATH_SLOTS: usize = 12;

struct IssuedCredential {
    envelope: CredentialEnvelope,
    binding: CredentialProofBinding,
    status_list: StatusList,
    private_claims: ZkCommonCredentialRootClaimsCommitment,
    private_lineage: ZkCommonCredentialRootPrivateLineageMaterial,
    claim_name: String,
    claim_value: Zeroizing<Vec<u8>>,
    claim_salt: Zeroizing<[u8; 16]>,
}

pub(crate) struct TrustedCommonCredentialRootSource {
    holder: ZkCommonCredentialRootHolderAssurance,
}

impl TrustedCommonCredentialRootSource {
    pub(crate) fn new(holder: ZkCommonCredentialRootHolderAssurance) -> Self {
        Self { holder }
    }

    fn holder(&self) -> &ZkCommonCredentialRootHolderAssurance {
        &self.holder
    }

    fn root(&self) -> &[u8; 32] {
        self.holder.root()
    }
}

pub(crate) fn trusted_common_credential_root_source_from_verified_stage_requests(
    requests: &[ZkSensitiveProviderRequest],
    trust: ZkCommonCredentialRootAttestationTrustPolicy,
    snapshot: ZkVerifiedRootStatusSnapshot,
    now_unix: u64,
) -> Result<TrustedCommonCredentialRootSource, HarnessError> {
    if requests.len() != 9 {
        return Err(HarnessError::InvalidLength);
    }
    let attestation_stage = stage(&requests[0])?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(
        attestation,
    )) = attestation_stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    let status_stage = stage(&requests[1])?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(status)) =
        status_stage.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    if crypto::input32(&status.active_status_root)? != snapshot.root() {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    let stage_signer = attestation
        .reallyme_public_key
        .as_option()
        .ok_or(HarnessError::MissingField)?;
    let material_signer = reallyme_zk_api::keys::ZkAttestationPublicKey {
        x: crypto::input32(&stage_signer.x)?,
        y: crypto::input32(&stage_signer.y)?,
    };
    let root = crypto::input32(&attestation.root)?;
    let signature = crypto::input64(&attestation.attestation_signature)?;
    let material = ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: material_signer,
        assurance_policy_id: crypto::input32(&attestation.assurance_policy_id)?,
        request_time_unix: attestation.request_unix,
        root: &root,
        attestation_issued_unix: attestation.attestation_issued_unix,
        attestation_expires_unix: attestation.attestation_expires_unix,
        attestation_epoch: attestation.attestation_epoch,
        attestation_signature: &signature,
    };
    let mut siblings = Zeroizing::new(Vec::new());
    if let Some(path) = status.status_path.as_option() {
        let path_length =
            usize::try_from(path.path_length).map_err(|_| HarnessError::InvalidLength)?;
        if path_length > path.siblings.len() {
            return Err(HarnessError::InvalidLength);
        }
        siblings
            .try_reserve_exact(path_length)
            .map_err(|_| HarnessError::InvalidLength)?;
        for sibling in path.siblings.iter().take(path_length) {
            siblings.push(crypto::raw32(&sibling.value)?);
        }
    }
    let holder = ZkCommonCredentialRootHolderAssurance::admit(
        material,
        trust,
        snapshot,
        now_unix,
        status.status_index,
        siblings.as_slice(),
    )?;
    Ok(TrustedCommonCredentialRootSource::new(holder))
}

pub(crate) struct VerifiedZkStoredCredential {
    envelope: CredentialEnvelope,
    binding: CredentialProofBinding,
    status_list: StatusList,
    private_claims: ZkCommonCredentialRootClaimsCommitment,
    private_lineage_root: Zeroizing<[u8; 32]>,
    relationship_did_hash: Zeroizing<[u8; 32]>,
    relationship_nonce: Zeroizing<[u8; 32]>,
}

/// Replace both synthetic credential witnesses with independently signed SSI
/// credentials that have survived OpenID4VCI response serialization.
pub(crate) fn issue_and_transport_into_stage_requests(
    requests: &mut [ZkSensitiveProviderRequest],
    trusted_source: &TrustedCommonCredentialRootSource,
    status_validation_time: u64,
) -> Result<[StatusList; 2], HarnessError> {
    let request_time = match stage(&requests[0])?.input.as_ref() {
        Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(
            input,
        )) => input.request_unix,
        _ => return Err(HarnessError::MissingField),
    };
    let selected = issue_verified_selected_records_for_stage_requests(requests, request_time)?;
    bind_verified_selected_records_into_stage_requests(
        requests,
        selected,
        Some(trusted_source),
        request_time,
        status_validation_time,
    )
}

pub(crate) fn issue_verified_selected_records_for_stage_requests(
    requests: &[ZkSensitiveProviderRequest],
    request_time: u64,
) -> Result<[VerifiedZkStoredCredential; 2], HarnessError> {
    let (first, second) =
        issue_and_transport_credentials_for_stage_requests(requests, request_time)?;
    Ok([first, second])
}

pub(crate) fn bind_verified_selected_records_into_stage_requests(
    requests: &mut [ZkSensitiveProviderRequest],
    selected: [VerifiedZkStoredCredential; 2],
    trusted_source: Option<&TrustedCommonCredentialRootSource>,
    request_time: u64,
    status_validation_time: u64,
) -> Result<[StatusList; 2], HarnessError> {
    if requests.len() != 9 {
        return Err(HarnessError::InvalidLength);
    }
    let trusted_source = trusted_source.ok_or(HarnessError::MissingField)?;
    let [first, second] = selected;
    validate_stage_roots_against_trusted_source(requests, trusted_source)?;
    validate_wallet_receipt(&first, ISSUER_SCALARS[0], SUBJECT_SCALARS[0], request_time)?;
    validate_wallet_receipt(&second, ISSUER_SCALARS[1], SUBJECT_SCALARS[1], request_time)?;
    reject_revoked_and_stale_wallet_receipts(
        &first,
        ISSUER_SCALARS[0],
        SUBJECT_SCALARS[0],
        request_time,
    )?;
    reject_revoked_and_stale_wallet_receipts(
        &second,
        ISSUER_SCALARS[1],
        SUBJECT_SCALARS[1],
        request_time,
    )?;
    if first.private_lineage_root.as_ref() != trusted_source.root().as_slice()
        || second.private_lineage_root.as_ref() != trusted_source.root().as_slice()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    // A valid signature on a different credential cannot be substituted for
    // the material issued to this subject or committed claim root.
    let first_proof = verified_proof(&first.binding)?;
    let policy = issuance_policy(first.envelope.status.status_list_id);
    if validate_zk_common_root_issuance(
        &first.envelope,
        &first_proof,
        &second.binding,
        issuer_key(&first.binding),
        policy,
    )
    .is_ok()
    {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    let mut statuses = Vec::new();
    statuses
        .try_reserve_exact(2)
        .map_err(|_| HarnessError::InvalidLength)?;
    for (lineage_index, claim_index, status_index, issued) in [(2, 4, 7, first), (3, 5, 8, second)]
    {
        bind_lineage(
            &mut requests[lineage_index],
            &issued.binding,
            issued.private_claims.openings(),
        )?;
        bind_selected_claim(
            &mut requests[claim_index],
            &issued.binding,
            issued.private_claims.openings(),
        )?;
        bind_issuer_status(&mut requests[status_index], &issued, status_validation_time)?;
        statuses.push(issued.status_list);
    }
    statuses.try_into().map_err(|_| HarnessError::InvalidLength)
}

fn validate_stage_roots_against_trusted_source(
    requests: &[ZkSensitiveProviderRequest],
    trusted_source: &TrustedCommonCredentialRootSource,
) -> Result<(), HarnessError> {
    let attestation = stage(&requests[0])?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootAttestation(input)) =
        attestation.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    if crypto::input32(&input.root)? != *trusted_source.root() {
        return Err(HarnessError::InvalidPresentationAccepted);
    }

    let status = stage(&requests[1])?;
    let Some(pb::zk_common_credential_root_stage_prove_operation::Input::RootStatus(input)) =
        status.input.as_ref()
    else {
        return Err(HarnessError::MissingField);
    };
    if crypto::input32(&input.root)? != *trusted_source.root() {
        return Err(HarnessError::InvalidPresentationAccepted);
    }
    Ok(())
}
