// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_credential_status::{
    CredentialStatusError, StatusList, StatusListAlgorithm, StatusListFreshnessPolicy,
    StatusListVerifier, StatusPurpose,
};
use reallyme_openid4vp_types::AuthorizationRequestObject;
use reallyme_openid4vp_verifier::{
    SessionRecord, VerifiedDisclosureSet, VerifierError, VerifierErrorReason,
    ZkCommonCredentialRootTrustPolicy, ZkCommonCredentialRootVerificationPolicy,
    ZkIssuerStatusRollbackFloor, ZkIssuerStatusTrust, ZkRootStatusRollbackFloor,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path, sync::Mutex};

use reallyme_crypto::p256;
use reallyme_openid4vp_wallet::{
    WalletCommonCredentialRootPresentation, WalletCommonCredentialRootProof,
};
use reallyme_zk_api::{
    artifacts::ZkArtifactIdentity,
    circuits::ZkCredentialHashAlgorithm,
    common_root::{
        verify_root_status_snapshot, ZkCommonCredentialRootPersonaMode,
        ZkCommonCredentialRootProofSlot, ZkCommonCredentialRootRawPublicInputs,
        ZkRootStatusTrustPolicy, ZkVerifiedRootStatusSnapshot,
    },
    keys::{ZkAttestationPublicKey, ZkIssuerPublicKey},
    proofs::{ZkProofBytes, ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_proto_codec::common_credential_root::ZkCommonCredentialRootRawProofPackage;
use serde_json::json;
use toml::Value as TomlValue;
use zeroize::Zeroizing;

use super::COMMON_CREDENTIAL_ROOT_LANE;

const CLAIM_VALUE_BYTES: usize = 64;
use crate::{
    common_credential_root_issuance::STATUS_ISSUER_URLS, direct_post::session_record,
    error::HarnessError, fixture::lower_hex,
};

mod fixture_io;
mod platform_context;

pub(super) use fixture_io::common_credential_root_release_root;
use fixture_io::{
    common_credential_root_fixture_root, read_toml, toml_bytes, toml_bytes32, toml_u32, toml_u64,
};
pub(super) use platform_context::PlatformContextGuard;

struct HarnessIssuerStatusVerifier {
    issuer: &'static str,
    public_key: Vec<u8>,
}

impl HarnessIssuerStatusVerifier {
    fn new(scalar: u8, issuer: &'static str) -> Result<Self, HarnessError> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        secret[31] = scalar;
        let (public_key, _) =
            reallyme_crypto::p256::generate_p256_keypair_from_secret_key(&secret)?;
        Ok(Self { issuer, public_key })
    }
}

impl StatusListVerifier for HarnessIssuerStatusVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer != self.issuer || alg != StatusListAlgorithm::P256 {
            return Err(CredentialStatusError::InvalidSignature);
        }
        let signature = p256::p256_ecdsa_jose_signature_to_der(signature)
            .map_err(|_| CredentialStatusError::InvalidSignature)?;
        let digest = Sha256::digest(payload);
        let digest = crypto_p256::P256Sha256Digest::new(digest.into());
        crypto_p256::verify_p256_sha256_digest_low_s_der(&signature, &digest, &self.public_key)
            .map_err(|_| CredentialStatusError::InvalidSignature)
    }
}

// A conformance-only floor retains accepted list revisions across the several
// verifier calls in this process. Deployments supply a durable floor.
#[derive(Default)]
struct HarnessStatusFloor {
    seen: Mutex<StatusFloorEntries>,
}

type StatusFloorEntries = BTreeMap<[u8; 32], (u64, [u8; 32])>;

#[derive(Default)]
struct HarnessRootStatusFloor {
    seen: Mutex<RootStatusFloorEntries>,
}

type RootStatusFloorEntries = BTreeMap<[u8; 32], (u64, [u8; 32])>;

pub(super) struct CommonCredentialRootPolicyOverrides {
    pub status_root: [u8; 32],
    pub attestation_signer: ZkAttestationPublicKey,
    pub assurance_policy_id: [u8; 32],
    pub expires_unix: u64,
    pub policy_build_time_unix: u64,
}

impl ZkIssuerStatusRollbackFloor for HarnessStatusFloor {
    fn admit_verified(
        &self,
        list_key: [u8; 32],
        issued_at: u64,
        payload_sha256: [u8; 32],
    ) -> Result<(), VerifierError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidCredentialStatus))?;
        if let Some((prior_time, prior_digest)) = seen.get(&list_key) {
            if issued_at < *prior_time
                || (issued_at == *prior_time && payload_sha256 != *prior_digest)
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::InvalidCredentialStatus,
                ));
            }
        }
        seen.insert(list_key, (issued_at, payload_sha256));
        Ok(())
    }
}

impl ZkRootStatusRollbackFloor for HarnessRootStatusFloor {
    fn admit_verified(
        &self,
        feed_id: [u8; 32],
        sequence: u64,
        signing_digest: [u8; 32],
    ) -> Result<(), VerifierError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| VerifierError::new(VerifierErrorReason::InvalidRootAssuranceStatus))?;
        if let Some((prior_sequence, prior_digest)) = seen.get(&feed_id) {
            if sequence < *prior_sequence
                || (sequence == *prior_sequence && signing_digest != *prior_digest)
            {
                return Err(VerifierError::new(
                    VerifierErrorReason::InvalidRootAssuranceStatus,
                ));
            }
        }
        seen.insert(feed_id, (sequence, signing_digest));
        Ok(())
    }
}

pub(super) struct HarnessCommonCredentialRootProof(ZkCommonCredentialRootRawProofPackage);

impl WalletCommonCredentialRootProof for HarnessCommonCredentialRootProof {
    fn slot(&self) -> ZkCommonCredentialRootProofSlot {
        self.0.slot()
    }

    fn artifact_identity(&self) -> ZkArtifactIdentity {
        self.0.artifact_identity()
    }

    fn proof_bytes(&self) -> &ZkProofBytes {
        self.0.proof_bytes()
    }

    fn public_inputs(&self) -> &ZkCommonCredentialRootRawPublicInputs {
        self.0.public_inputs()
    }
}

pub(super) struct HarnessCommonCredentialRootPresentation {
    persona_mode: ZkCommonCredentialRootPersonaMode,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    session_binding: ZkSessionBinding,
    pub(super) proofs: Vec<HarnessCommonCredentialRootProof>,
    pub(super) issuer_status_lists: [StatusList; 2],
}

impl HarnessCommonCredentialRootPresentation {
    pub(super) fn try_new(
        proofs: Vec<ZkCommonCredentialRootRawProofPackage>,
        session_binding: ZkSessionBinding,
        issuer_status_lists: [StatusList; 2],
    ) -> Result<Self, HarnessError> {
        Self::try_new_profile(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCredentialHashAlgorithm::Sha256,
            proofs,
            session_binding,
            issuer_status_lists,
        )
    }

    pub(super) fn try_new_profile(
        persona_mode: ZkCommonCredentialRootPersonaMode,
        credential_hash_algorithm: ZkCredentialHashAlgorithm,
        proofs: Vec<ZkCommonCredentialRootRawProofPackage>,
        session_binding: ZkSessionBinding,
        issuer_status_lists: [StatusList; 2],
    ) -> Result<Self, HarnessError> {
        let mut wrapped = Vec::new();
        wrapped
            .try_reserve_exact(proofs.len())
            .map_err(|_| HarnessError::InvalidLength)?;
        for proof in proofs {
            wrapped.push(HarnessCommonCredentialRootProof(proof));
        }
        Ok(Self {
            persona_mode,
            credential_hash_algorithm,
            session_binding,
            proofs: wrapped,
            issuer_status_lists,
        })
    }
}

impl WalletCommonCredentialRootPresentation for HarnessCommonCredentialRootPresentation {
    type Proof = HarnessCommonCredentialRootProof;

    fn persona_mode(&self) -> ZkCommonCredentialRootPersonaMode {
        self.persona_mode
    }

    fn credential_hash_algorithm(&self) -> ZkCredentialHashAlgorithm {
        self.credential_hash_algorithm
    }

    fn proof_suite(&self) -> ZkProofSuite {
        ZkProofSuite::PRODUCTION
    }

    fn session_binding(&self) -> ZkSessionBinding {
        self.session_binding
    }

    fn proofs(&self) -> &[Self::Proof] {
        self.proofs.as_slice()
    }
}

pub(crate) struct CommonCredentialRootFixture {
    pub(super) request_time_unix: u64,
    pub(super) attestation_signer: ZkAttestationPublicKey,
    pub(super) assurance_policy_id: [u8; 32],
    pub(super) status_root: [u8; 32],
    pub(super) first_claim: CommonCredentialRootClaimFixture,
    pub(super) second_claim: CommonCredentialRootClaimFixture,
    root_status_floor: HarnessRootStatusFloor,
    status_floor: HarnessStatusFloor,
}

impl CommonCredentialRootFixture {
    pub(super) fn read() -> Result<Self, HarnessError> {
        Self::read_from(&common_credential_root_fixture_root()?)
    }

    fn read_from(fixture_root: &Path) -> Result<Self, HarnessError> {
        let root = fixture_root
            .join(COMMON_CREDENTIAL_ROOT_LANE)
            .join("families/common_credential_root_v1");
        let attestation = read_toml(root.join("root_attestation/Prover.toml"))?;
        let status = read_toml(root.join("root_status/Prover.toml"))?;
        let claim_root = root.join("private_persona_claim");
        let first_claim =
            CommonCredentialRootClaimFixture::read(&read_toml(claim_root.join("Prover.toml"))?)?;
        let second_claim = CommonCredentialRootClaimFixture::read(&read_toml(
            claim_root.join("ProverEmployer.toml"),
        )?)?;
        Ok(Self {
            request_time_unix: toml_u64(&attestation, "request_unix")?,
            attestation_signer: ZkAttestationPublicKey {
                x: toml_bytes32(&attestation, "reallyme_x")?,
                y: toml_bytes32(&attestation, "reallyme_y")?,
            },
            assurance_policy_id: toml_bytes32(&attestation, "assurance_policy_id")?,
            status_root: toml_bytes32(&status, "active_status_root")?,
            first_claim,
            second_claim,
            root_status_floor: HarnessRootStatusFloor::default(),
            status_floor: HarnessStatusFloor::default(),
        })
    }

    pub(crate) fn verification_policy(
        &self,
        issuer_status_lists: &[StatusList; 2],
        verification_time_unix: u64,
    ) -> Result<ZkCommonCredentialRootVerificationPolicy<'_>, HarnessError> {
        self.verification_policy_with(
            issuer_status_lists,
            verification_time_unix,
            CommonCredentialRootPolicyOverrides {
                status_root: self.status_root,
                attestation_signer: self.attestation_signer,
                assurance_policy_id: self.assurance_policy_id,
                expires_unix: verification_time_unix
                    .checked_add(60)
                    .ok_or(HarnessError::InvalidLength)?,
                policy_build_time_unix: verification_time_unix,
            },
        )
    }

    pub(super) fn verification_policy_with(
        &self,
        issuer_status_lists: &[StatusList; 2],
        verification_time_unix: u64,
        overrides: CommonCredentialRootPolicyOverrides,
    ) -> Result<ZkCommonCredentialRootVerificationPolicy<'_>, HarnessError> {
        const STATUS_SEQUENCE: u64 = 1;
        const STATUS_MAX_AGE_SECONDS: u64 = 120;
        let (snapshot, signer) = status_snapshot::signed_status_snapshot(
            verification_time_unix,
            overrides.status_root,
            overrides.expires_unix,
        )?;
        let first_verifier = HarnessIssuerStatusVerifier::new(11, STATUS_ISSUER_URLS[0])?;
        let second_verifier = HarnessIssuerStatusVerifier::new(17, STATUS_ISSUER_URLS[1])?;
        let [first, second] = issuer_status_lists;
        Ok(
            ZkCommonCredentialRootVerificationPolicy::try_from_signed_snapshot_with_issuer_status(
                ZkCommonCredentialRootTrustPolicy {
                    attestation_signer: overrides.attestation_signer,
                    assurance_policy_id: overrides.assurance_policy_id,
                    credential_issuers: [self.first_claim.issuer, self.second_claim.issuer],
                    status_feed_id: [0x5a; 32],
                    status: ZkRootStatusTrustPolicy {
                        authority: signer,
                        minimum_sequence: STATUS_SEQUENCE,
                        maximum_age_seconds: STATUS_MAX_AGE_SECONDS,
                    },
                },
                snapshot,
                &self.root_status_floor,
                [
                    ZkIssuerStatusTrust {
                        list: first,
                        issuer: STATUS_ISSUER_URLS[0],
                        url: STATUS_ISSUER_URLS[0],
                        purpose: StatusPurpose::Revocation,
                        verifier: &first_verifier,
                        freshness: StatusListFreshnessPolicy {
                            max_age_secs: STATUS_MAX_AGE_SECONDS,
                        },
                        floor: &self.status_floor,
                    },
                    ZkIssuerStatusTrust {
                        list: second,
                        issuer: STATUS_ISSUER_URLS[1],
                        url: STATUS_ISSUER_URLS[1],
                        purpose: StatusPurpose::Revocation,
                        verifier: &second_verifier,
                        freshness: StatusListFreshnessPolicy {
                            max_age_secs: STATUS_MAX_AGE_SECONDS,
                        },
                        floor: &self.status_floor,
                    },
                ],
                overrides.policy_build_time_unix,
            )?,
        )
    }

    pub(super) fn verified_status_snapshot(
        &self,
        verification_time_unix: u64,
    ) -> Result<ZkVerifiedRootStatusSnapshot, HarnessError> {
        let expires_unix = verification_time_unix
            .checked_add(60)
            .ok_or(HarnessError::InvalidLength)?;
        let (snapshot, signer) = status_snapshot::signed_status_snapshot(
            verification_time_unix,
            self.status_root,
            expires_unix,
        )?;
        Ok(verify_root_status_snapshot(
            snapshot,
            ZkRootStatusTrustPolicy {
                authority: signer,
                minimum_sequence: 1,
                maximum_age_seconds: 120,
            },
            verification_time_unix,
        )?)
    }

    pub(super) fn verification_time(&self) -> Result<u64, HarnessError> {
        self.request_time_unix
            .checked_add(60)
            .ok_or(HarnessError::InvalidLength)
    }
}

pub(super) struct CommonCredentialRootClaimFixture {
    pub(super) issuer: ZkIssuerPublicKey,
    pub(super) claim_name_hash: [u8; 32],
    pub(super) value: Vec<u8>,
}

impl CommonCredentialRootClaimFixture {
    fn read(fixture: &TomlValue) -> Result<Self, HarnessError> {
        let value_length = toml_u32(fixture, "val_len")?;
        let padded_value = toml_bytes(fixture, "val_pub", CLAIM_VALUE_BYTES)?;
        let value_len = usize::try_from(value_length).map_err(|_| HarnessError::InvalidLength)?;
        if value_len == 0 || value_len > padded_value.len() {
            return Err(HarnessError::InvalidLength);
        }
        Ok(Self {
            issuer: ZkIssuerPublicKey {
                x: toml_bytes32(fixture, "pk_issuer_x")?,
                y: toml_bytes32(fixture, "pk_issuer_y")?,
            },
            claim_name_hash: toml_bytes32(fixture, "name_hash")?,
            value: padded_value[..value_len].to_vec(),
        })
    }
}

pub(super) fn session_with_wrong_query(
    request: AuthorizationRequestObject,
    verification_time_unix: u64,
) -> Result<SessionRecord, HarnessError> {
    let mut session = session_record(request, verification_time_unix)?;
    let query = session
        .dcql_query
        .credentials
        .first_mut()
        .ok_or(HarnessError::MissingField)?;
    query.meta.insert(
        "claim_0_name_hash".to_owned(),
        json!(lower_hex(&[9_u8; 32])?),
    );
    Ok(session)
}

pub(super) fn zk_common_credential_root(
    presentations: &[reallyme_openid4vp_verifier::VerifiedPresentation],
) -> Result<&reallyme_openid4vp_verifier::VerifiedZkCommonCredentialRootPresentation, HarnessError>
{
    let presentation = presentations.first().ok_or(HarnessError::MissingZkClaim)?;
    match presentation.holder_binding().disclosures() {
        VerifiedDisclosureSet::ZkCommonCredentialRoot(common_credential_root) => {
            Ok(common_credential_root.as_ref())
        }
        _ => Err(HarnessError::MissingZkClaim),
    }
}

#[cfg(test)]
mod model_tests;

mod status_snapshot;
