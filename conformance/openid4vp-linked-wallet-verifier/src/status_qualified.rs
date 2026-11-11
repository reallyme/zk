// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Real linked proof generation for a direct/private credential's fifth slot.

use reallyme_credential_status::{
    status_list_signing_payload, CredentialStatusError, StatusList, StatusListAlgorithm,
    StatusListSignature, StatusListVerifier, StatusPurpose,
};
use reallyme_crypto::{p256, sha2};
use reallyme_identity_openid4vp_product_store::{
    ZkPersonaCredentialEvidenceIssuerStatusSource, ZkPersonaCredentialEvidenceSignedStatusAuthority,
};
use reallyme_zk_api::{
    circuits::{ZkCircuitFamily, ZkCircuitRef, ZkCircuitStage, ZkCredentialHashAlgorithm},
    claim_bundle::{
        verify_status_qualified_claim_proof_bundle_with, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkStatusQualifiedClaimProofBundle, ZkStatusQualifiedClaimProofBundleVerifyRequest,
    },
    common_root::{ZkCommonCredentialRootPersonaMode, ZkCommonCredentialRootProofSlot},
    errors::ZkErrorReason,
    issuer_status::{ZkIssuerCredentialStatusProof, ZkIssuerStatusAuthority},
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding, ZkWitness},
};
use reallyme_zk_backend_bb::{
    BarretenbergBundleProvider, BarretenbergCommonCredentialRootArtifactResolver,
    NativeBarretenbergBackend,
};

use crate::{
    artifacts::StageResolver, direct_post::status_floor_store, error::HarnessError,
    fixture::CredentialFixture, openid::expect_zk_reason,
    witness::generate_exact_witness_from_toml,
};
use zeroize::Zeroizing;

const STATUS_URL: &str = "https://status.example/revocation-v1";
const STATUS_ISSUER: &str = "did:example:issuer";
const STATUS_LIST_LENGTH: u64 = 256;
const STATUS_SIGNER_SCALAR: [u8; 32] = {
    let mut scalar = [0_u8; 32];
    scalar[31] = 7;
    scalar
};

/// Conformance trust anchor for the issuer's delegated status signer. The
/// credential issuer key is independently pinned by the ZK verifier.
pub(crate) struct FixtureStatusSignatureVerifier {
    public_key: Vec<u8>,
}

impl FixtureStatusSignatureVerifier {
    pub(crate) fn new() -> Result<Self, HarnessError> {
        let secret = Zeroizing::new(STATUS_SIGNER_SCALAR);
        let (public_key, _owned_secret) = p256::generate_p256_keypair_from_secret_key(&secret)?;
        Ok(Self { public_key })
    }
}

impl StatusListVerifier for FixtureStatusSignatureVerifier {
    fn verify_status_list(
        &self,
        issuer: &str,
        alg: StatusListAlgorithm,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), CredentialStatusError> {
        if issuer != STATUS_ISSUER || alg != StatusListAlgorithm::P256 {
            return Err(CredentialStatusError::InvalidSignature);
        }
        let digest = sha2::digest(payload);
        let digest = crypto_p256::P256Sha256Digest::new(digest.into_bytes());
        crypto_p256::verify_p256_sha256_digest_low_s_der(signature, &digest, &self.public_key)
            .map_err(|_| CredentialStatusError::InvalidSignature)
    }
}

pub(crate) fn signed_status_list(fixture: &CredentialFixture) -> Result<StatusList, HarnessError> {
    signed_status_list_with_revocation(fixture, false)
}

pub(crate) fn signed_status_list_with_revocation(
    fixture: &CredentialFixture,
    revoked: bool,
) -> Result<StatusList, HarnessError> {
    let fields = fixture.issuer_status()?;
    if fields.length != STATUS_LIST_LENGTH
        || sha2::digest(STATUS_URL.as_bytes()).as_bytes() != &fields.url_hash
    {
        return Err(HarnessError::InvalidLength);
    }
    let mut encoded_list = fields.status_chunk.to_vec();
    if revoked {
        let first = encoded_list
            .first_mut()
            .ok_or(HarnessError::InvalidLength)?;
        *first |= 1;
    }
    let mut list = StatusList {
        issuer: STATUS_ISSUER.to_owned(),
        purpose: StatusPurpose::Revocation,
        issued_at: fields
            .verification_time_unix
            .checked_sub(30)
            .ok_or(HarnessError::InvalidLength)?,
        next_update: fields
            .verification_time_unix
            .checked_add(300)
            .ok_or(HarnessError::InvalidLength)?,
        encoded_list,
        length: fields.length,
        list_id: Some(fields.list_id),
        signature: StatusListSignature {
            alg: StatusListAlgorithm::P256,
            sig_bytes: Vec::new(),
        },
    };
    let payload = status_list_signing_payload(&list)?;
    let digest = sha2::digest(&payload);
    let secret = Zeroizing::new(STATUS_SIGNER_SCALAR);
    let digest = crypto_p256::P256Sha256Digest::new(digest.into_bytes());
    list.signature.sig_bytes =
        crypto_p256::sign_p256_sha256_digest_low_s_der(secret.as_slice(), &digest)?;
    Ok(list)
}

pub(crate) fn status_source<'a>(
    list: &'a StatusList,
    verifier: &'a FixtureStatusSignatureVerifier,
    credential_issuer_key: ZkIssuerPublicKey,
) -> ZkPersonaCredentialEvidenceIssuerStatusSource<'a> {
    ZkPersonaCredentialEvidenceIssuerStatusSource {
        credential_issuer_key,
        list,
        issuer: STATUS_ISSUER,
        url: STATUS_URL,
        purpose: StatusPurpose::Revocation,
        verifier,
        freshness: reallyme_credential_status::StatusListFreshnessPolicy { max_age_secs: 300 },
    }
}

pub(crate) fn prove_issuer_credential_status(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    fixture: &CredentialFixture,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    session_binding: ZkSessionBinding,
) -> Result<ZkIssuerCredentialStatusProof, HarnessError> {
    let witness = issuer_credential_status_witness(
        provider,
        fixture,
        credential_hash_algorithm,
        session_binding,
    )?;
    Ok(provider.prove_issuer_credential_status(
        credential_hash_algorithm,
        &witness,
        session_binding,
    )?)
}

pub(crate) fn issuer_credential_status_witness(
    provider: &BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    fixture: &CredentialFixture,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    session_binding: ZkSessionBinding,
) -> Result<ZkWitness, HarnessError> {
    let circuit_ref = ZkCircuitRef::new(
        credential_hash_algorithm,
        ZkCircuitFamily::CommonCredentialRootV1,
        ZkCircuitStage::IssuerCredentialStatus,
    );
    let artifacts = provider
        .artifact_resolver()
        .resolve_common_credential_root_artifacts(
            ZkCommonCredentialRootPersonaMode::PrivatePersona,
            ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0,
            circuit_ref,
            ZkProofSuite::PRODUCTION,
        )?;
    let witness = generate_exact_witness_from_toml(
        circuit_ref,
        artifacts.bytecode().as_bytes(),
        fixture.prover_toml_for(ZkCircuitStage::IssuerCredentialStatus)?,
        session_binding,
    )?;
    Ok(witness)
}

pub(crate) struct StatusRejectionContext<'a> {
    pub(crate) provider: &'a BarretenbergBundleProvider<NativeBarretenbergBackend, StageResolver>,
    pub(crate) first: &'a ZkStatusQualifiedClaimProofBundle,
    pub(crate) second: &'a ZkStatusQualifiedClaimProofBundle,
    pub(crate) first_fixture: &'a CredentialFixture,
    pub(crate) signer_verifier: &'a FixtureStatusSignatureVerifier,
    pub(crate) trusted_issuers: &'a [ZkIssuerPublicKey],
    pub(crate) current_authority: &'a dyn ZkIssuerStatusAuthority,
    pub(crate) session_binding: ZkSessionBinding,
    pub(crate) verification_time_unix: u64,
}

pub(crate) fn expect_live_status_rejections(
    context: StatusRejectionContext<'_>,
) -> Result<(), HarnessError> {
    let StatusRejectionContext {
        provider,
        first,
        second,
        first_fixture,
        signer_verifier,
        trusted_issuers,
        current_authority,
        session_binding,
        verification_time_unix,
    } = context;
    let swapped_bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        first.claim_proof_bundle(),
        ZkProofSuite::PRODUCTION,
        session_binding,
        trusted_issuers,
        verification_time_unix,
    )?;
    let swapped = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        swapped_bundle_request,
        second.issuer_credential_status(),
        current_authority,
        reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    expect_zk_reason(
        verify_status_qualified_claim_proof_bundle_with(provider, provider, swapped).map(|_| ()),
        ZkErrorReason::BindingMismatch,
    )?;

    // This list is correctly signed and current. The earlier proof must fail
    // because its hidden-index membership is bound to a different root.
    let revoked_list = signed_status_list_with_revocation(first_fixture, true)?;
    let revoked_sources = [status_source(
        &revoked_list,
        signer_verifier,
        first_fixture.issuer_key,
    )];
    let (revoked_store, _directory) = status_floor_store()?;
    let revoked_authority = ZkPersonaCredentialEvidenceSignedStatusAuthority::new(
        revoked_store.as_ref(),
        &revoked_sources,
    );
    let revoked_bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        first.claim_proof_bundle(),
        ZkProofSuite::PRODUCTION,
        session_binding,
        trusted_issuers,
        verification_time_unix,
    )?;
    let revoked = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        revoked_bundle_request,
        first.issuer_credential_status(),
        &revoked_authority,
        reallyme_zk_api::issuer_status::ZkIssuerStatusPurpose::Revocation,
    )?;
    expect_zk_reason(
        verify_status_qualified_claim_proof_bundle_with(provider, provider, revoked).map(|_| ()),
        ZkErrorReason::BindingMismatch,
    )
}
