// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    circuits::ZkCredentialHashAlgorithm,
    claim_bundle::{
        verify_presentation_bound_claim_bundle_with,
        verify_status_qualified_claim_proof_bundle_with, ZkClaimProofBundle,
        ZkClaimProofBundleKind, ZkClaimProofBundleProveRequest, ZkClaimProofBundleProver,
        ZkClaimProofBundleWitness, ZkPresentationBoundClaimBundleVerifyRequest,
        ZkStatusQualifiedClaimProofBundle, ZkStatusQualifiedClaimProofBundleVerifyRequest,
    },
    errors::{ZkError, ZkErrorReason},
    issuer_status::ZkIssuerStatusFeed,
    keys::ZkIssuerPublicKey,
    proofs::{ZkProofSuite, ZkSessionBinding},
};
use reallyme_zk_backend_bb::BarretenbergBundleProvider;
use reallyme_zk_proto_codec::{
    operation::{decode_operation_request, ZkNativeStageWitnessHandle, ZkProviderOperation},
    result::{
        encode_artifact_manifest_response, encode_claim_proof_bundle_response,
        encode_claim_proof_bundle_verification_response, encode_operation_failure_response,
        encode_status_qualified_claim_proof_bundle_verification_response,
    },
};
use zeroize::Zeroizing;

use crate::context::{PlatformContext, PlatformCrsMode};

mod backend_adapter;
mod bundle;
mod common_credential_root;
#[cfg(feature = "diagnostic-exact-source")]
mod exact_source;
mod persona_credential_evidence;
mod stage;
mod supplied_issuer_status;

use backend_adapter::BorrowedPlatformBackend;
use bundle::bundle_credential_hash_algorithm;
use common_credential_root::{
    prove_common_credential_root_presentation, prove_common_credential_root_stage,
    verify_common_credential_root,
};
use persona_credential_evidence::{
    assemble_persona_credential_evidence_presentation,
    prepare_persona_credential_evidence_presentation_signing,
    prove_persona_credential_evidence_claim_root, prove_persona_credential_evidence_current_state,
    prove_persona_credential_evidence_issuer_envelope,
    prove_persona_credential_evidence_selected_claim,
    prove_persona_credential_evidence_signed_validity, prove_persona_credential_evidence_stage,
    verify_persona_credential_evidence_stage,
};
use stage::{prove_stage, release_stage_witness, verify_stage, witness_stage};
use supplied_issuer_status::SuppliedIssuerStatusAuthority;

#[cfg(test)]
mod tests;

pub(crate) fn dispatch_operation(
    context: &PlatformContext,
    request_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let _lease = context.acquire_dispatch()?;
    match decode_operation_request(request_bytes) {
        Ok(operation) => dispatch_decoded_operation(context, request_bytes, operation),
        Err(error) => encode_operation_failure_response(request_bytes, error),
    }
}

fn dispatch_decoded_operation(
    context: &PlatformContext,
    request_bytes: &[u8],
    operation: ZkProviderOperation,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let result = match operation {
        ZkProviderOperation::GetArtifactManifest {
            circuit_ref,
            proof_suite,
        } => context
            .stage_manifest_for_ref(circuit_ref, proof_suite)
            .and_then(|manifest| encode_artifact_manifest_response(request_bytes, &manifest)),
        ZkProviderOperation::VerifyStage {
            proof,
            expected_proof_suite,
            expected_binding,
        } => verify_stage(
            context,
            request_bytes,
            &proof,
            expected_proof_suite,
            expected_binding,
        ),
        ZkProviderOperation::ProveStage {
            circuit_ref,
            proof_suite,
            witness_source,
            public_inputs,
            session_binding,
        } => prove_stage(
            context,
            request_bytes,
            circuit_ref,
            proof_suite,
            witness_source,
            &public_inputs,
            session_binding,
        ),
        ZkProviderOperation::WitnessStage {
            circuit_ref,
            proof_suite,
            input,
        } => witness_stage(context, request_bytes, circuit_ref, proof_suite, input),
        ZkProviderOperation::ReleaseStageWitness { witness_handle } => {
            release_stage_witness(context, request_bytes, witness_handle)
        }
        ZkProviderOperation::ProveClaimProofBundle {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_bundle,
            session_binding,
        } => prove_claim_proof_bundle(
            context,
            request_bytes,
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            &witness_bundle,
            session_binding,
        ),
        ZkProviderOperation::ProveRetainedClaimProofBundle {
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            witness_handles,
            session_binding,
        } => prove_retained_claim_proof_bundle(
            context,
            request_bytes,
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            &witness_handles,
            session_binding,
        ),
        ZkProviderOperation::VerifyClaimProofBundle {
            claim_proof_bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
        } => verify_claim_proof_bundle(
            context,
            request_bytes,
            &claim_proof_bundle,
            expected_proof_suite,
            expected_binding,
            &trusted_issuers,
            verification_time_unix,
        ),
        ZkProviderOperation::VerifyStatusQualifiedClaimProofBundle {
            status_qualified_claim_proof_bundle,
            expected_proof_suite,
            expected_binding,
            trusted_issuers,
            verification_time_unix,
            current_issuer_status,
            expected_issuer,
        } => verify_status_qualified_claim_proof_bundle(
            context,
            request_bytes,
            &status_qualified_claim_proof_bundle,
            StatusQualifiedVerifierPolicy {
                expected_proof_suite,
                expected_binding,
                trusted_issuers: &trusted_issuers,
                verification_time_unix,
                current_issuer_status,
                expected_issuer,
            },
        ),
        ZkProviderOperation::VerifyCommonCredentialRoot {
            presentation,
            join_policy,
            expected_proof_suite,
        } => verify_common_credential_root(
            context,
            request_bytes,
            &presentation,
            &join_policy,
            expected_proof_suite,
        ),
        ZkProviderOperation::ProveCommonCredentialRootStage {
            plan,
            proof_suite,
            input,
            expected_binding,
        } => prove_common_credential_root_stage(
            context,
            request_bytes,
            plan,
            proof_suite,
            input,
            expected_binding,
        ),
        ZkProviderOperation::ProveCommonCredentialRootPresentation {
            persona_mode: bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            expected_binding,
            stages,
        } => prove_common_credential_root_presentation(
            context,
            request_bytes,
            bundle_kind,
            credential_hash_algorithm,
            proof_suite,
            expected_binding,
            stages,
        ),
        ZkProviderOperation::VerifyPersonaCredentialEvidenceStage { proof } => {
            verify_persona_credential_evidence_stage(context, request_bytes, &proof)
        }
        ZkProviderOperation::ProvePersonaCredentialEvidenceStage {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            witness,
        } => prove_persona_credential_evidence_stage(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &witness,
        ),
        ZkProviderOperation::ProvePersonaCredentialEvidenceCurrentState {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            input,
        } => prove_persona_credential_evidence_current_state(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &input,
        ),
        ZkProviderOperation::ProvePersonaCredentialEvidenceIssuerEnvelope {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            input,
        } => prove_persona_credential_evidence_issuer_envelope(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &input,
        ),
        ZkProviderOperation::ProvePersonaCredentialEvidenceClaimRoot {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            input,
        } => prove_persona_credential_evidence_claim_root(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &input,
        ),
        ZkProviderOperation::ProvePersonaCredentialEvidenceSignedValidity {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            input,
        } => prove_persona_credential_evidence_signed_validity(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &input,
        ),
        ZkProviderOperation::ProvePersonaCredentialEvidenceSelectedClaim {
            mode: bundle_kind,
            circuit_ref,
            proof_suite,
            input,
        } => prove_persona_credential_evidence_selected_claim(
            context,
            request_bytes,
            bundle_kind,
            circuit_ref,
            proof_suite,
            &input,
        ),
        ZkProviderOperation::PreparePersonaCredentialEvidencePresentationSigning { input } => {
            prepare_persona_credential_evidence_presentation_signing(request_bytes, &input)
        }
        ZkProviderOperation::AssemblePersonaCredentialEvidencePresentation { input, signature } => {
            assemble_persona_credential_evidence_presentation(request_bytes, &input, &signature)
        }
    };
    match result {
        Ok(response) => Ok(response),
        Err(error) => encode_operation_failure_response(request_bytes, error),
    }
}

fn prove_retained_claim_proof_bundle(
    context: &PlatformContext,
    request_bytes: &[u8],
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    witness_handles: &[ZkNativeStageWitnessHandle],
    session_binding: ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let mut handle_requests = Vec::new();
    if handle_requests
        .try_reserve_exact(witness_handles.len())
        .is_err()
    {
        let _cleanup_result =
            release_retained_claim_proof_bundle_handles_present(context, witness_handles);
        return Err(ZkError::new(ZkErrorReason::ResourceExhausted));
    }
    for handle in witness_handles {
        handle_requests.push((handle.native_handle_id, handle.circuit_ref));
    }
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        let _cleanup_result = context.release_stage_witnesses_present(&handle_requests);
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let stage_witnesses =
        context.take_ordered_stage_witnesses_or_release_present(&handle_requests)?;
    let witness_bundle = ZkClaimProofBundleWitness::try_from_stage_witnesses(
        bundle_kind,
        credential_hash_algorithm,
        stage_witnesses,
    )?;
    prove_claim_proof_bundle(
        context,
        request_bytes,
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        &witness_bundle,
        session_binding,
    )
}

fn release_retained_claim_proof_bundle_handles_present(
    context: &PlatformContext,
    witness_handles: &[ZkNativeStageWitnessHandle],
) -> Result<(), ZkError> {
    let mut index = 0_usize;
    while index < witness_handles.len() {
        let handle = witness_handles[index];
        if handle.native_handle_id != 0 {
            let _released =
                context.release_stage_witness(handle.native_handle_id, handle.circuit_ref);
        }
        index = index
            .checked_add(1)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
    }
    Ok(())
}

fn prove_claim_proof_bundle(
    context: &PlatformContext,
    request_bytes: &[u8],
    bundle_kind: ZkClaimProofBundleKind,
    credential_hash_algorithm: ZkCredentialHashAlgorithm,
    proof_suite: ZkProofSuite,
    witness_bundle: &ZkClaimProofBundleWitness,
    session_binding: ZkSessionBinding,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    if !matches!(context.crs_mode(), PlatformCrsMode::FullProver) {
        return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
    }
    let resolver = context.resolver(bundle_kind, credential_hash_algorithm, proof_suite)?;
    let provider =
        BarretenbergBundleProvider::new(BorrowedPlatformBackend::new(context.backend()), resolver);
    let request = ZkClaimProofBundleProveRequest::try_new(
        bundle_kind,
        credential_hash_algorithm,
        proof_suite,
        witness_bundle,
        session_binding,
    )?;
    let bundle = provider.prove_claim_proof_bundle(request)?;
    encode_claim_proof_bundle_response(request_bytes, &bundle)
}

fn verify_claim_proof_bundle(
    context: &PlatformContext,
    request_bytes: &[u8],
    claim_proof_bundle: &ZkClaimProofBundle,
    expected_proof_suite: ZkProofSuite,
    expected_binding: ZkSessionBinding,
    trusted_issuers: &[ZkIssuerPublicKey],
    verification_time_unix: u64,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let credential_hash_algorithm = bundle_credential_hash_algorithm(claim_proof_bundle)?;
    let resolver = context.resolver(
        claim_proof_bundle.bundle_kind(),
        credential_hash_algorithm,
        expected_proof_suite,
    )?;
    let provider =
        BarretenbergBundleProvider::new(BorrowedPlatformBackend::new(context.backend()), resolver);
    let request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        claim_proof_bundle,
        expected_proof_suite,
        expected_binding,
        trusted_issuers,
        verification_time_unix,
    )?;
    let verification = verify_presentation_bound_claim_bundle_with(&provider, request)?;
    encode_claim_proof_bundle_verification_response(request_bytes, &verification)
}

/// Verifier-owned policy for one status-qualified verification.
struct StatusQualifiedVerifierPolicy<'a> {
    expected_proof_suite: ZkProofSuite,
    expected_binding: ZkSessionBinding,
    trusted_issuers: &'a [ZkIssuerPublicKey],
    verification_time_unix: u64,
    current_issuer_status: ZkIssuerStatusFeed,
    expected_issuer: ZkIssuerPublicKey,
}

/// Verifies all five proofs and the verifier-supplied current issuer status
/// list, and encodes the result only for the status-qualified value the API
/// mints after every join succeeds.
fn verify_status_qualified_claim_proof_bundle(
    context: &PlatformContext,
    request_bytes: &[u8],
    bundle: &ZkStatusQualifiedClaimProofBundle,
    policy: StatusQualifiedVerifierPolicy<'_>,
) -> Result<Zeroizing<Vec<u8>>, ZkError> {
    let StatusQualifiedVerifierPolicy {
        expected_proof_suite,
        expected_binding,
        trusted_issuers,
        verification_time_unix,
        current_issuer_status,
        expected_issuer,
    } = policy;
    let claim_proof_bundle = bundle.claim_proof_bundle();
    let credential_hash_algorithm = bundle_credential_hash_algorithm(claim_proof_bundle)?;
    let resolver = context.resolver(
        claim_proof_bundle.bundle_kind(),
        credential_hash_algorithm,
        expected_proof_suite,
    )?;
    let bundle_provider =
        BarretenbergBundleProvider::new(BorrowedPlatformBackend::new(context.backend()), resolver);
    // The status circuit resolves through the common-credential-root artifact
    // set, which the platform context pins separately from the claim stages.
    let status_provider = BarretenbergBundleProvider::new(context.backend(), context);
    let expected_status_purpose = current_issuer_status.purpose;
    let status_authority =
        SuppliedIssuerStatusAuthority::new(expected_issuer, current_issuer_status);
    let bundle_request = ZkPresentationBoundClaimBundleVerifyRequest::try_new(
        claim_proof_bundle,
        expected_proof_suite,
        expected_binding,
        trusted_issuers,
        verification_time_unix,
    )?;
    let request = ZkStatusQualifiedClaimProofBundleVerifyRequest::try_new(
        bundle_request,
        bundle.issuer_credential_status(),
        &status_authority,
        expected_status_purpose,
    )?;
    let verification = verify_status_qualified_claim_proof_bundle_with(
        &bundle_provider,
        &status_provider,
        request,
    )?;
    encode_status_qualified_claim_proof_bundle_verification_response(request_bytes, &verification)
}
