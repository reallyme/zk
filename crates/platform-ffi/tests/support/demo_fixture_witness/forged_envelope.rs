// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::circuits::ZkCircuitRef;

use super::demo_fixture_types::hex_to_digest;
use super::{
    claim_proof_bundle_to_proto, dispatch_failure_reason, dispatch_success, pb,
    proof_package_to_proto, prove_request, verify_claim_proof_bundle_proto_request, verify_request,
    witness_request, DemoPaths, DemoProfile, DemoStage, MessageField, PlatformContextGuard,
    TestError, ZkClaimProofBundle, ZkErrorReason, ZkProviderOperationResult,
};

// For the demo issuer's public point Q, let r = x(G + 2Q) mod n and
// s = r / 2 mod n, which is low-s. Taking the raw digest equal to s gives
// u1 = 1 and u2 = 2 in ECDSA verification, so the signature (r, s) is valid
// over that digest and can be constructed using only Q. The secp256r1
// gadget rejects u2 in {0, 1, -1}, so the forgery uses u2 = 2.
const FORGED_DIGEST_AND_S: &str =
    "0748e391ce13206be9451f1cea2c1fd31e05e052efb2527f33972b9822e53c4b";
const FORGED_SIGNATURE_R: &str = "0e91c7239c2640d7d28a3e39d4583fa63c0bc0a5df64a4fe672e573045ca7896";
// SHA-256 over the ENVB1 transcript with the forged digest and the demo
// fixture's unchanged issuer key, session fields, and expiry.
const FORGED_ENVELOPE_BINDING: &str =
    "95924e0671c8304fb50760e1d2f08a7d960fe01ca3a4f4e3ff9f32e6ad46dc64";

pub(super) fn exercise_forged_envelope(
    context: &PlatformContextGuard,
    paths: &DemoPaths,
    profile: DemoProfile,
    honest_bundle: &ZkClaimProofBundle,
) -> Result<(), TestError> {
    let stage = DemoStage::ALL
        .iter()
        .find(|stage| stage.circuit_stage == pb::ZkCircuitStage::CredentialEnvelope)
        .copied()
        .ok_or(TestError::UnexpectedResponse)?;
    let mut input = paths.read_fixture(profile, stage)?;
    let Some(pb::zk_stage_witness_input::Input::CredentialEnvelope(envelope)) =
        input.input.as_mut()
    else {
        return Err(TestError::UnexpectedResponse);
    };
    let digest_and_s = hex_to_digest(FORGED_DIGEST_AND_S)?;
    let signature = [hex_to_digest(FORGED_SIGNATURE_R)?, digest_and_s].concat();
    let private = envelope
        .proof
        .as_option_mut()
        .ok_or(TestError::UnexpectedResponse)?;
    private.envelope_hash = MessageField::some(pb::ZkInputBytes32 {
        value: digest_and_s.to_vec(),
        __buffa_unknown_fields: Default::default(),
    });
    private.issuer_signature = MessageField::some(pb::ZkInputBytes64 {
        value: signature,
        __buffa_unknown_fields: Default::default(),
    });
    envelope.envelope_binding = MessageField::some(pb::ZkInputBytes32 {
        value: hex_to_digest(FORGED_ENVELOPE_BINDING)?.to_vec(),
        __buffa_unknown_fields: Default::default(),
    });

    let ZkProviderOperationResult::StageWitness(witness) =
        dispatch_success(context, witness_request(profile, stage, input))?
    else {
        return Err(TestError::UnexpectedResponse);
    };
    let ZkProviderOperationResult::StageProof(proof) =
        dispatch_success(context, prove_request(&witness))?
    else {
        return Err(TestError::UnexpectedResponse);
    };
    assert_eq!(witness.session_binding, honest_bundle.session_binding());
    assert_stage_verification_policy(
        context,
        verify_request(&proof, witness.session_binding)?,
        proof.circuit_ref(),
    )?;

    // Even with the demo issuer trusted, the forged envelope cannot replace
    // the envelope joined to the credential-root and claim proofs.
    let statement = honest_bundle
        .decode_claimed_statement()
        .map_err(|error| TestError::Domain(error.reason()))?;
    let mut substituted = claim_proof_bundle_to_proto(profile, honest_bundle)?;
    let envelope = substituted
        .stages
        .get_mut(usize::from(stage.production_stage.index()))
        .ok_or(TestError::UnexpectedResponse)?;
    envelope.proof = MessageField::some(proof_package_to_proto(&proof)?);
    let verification_time = statement
        .presentation_expiry_unix()
        .checked_sub(1)
        .ok_or(TestError::Domain(ZkErrorReason::PresentationExpired))?;
    let request = verify_claim_proof_bundle_proto_request(
        substituted,
        witness.session_binding,
        statement.issuer(),
        verification_time,
    );
    assert_eq!(
        dispatch_failure_reason(context, request)?,
        ZkErrorReason::BindingMismatch
    );
    Ok(())
}

pub(super) fn assert_stage_verification_policy(
    context: &PlatformContextGuard,
    request: pb::ZkProviderOperationRequest,
    circuit_ref: ZkCircuitRef,
) -> Result<(), TestError> {
    if cfg!(feature = "diagnostic-stage-verification") {
        let ZkProviderOperationResult::StageVerification(report) =
            dispatch_success(context, request)?
        else {
            return Err(TestError::UnexpectedResponse);
        };
        assert_eq!(report.circuit_ref, Some(circuit_ref));
    } else {
        assert_eq!(
            dispatch_failure_reason(context, request)?,
            ZkErrorReason::UnsupportedTransport
        );
    }
    Ok(())
}
