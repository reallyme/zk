// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::{
    io::Write,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, MutexGuard,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::{write::GzEncoder, Compression};
use reallyme_zk_api::{
    artifacts::ZkArtifactManifestDigest,
    capabilities::circuit_ref_capabilities,
    circuits::{ZkCircuitRef, ZkCredentialHashAlgorithm},
    claim_bundle::{ZkClaimProofBundleKind, ZkClaimProofBundleStage},
    errors::{ZkError, ZkErrorReason},
    proofs::{
        ZkProof, ZkProofSuite, ZkPublicInputDescriptor, ZkPublicInputName, ZkPublicInputs,
        ZkSessionBinding, ZkWitness,
    },
};
use reallyme_zk_artifacts::{
    ArtifactDigests, ArtifactKind, ArtifactManifestPin, ArtifactToolchain, Digest32,
    ProductionArtifactManifest, VerifiedArtifactBytes,
};

use super::{
    lock_bbapi_process_state, BarretenbergBbapiOwnedOutput, BarretenbergBbapiResponse,
    BarretenbergBbapiTransport, BarretenbergProcessCrsIdentity, BarretenbergProverCrs,
    BarretenbergProverCrsIdentity, BarretenbergVerifierCrs, BarretenbergVerifierCrsIdentity,
    BbapiProcessCrsState, NativeBarretenbergBackend, SHIM_STATUS_INPUT_TOO_LARGE, SHIM_STATUS_OK,
    SHIM_STATUS_UPSTREAM_EXCEPTION,
};
use crate::{
    BbStageArtifacts, BbStageVerificationArtifacts, BbStageVerifyRequest, LinkedBarretenbergBackend,
};

mod prove;
mod verify;

const SUCCESS_RESPONSE: &[u8] = &[
    0x92, 0xb5, b'C', b'i', b'r', b'c', b'u', b'i', b't', b'V', b'e', b'r', b'i', b'f', b'y', b'R',
    b'e', b's', b'p', b'o', b'n', b's', b'e', 0x81, 0xa8, b'v', b'e', b'r', b'i', b'f', b'i', b'e',
    b'd', 0xc3,
];
const EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES: usize = 9_152;
const SRS_SUCCESS_RESPONSE: &[u8] = &[
    0x92, 0xb2, b'S', b'r', b's', b'I', b'n', b'i', b't', b'S', b'r', b's', b'R', b'e', b's', b'p',
    b'o', b'n', b's', b'e', 0x81, 0xaa, b'p', b'o', b'i', b'n', b't', b's', b'_', b'b', b'u', b'f',
    0xc4, 0x00,
];

static FREE_COUNT: AtomicUsize = AtomicUsize::new(0);
static SRS_INIT_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
static PROCESS_STATE_TEST_LOCK: Mutex<()> = Mutex::new(());

impl NativeBarretenbergBackend {
    fn from_transport<T>(transport: T) -> Self
    where
        T: BarretenbergBbapiTransport + 'static,
    {
        Self {
            transport: Box::new(transport),
        }
    }

    fn reset_process_state_for_test() -> Result<(), ZkError> {
        let mut state = lock_bbapi_process_state()?;
        state.crs = BbapiProcessCrsState::Uninitialized;
        Ok(())
    }

    fn poison_process_state_for_test() -> Result<(), ZkError> {
        let mut state = lock_bbapi_process_state()?;
        state.crs = BbapiProcessCrsState::Poisoned;
        Ok(())
    }

    fn set_process_state_for_test(
        identity: BarretenbergVerifierCrsIdentity,
    ) -> Result<(), ZkError> {
        let mut state = lock_bbapi_process_state()?;
        state.crs =
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(identity));
        Ok(())
    }

    fn set_prover_process_state_for_test(
        identity: BarretenbergProverCrsIdentity,
    ) -> Result<(), ZkError> {
        let mut state = lock_bbapi_process_state()?;
        state.crs =
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::FullProver(identity));
        Ok(())
    }
}

fn lock_process_state_test() -> Result<MutexGuard<'static, ()>, ZkError> {
    PROCESS_STATE_TEST_LOCK
        .lock()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))
}

unsafe extern "C" fn fake_free(ptr: *mut u8, _len: usize) {
    FREE_COUNT.fetch_add(1, Ordering::SeqCst);
    // SAFETY: tests allocate native buffers with `libc::malloc`; this fake
    // destroy function is paired only with those allocations.
    unsafe {
        libc::free(ptr.cast());
    }
}

unsafe extern "C" fn fake_call_success(
    _input: *const u8,
    _input_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> u32 {
    let ptr = allocate_native(SUCCESS_RESPONSE);
    if ptr.is_null() {
        return SHIM_STATUS_UPSTREAM_EXCEPTION;
    }
    // SAFETY: the shim contract passes valid out-parameter pointers.
    unsafe {
        *output = ptr;
        *output_len = SUCCESS_RESPONSE.len();
    }
    SHIM_STATUS_OK
}

unsafe extern "C" fn fake_call_exception_after_allocation(
    _input: *const u8,
    _input_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> u32 {
    let ptr = allocate_native(&[1, 2, 3]);
    // SAFETY: the shim contract passes valid out-parameter pointers.
    unsafe {
        *output = ptr;
        *output_len = 3;
    }
    SHIM_STATUS_UPSTREAM_EXCEPTION
}

fn allocate_native(bytes: &[u8]) -> *mut u8 {
    // SAFETY: malloc either returns null or a live allocation of `bytes.len()`
    // bytes. The caller pairs it with `fake_free`.
    let ptr = unsafe { libc::malloc(bytes.len()) }.cast::<u8>();
    if ptr.is_null() {
        return ptr;
    }
    // SAFETY: `ptr` names a live allocation of at least `bytes.len()` bytes and
    // the source slice is valid for the duration of the copy.
    unsafe {
        ptr.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
    }
    ptr
}

fn reset_free_count() {
    FREE_COUNT.store(0, Ordering::SeqCst);
}

#[test]
fn shim_input_limit_maps_to_typed_resource_error() {
    assert_eq!(
        super::map_shim_status(SHIM_STATUS_INPUT_TOO_LARGE),
        ZkErrorReason::MessageTooLarge
    );
}

fn binding() -> ZkSessionBinding {
    ZkSessionBinding {
        nonce_hash: [1_u8; 32],
        audience_hash: [2_u8; 32],
        transaction_data_hash: None,
    }
}

fn bundle_kind() -> ZkClaimProofBundleKind {
    ZkClaimProofBundleKind::PrivatePersonaClaimV1
}

fn stage() -> ZkClaimProofBundleStage {
    ZkClaimProofBundleStage::Session
}

fn circuit_ref() -> ZkCircuitRef {
    bundle_kind().source_ref(ZkCredentialHashAlgorithm::Sha256, stage())
}

fn manifest_digest() -> ZkArtifactManifestDigest {
    ZkArtifactManifestDigest::from_bytes([7_u8; 32])
}

fn public_inputs_for_binding(
    circuit_ref: ZkCircuitRef,
    binding: ZkSessionBinding,
) -> Result<ZkPublicInputs, ZkError> {
    let descriptor = ZkPublicInputDescriptor::for_circuit(circuit_ref)?;
    let mut bytes = vec![0_u8; descriptor.encoded_len()?];
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::Challenge,
        &binding.nonce_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::AudienceHash,
        &binding.audience_hash,
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::TransactionDataHash,
        &binding.transaction_data_public_input(),
    )?;
    write_public_input(
        bytes.as_mut_slice(),
        descriptor,
        ZkPublicInputName::ExpiryUnix,
        &42_u64.to_be_bytes(),
    )?;
    ZkPublicInputs::try_from_bytes(bytes)
}

fn write_public_input(
    bytes: &mut [u8],
    descriptor: ZkPublicInputDescriptor,
    name: ZkPublicInputName,
    value: &[u8],
) -> Result<(), ZkError> {
    let target = bytes
        .get_mut(descriptor.field_range(name)?)
        .ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?;
    if target.len() != value.len() {
        return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
    }
    target.copy_from_slice(value);
    Ok(())
}

fn verification_artifacts() -> Result<BbStageVerificationArtifacts, ZkError> {
    let verification_key = vec![99_u8; 64];
    let verification_key_digest = Digest32::sha256(verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind(),
        stage(),
        circuit_ref(),
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest())?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref())?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: Digest32::from_bytes([2_u8; 32]),
            verification_key_sha256: verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        verification_key_digest,
    )?;
    BbStageVerificationArtifacts::try_new(manifest, verification_key)
}

fn stage_artifacts() -> Result<BbStageArtifacts, ZkError> {
    let bytecode = compiled_program_json(&[0x04, 0x31, 0x59, 0x26])?;
    let bytecode_digest = Digest32::sha256(bytecode.as_slice());
    let verification_key = vec![99_u8; 64];
    let verification_key_digest = Digest32::sha256(verification_key.as_slice());
    let manifest = ProductionArtifactManifest::try_new(
        bundle_kind(),
        stage(),
        circuit_ref(),
        ArtifactManifestPin::try_new(ZkProofSuite::PRODUCTION, manifest_digest())?,
        ArtifactToolchain::try_from_versions("1.0.0", "6.0.0")?,
        circuit_ref_capabilities(circuit_ref())?,
        ArtifactDigests {
            noir_source_sha256: Digest32::from_bytes([1_u8; 32]),
            bytecode_sha256: bytecode_digest,
            verification_key_sha256: verification_key_digest,
            capability_registry_sha256: Digest32::from_bytes([3_u8; 32]),
            vector_set_sha256: vec![Digest32::from_bytes([4_u8; 32])],
        },
    )?;
    let bytecode = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::AcirBytecode,
        bytecode,
        bytecode_digest,
    )?;
    let verification_key = VerifiedArtifactBytes::try_from_bytes(
        ArtifactKind::VerificationKey,
        verification_key,
        verification_key_digest,
    )?;
    BbStageArtifacts::try_new(manifest, bytecode, verification_key)
}

fn witness() -> Result<ZkWitness, ZkError> {
    ZkWitness::try_from_noir_witness_stack_v1(circuit_ref(), gzip_bytes(&[0x03, 0x91, 0x91, 0x01])?)
}

fn compiled_program_json(acir_bytecode: &[u8]) -> Result<Vec<u8>, ZkError> {
    let compressed = gzip_bytes(acir_bytecode)?;
    let encoded = STANDARD.encode(compressed);
    Ok(format!(r#"{{"bytecode":"{encoded}"}}"#).into_bytes())
}

fn gzip_bytes(bytes: &[u8]) -> Result<Vec<u8>, ZkError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(bytes)
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))?;
    encoder
        .finish()
        .map_err(|_| ZkError::new(ZkErrorReason::BackendFailure))
}

fn proof() -> Result<ZkProof, ZkError> {
    ZkProof::try_from_exact_parts(
        bundle_kind().circuit_id(),
        circuit_ref(),
        ZkProofSuite::PRODUCTION,
        manifest_digest(),
        vec![23_u8; EXPECTED_SHA256_CREDENTIAL_SUBJECT_CLAIM_SESSION_PROOF_BYTES],
        public_inputs_for_binding(circuit_ref(), binding())?,
    )
}

struct StaticTransport {
    response: &'static [u8],
    required_command: &'static [u8],
    call_count: Option<&'static AtomicUsize>,
}

impl BarretenbergBbapiTransport for StaticTransport {
    fn call(&self, command: &[u8]) -> Result<BarretenbergBbapiResponse, ZkError> {
        if !command
            .windows(self.required_command.len())
            .any(|window| window == self.required_command)
        {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        if let Some(call_count) = self.call_count {
            call_count.fetch_add(1, Ordering::SeqCst);
        }
        BarretenbergBbapiResponse::try_copy_from_slice(self.response)
    }
}

struct ErrorTransport {
    required_command: &'static [u8],
    call_count: &'static AtomicUsize,
    reason: ZkErrorReason,
}

impl BarretenbergBbapiTransport for ErrorTransport {
    fn call(&self, command: &[u8]) -> Result<BarretenbergBbapiResponse, ZkError> {
        if !command
            .windows(self.required_command.len())
            .any(|window| window == self.required_command)
        {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Err(ZkError::new(self.reason))
    }
}

fn verifier_crs(seed: u8) -> Result<BarretenbergVerifierCrs<'static>, ZkError> {
    static G1_A: [u8; 64] = [1_u8; 64];
    static G2_A: [u8; 128] = [2_u8; 128];
    static G2_B: [u8; 128] = [3_u8; 128];
    let g2 = if seed == 1 { &G2_A } else { &G2_B };
    if G1_A.len() != crate::bbapi_abi::VERIFIER_CRS_G1_PREFIX_BYTES
        || g2.len() != crate::bbapi_abi::VERIFIER_CRS_G2_BYTES
    {
        return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
    }
    Ok(BarretenbergVerifierCrs {
        g1_prefix: &G1_A,
        g2_point: g2,
        identity: if seed == 1 {
            BarretenbergVerifierCrsIdentity::pinned_modern_verifier()
        } else {
            BarretenbergVerifierCrsIdentity {
                g1_prefix_sha256: BarretenbergVerifierCrsIdentity::pinned_modern_verifier()
                    .g1_prefix_sha256(),
                g2_sha256: Digest32::sha256(g2),
            }
        },
    })
}

fn fake_prover_crs() -> BarretenbergProverCrs<'static> {
    static G1: [u8; 64] = [4_u8; 64];
    static G2: [u8; 128] = [5_u8; 128];
    BarretenbergProverCrs {
        g1_prefix: &G1,
        g2_point: &G2,
        identity: BarretenbergProverCrsIdentity::pinned_modern_prover(),
    }
}

#[test]
fn native_output_frees_even_when_length_is_invalid() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    reset_free_count();
    let ptr = allocate_native(&[0x42]);
    if ptr.is_null() {
        return Err(ZkError::new(ZkErrorReason::ResourceExhausted));
    }

    {
        // SAFETY: `ptr` is a live test allocation paired with `fake_free`.
        let output = unsafe { BarretenbergBbapiOwnedOutput::claim(ptr, 0, fake_free) }
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        let error = output
            .try_copy_response()
            .err()
            .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        assert_eq!(error.reason(), ZkErrorReason::EmptyInput);
    }

    assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn shim_transport_frees_success_output_after_copy() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    reset_free_count();
    let transport = super::ShimBbapiTransport {
        call: fake_call_success,
        free: fake_free,
    };

    let response = transport.call(&[0x90])?;

    assert_eq!(response.as_bytes(), SUCCESS_RESPONSE);
    assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn shim_transport_frees_error_output_before_returning_failure() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    reset_free_count();
    let transport = super::ShimBbapiTransport {
        call: fake_call_exception_after_allocation,
        free: fake_free,
    };

    let error = transport
        .call(&[0x90])
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(FREE_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn verifier_backend_uses_typed_command_and_decodes_success() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    backend.verify_stage(BbStageVerifyRequest {
        bundle_kind: bundle_kind(),
        stage: stage(),
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        proof: &proof,
        expected_binding: binding(),
    })
}

#[test]
fn verifier_backend_accepts_full_prover_crs_process_state() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    backend.verify_stage(BbStageVerifyRequest {
        bundle_kind: bundle_kind(),
        stage: stage(),
        circuit_ref: circuit_ref(),
        proof_suite: ZkProofSuite::PRODUCTION,
        artifacts: &artifacts,
        proof: &proof,
        expected_binding: binding(),
    })
}

#[test]
fn verifier_backend_rechecks_manifest_coordinates() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: None,
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    let error = backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: ZkClaimProofBundleKind::CredentialSubjectClaimV1,
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::StageMismatch);
    Ok(())
}

#[test]
fn verifier_backend_rejects_verify_before_crs_init_without_calling_transport() -> Result<(), ZkError>
{
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::reset_process_state_for_test()?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    let error = backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendUnavailable);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn verifier_crs_init_is_process_global_idempotent_and_conflict_checked() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::reset_process_state_for_test()?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SRS_SUCCESS_RESPONSE,
        required_command: b"SrsInitSrs",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });
    let crs = verifier_crs(1)?;

    backend.initialize_verifier_crs(crs)?;
    backend.initialize_verifier_crs(crs)?;

    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);

    let conflicting = verifier_crs(2)?;
    let error = backend
        .initialize_verifier_crs(conflicting)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn verifier_crs_init_accepts_existing_full_prover_crs_state() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_prover_process_state_for_test(
        BarretenbergProverCrsIdentity::pinned_modern_prover(),
    )?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SRS_SUCCESS_RESPONSE,
        required_command: b"SrsInitSrs",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });

    backend.initialize_verifier_crs(verifier_crs(1)?)?;

    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn verifier_crs_init_transport_failure_poisons_process_state() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::reset_process_state_for_test()?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(ErrorTransport {
        required_command: b"SrsInitSrs",
        call_count: &SRS_INIT_CALL_COUNT,
        reason: ZkErrorReason::BackendFailure,
    });

    let error = backend
        .initialize_verifier_crs(verifier_crs(1)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);

    let retry_error = backend
        .initialize_verifier_crs(verifier_crs(1)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(retry_error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn verifier_crs_init_malformed_response_poisons_process_state() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::reset_process_state_for_test()?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"SrsInitSrs",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });

    let error = backend
        .initialize_verifier_crs(verifier_crs(1)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);

    let retry_error = backend
        .initialize_verifier_crs(verifier_crs(2)?)
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(retry_error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 1);
    Ok(())
}

#[test]
fn verifier_backend_rejects_verify_after_poison_without_calling_transport() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::poison_process_state_for_test()?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SUCCESS_RESPONSE,
        required_command: b"CircuitVerify",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });
    let artifacts = verification_artifacts()?;
    let proof = proof()?;

    let error = backend
        .verify_stage(BbStageVerifyRequest {
            bundle_kind: bundle_kind(),
            stage: stage(),
            circuit_ref: circuit_ref(),
            proof_suite: ZkProofSuite::PRODUCTION,
            artifacts: &artifacts,
            proof: &proof,
            expected_binding: binding(),
        })
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::BackendFailure);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn prover_crs_init_rejects_after_verifier_crs_state() -> Result<(), ZkError> {
    let _process_state_guard = lock_process_state_test()?;
    NativeBarretenbergBackend::set_process_state_for_test(
        BarretenbergVerifierCrsIdentity::pinned_modern_verifier(),
    )?;
    SRS_INIT_CALL_COUNT.store(0, Ordering::SeqCst);
    let backend = NativeBarretenbergBackend::from_transport(StaticTransport {
        response: SRS_SUCCESS_RESPONSE,
        required_command: b"SrsInitSrs",
        call_count: Some(&SRS_INIT_CALL_COUNT),
    });

    let error = backend
        .initialize_prover_crs(fake_prover_crs())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    assert_eq!(SRS_INIT_CALL_COUNT.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn verifier_crs_owner_rejects_arbitrary_self_consistent_bytes() -> Result<(), ZkError> {
    let crs = verifier_crs(1)?;
    let error = BarretenbergVerifierCrs::try_from_pinned_slices(crs.g1_prefix(), crs.g2_point())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}

#[test]
fn prover_crs_owner_rejects_short_or_arbitrary_bytes() -> Result<(), ZkError> {
    let crs = fake_prover_crs();
    let error = BarretenbergProverCrs::try_from_pinned_slices(crs.g1_prefix(), crs.g2_point())
        .err()
        .ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;

    assert_eq!(error.reason(), ZkErrorReason::ArtifactMismatch);
    Ok(())
}
