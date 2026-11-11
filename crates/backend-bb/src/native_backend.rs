// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Native Barretenberg provider wiring around the narrow BBAPI shim.

use std::{ptr, ptr::NonNull, slice};

use reallyme_zk_api::{
    errors::{ZkError, ZkErrorReason},
    proofs::{ZkProof, ZkProofSuite, ZkPublicInputs},
};
use zeroize::Zeroize;

mod crs;
mod exact_circuit;
use crs::{lock_bbapi_process_state, BarretenbergProcessCrsIdentity, BbapiProcessCrsState};
pub use crs::{
    BarretenbergProverCrs, BarretenbergProverCrsIdentity, BarretenbergVerifierCrs,
    BarretenbergVerifierCrsIdentity,
};

use crate::{
    bbapi_abi::{
        decode_circuit_prove_response, decode_circuit_verify_response, decode_srs_init_response,
        validate_message_length, BbapiCircuitProveCommand, BbapiCircuitVerifyCommand,
        BbapiSrsInitCommand,
    },
    BbStageProveRequest, BbStageProveResponse, BbStageVerifyRequest, LinkedBarretenbergBackend,
};

#[allow(unsafe_code)]
type BbapiCall = unsafe extern "C" fn(*const u8, usize, *mut *mut u8, *mut usize) -> u32;
#[allow(unsafe_code)]
type BbapiFree = unsafe extern "C" fn(*mut u8, usize);

const SHIM_STATUS_OK: u32 = 0;
const SHIM_STATUS_NULL_ARGUMENT: u32 = 1;
const SHIM_STATUS_EMPTY_INPUT: u32 = 2;
const SHIM_STATUS_UPSTREAM_EXCEPTION: u32 = 3;
const SHIM_STATUS_UPSTREAM_NULL_OUTPUT: u32 = 4;
const SHIM_STATUS_UPSTREAM_EMPTY_OUTPUT: u32 = 5;
const SHIM_STATUS_UPSTREAM_OUTPUT_TOO_LARGE: u32 = 6;
const SHIM_STATUS_INPUT_TOO_LARGE: u32 = 7;

struct BarretenbergBbapiResponse {
    bytes: Vec<u8>,
}

impl BarretenbergBbapiResponse {
    fn try_copy_from_slice(bytes: &[u8]) -> Result<Self, ZkError> {
        validate_message_length(bytes.len())?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        owned.extend_from_slice(bytes);
        Ok(Self { bytes: owned })
    }

    fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

impl Drop for BarretenbergBbapiResponse {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for BarretenbergBbapiResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BarretenbergBbapiResponse")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

trait BarretenbergBbapiTransport: Send + Sync {
    fn call(&self, command: &[u8]) -> Result<BarretenbergBbapiResponse, ZkError>;
}

struct BarretenbergBbapiOwnedOutput {
    ptr: NonNull<u8>,
    len: usize,
    free: BbapiFree,
}

impl BarretenbergBbapiOwnedOutput {
    /// Claims ownership before validating the reported length.
    ///
    /// # Safety
    ///
    /// `ptr` must be either null or a live allocation returned by the matching
    /// ReallyMe BBAPI C shim. `len` must be the allocation's reported byte
    /// length. When non-null, this guard takes exclusive ownership and releases
    /// the pointer exactly once through `free`, even if subsequent validation
    /// fails.
    #[allow(unsafe_code)]
    unsafe fn claim(ptr: *mut u8, len: usize, free: BbapiFree) -> Option<Self> {
        NonNull::new(ptr).map(|ptr| Self { ptr, len, free })
    }

    #[allow(unsafe_code)]
    fn try_copy_response(&self) -> Result<BarretenbergBbapiResponse, ZkError> {
        validate_message_length(self.len)?;
        // SAFETY: `claim` gives this guard exclusive ownership of the shim
        // allocation. The pointer is non-null, `self.len` is validated before
        // creating the slice, and the immutable borrow lives only until the
        // bytes are copied into Rust-owned memory.
        let bytes = unsafe { slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
        BarretenbergBbapiResponse::try_copy_from_slice(bytes)
    }
}

impl Drop for BarretenbergBbapiOwnedOutput {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: construction claims exclusive ownership of a pointer returned
        // by the paired shim and stores the corresponding destroy function.
        // Drop returns that exact pointer and length once and never reads it
        // afterward.
        unsafe {
            (self.free)(self.ptr.as_ptr(), self.len);
        }
    }
}

impl core::fmt::Debug for BarretenbergBbapiOwnedOutput {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BarretenbergBbapiOwnedOutput")
            .field("len", &self.len)
            .field("ptr", &"<redacted>")
            .finish()
    }
}

struct ShimBbapiTransport {
    call: BbapiCall,
    free: BbapiFree,
}

impl BarretenbergBbapiTransport for ShimBbapiTransport {
    #[allow(unsafe_code)]
    fn call(&self, command: &[u8]) -> Result<BarretenbergBbapiResponse, ZkError> {
        if command.is_empty() {
            return Err(ZkError::new(ZkErrorReason::EmptyInput));
        }

        let mut output = ptr::null_mut();
        let mut output_len = 0_usize;
        // SAFETY: `command` is an immutable Rust-owned byte slice and remains
        // live for the entire call. The output pointer slots are initialized
        // local variables owned by this stack frame, so the shim may write only
        // those slots. Any non-null returned allocation is claimed immediately
        // with the paired destroy function before status handling can return.
        let status = unsafe {
            (self.call)(
                command.as_ptr(),
                command.len(),
                &mut output,
                &mut output_len,
            )
        };
        // SAFETY: any non-null pointer originated from the paired shim call in
        // this function and is transferred to a guard that releases it exactly
        // once through the paired destroy function.
        let owned = unsafe { BarretenbergBbapiOwnedOutput::claim(output, output_len, self.free) };
        if status != SHIM_STATUS_OK {
            return Err(ZkError::new(map_shim_status(status)));
        }
        let owned = owned.ok_or(ZkError::new(ZkErrorReason::BackendFailure))?;
        owned.try_copy_response()
    }
}

const fn map_shim_status(status: u32) -> ZkErrorReason {
    match status {
        SHIM_STATUS_NULL_ARGUMENT
        | SHIM_STATUS_UPSTREAM_EXCEPTION
        | SHIM_STATUS_UPSTREAM_NULL_OUTPUT
        | SHIM_STATUS_UPSTREAM_EMPTY_OUTPUT => ZkErrorReason::BackendFailure,
        SHIM_STATUS_EMPTY_INPUT => ZkErrorReason::EmptyInput,
        SHIM_STATUS_UPSTREAM_OUTPUT_TOO_LARGE | SHIM_STATUS_INPUT_TOO_LARGE => {
            ZkErrorReason::MessageTooLarge
        }
        _ => ZkErrorReason::BackendFailure,
    }
}

/// Linked Barretenberg backend backed by the ReallyMe BBAPI C++ shim.
pub struct NativeBarretenbergBackend {
    transport: Box<dyn BarretenbergBbapiTransport>,
}

impl NativeBarretenbergBackend {
    /// Resolves the process-linked ReallyMe BBAPI shim.
    pub fn try_new() -> Result<Self, ZkError> {
        Ok(Self {
            transport: Box::new(ShimBbapiTransport {
                call: linked_bbapi::reallyme_bbapi_call,
                free: linked_bbapi::reallyme_bbapi_free,
            }),
        })
    }

    /// Initializes Barretenberg's process-global verifier-only CRS once.
    ///
    /// Repeating the same hash-pinned identity is idempotent. A different CRS
    /// identity is rejected because upstream Barretenberg treats SRS state as
    /// process-global; services that need proving must select and initialize a
    /// full prover CRS before any verifier-only initializer runs.
    pub fn initialize_verifier_crs(&self, crs: BarretenbergVerifierCrs<'_>) -> Result<(), ZkError> {
        let process_identity = BarretenbergProcessCrsIdentity::VerifierOnly(crs.identity());
        self.initialize_process_crs(process_identity, || {
            BbapiSrsInitCommand::try_new_verifier(crs.g1_prefix(), crs.g2_point())
        })
    }

    /// Initializes Barretenberg's process-global full prover CRS once.
    ///
    /// Barretenberg's SRS is process-global. A process that may prove should
    /// call this initializer before any verifier-only initializer so both
    /// proving and subsequent verification observe a single CRS profile.
    pub fn initialize_prover_crs(&self, crs: BarretenbergProverCrs<'_>) -> Result<(), ZkError> {
        let process_identity = BarretenbergProcessCrsIdentity::FullProver(crs.identity());
        self.initialize_process_crs(process_identity, || {
            BbapiSrsInitCommand::try_new_prover(crs.g1_prefix(), crs.g2_point())
        })
    }

    fn initialize_process_crs<F>(
        &self,
        process_identity: BarretenbergProcessCrsIdentity,
        build_command: F,
    ) -> Result<(), ZkError>
    where
        F: FnOnce() -> Result<BbapiSrsInitCommand, ZkError>,
    {
        let mut state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(identity) => {
                if identity.satisfies(process_identity) {
                    return Ok(());
                }
                return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
            BbapiProcessCrsState::Uninitialized => {}
        }

        let command = build_command()?;
        state.crs = BbapiProcessCrsState::Poisoned;
        let response = self.transport.call(command.as_bytes())?;
        match decode_srs_init_response(response.as_bytes()) {
            Ok(()) => {
                state.crs = BbapiProcessCrsState::Ready(process_identity);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[allow(unsafe_code)]
mod linked_bbapi;

impl LinkedBarretenbergBackend for NativeBarretenbergBackend {
    fn supports_proof_suite(&self, proof_suite: ZkProofSuite) -> bool {
        proof_suite == ZkProofSuite::PRODUCTION
    }

    fn prove_stage(
        &self,
        request: BbStageProveRequest<'_>,
    ) -> Result<BbStageProveResponse, ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION
            || request.artifacts.manifest().proof_suite() != ZkProofSuite::PRODUCTION
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.artifacts.manifest().bundle_kind() != request.bundle_kind
            || request.artifacts.manifest().stage() != request.stage
            || request.artifacts.manifest().circuit_ref() != request.circuit_ref
            || request.witness.circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }

        let command = BbapiCircuitProveCommand::try_new(request)?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::FullProver(_)) => {}
            BbapiProcessCrsState::Ready(BarretenbergProcessCrsIdentity::VerifierOnly(_))
            | BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        let proof = decode_circuit_prove_response(
            request.circuit_ref,
            request.artifacts.verification_key(),
            response.as_bytes(),
        )?;
        request
            .session_binding
            .decode_and_validate(request.circuit_ref, proof.public_inputs())?;
        self.verify_proved_stage_response(request, &proof)?;
        Ok(proof)
    }

    fn verify_stage(&self, request: BbStageVerifyRequest<'_>) -> Result<(), ZkError> {
        if request.proof_suite != ZkProofSuite::PRODUCTION
            || request.proof.proof_suite() != ZkProofSuite::PRODUCTION
            || request.artifacts.manifest().proof_suite() != ZkProofSuite::PRODUCTION
        {
            return Err(ZkError::new(ZkErrorReason::UnsupportedProofSuite));
        }
        if request.proof.circuit_ref() != request.circuit_ref
            || request.artifacts.manifest().bundle_kind() != request.bundle_kind
            || request.artifacts.manifest().stage() != request.stage
            || request.artifacts.manifest().circuit_ref() != request.circuit_ref
        {
            return Err(ZkError::new(ZkErrorReason::StageMismatch));
        }
        if request.proof.artifact_identity()
            != request.artifacts.manifest().manifest_sha256().into()
        {
            return Err(ZkError::new(ZkErrorReason::ArtifactMismatch));
        }
        request
            .expected_binding
            .decode_and_validate(request.circuit_ref, request.proof.public_inputs())?;

        let command = BbapiCircuitVerifyCommand::try_new(
            request.artifacts.verification_key(),
            request.proof,
        )?;
        let state = lock_bbapi_process_state()?;
        match state.crs {
            BbapiProcessCrsState::Ready(_) => {}
            BbapiProcessCrsState::Uninitialized => {
                return Err(ZkError::new(ZkErrorReason::BackendUnavailable));
            }
            BbapiProcessCrsState::Poisoned => {
                return Err(ZkError::new(ZkErrorReason::BackendFailure));
            }
        }
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }

    fn verify_common_credential_root_raw(
        &self,
        request: crate::BbCommonCredentialRootRawVerifyRequest<'_>,
    ) -> Result<(), ZkError> {
        Self::verify_common_credential_root_raw_exact_circuit(self, request)
    }
}

impl NativeBarretenbergBackend {
    fn verify_proved_stage_response(
        &self,
        request: BbStageProveRequest<'_>,
        response: &BbStageProveResponse,
    ) -> Result<(), ZkError> {
        let public_inputs =
            ZkPublicInputs::try_copy_from_slice(response.public_inputs().as_bytes())?;
        let proof = ZkProof::try_from_exact_parts(
            request.bundle_kind.circuit_id(),
            request.circuit_ref,
            request.proof_suite,
            request.artifacts.manifest().manifest_sha256(),
            response.proof_bytes().as_bytes().to_vec(),
            public_inputs,
        )?;
        let command =
            BbapiCircuitVerifyCommand::try_new(request.artifacts.verification_key(), &proof)?;
        let response = self.transport.call(command.as_bytes())?;
        decode_circuit_verify_response(response.as_bytes())
    }
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests;
