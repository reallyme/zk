// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Typed public-statement decoding for structurally complete proof bundles.

use crate::{
    claim_bundle::{ZkClaimProofBundle, ZkClaimedStatement},
    errors::{ZkError, ZkErrorReason},
    keys::{ZkIssuerPublicKey, ZkPersonaPublicKey},
};

impl ZkClaimProofBundle {
    /// Decodes the typed statement claimed by the structurally complete bundle.
    ///
    /// This performs ABI and cross-stage consistency checks only. The value
    /// becomes verified exclusively after an injected bundle verifier accepts
    /// every proof plus active binding, issuer trust, and presentation-time
    /// policy. Credential validity and status remain separate unsupported
    /// requirements in the v1 claim proof bundles.
    pub fn decode_claimed_statement(&self) -> Result<ZkClaimedStatement, ZkError> {
        let mut issuer = None;
        let mut persona = None;
        let mut credential_binding = None;
        let mut claim_name_hash = None;
        let mut claim_value = None;
        let mut claim_value_length = None;
        let mut expiry_unix = None;
        for stage_proof in self.stage_proofs() {
            let circuit_ref = stage_proof.proof().circuit_ref();
            let decoded = self
                .session_binding()
                .decode_and_validate(circuit_ref, stage_proof.proof().public_inputs())?;
            require_consistent(&mut expiry_unix, decoded.expiry_unix())?;
            if let Some(key) = decoded.issuer_key {
                require_consistent(&mut issuer, ZkIssuerPublicKey { x: key.x, y: key.y })?;
            }
            if let Some(key) = decoded.persona_key {
                require_consistent(&mut persona, ZkPersonaPublicKey { x: key.x, y: key.y })?;
            }
            require_optional_consistent(&mut credential_binding, decoded.credential_binding())?;
            require_optional_consistent(&mut claim_name_hash, decoded.claim_name_hash())?;
            require_optional_consistent(&mut claim_value, decoded.value())?;
            require_optional_consistent(&mut claim_value_length, decoded.value_length())?;
        }

        ZkClaimedStatement::try_from_parts(
            issuer.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            persona,
            credential_binding.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            claim_name_hash.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            claim_value.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            claim_value_length.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
            expiry_unix.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))?,
        )
    }

    /// Decodes the claimed session-link commitment from the bundle.
    ///
    /// This is structural public-input decoding only. Callers must not treat
    /// the value as verified until an injected bundle verifier accepts the
    /// complete proof bundle for the active request.
    pub fn session_link_commitment(&self) -> Result<[u8; 32], ZkError> {
        let mut commitment = None;
        for stage_proof in self.stage_proofs() {
            let circuit_ref = stage_proof.proof().circuit_ref();
            let decoded = self
                .session_binding()
                .decode_and_validate(circuit_ref, stage_proof.proof().public_inputs())?;
            require_optional_consistent(&mut commitment, decoded.session_binding())?;
        }
        commitment.ok_or(ZkError::new(ZkErrorReason::InvalidProofEncoding))
    }
}

fn require_consistent<T: Copy + Eq>(slot: &mut Option<T>, value: T) -> Result<(), ZkError> {
    if let Some(existing) = slot {
        if *existing != value {
            return Err(ZkError::new(ZkErrorReason::BindingMismatch));
        }
    } else {
        *slot = Some(value);
    }
    Ok(())
}

fn require_optional_consistent<T: Copy + Eq>(
    slot: &mut Option<T>,
    value: Option<T>,
) -> Result<(), ZkError> {
    if let Some(value) = value {
        require_consistent(slot, value)?;
    }
    Ok(())
}
