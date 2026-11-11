// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

/// Raw Barretenberg public-input streams from nine verified proofs.
///
/// Each byte of a Noir public byte array occupies one canonical BN254 field.
/// Callers must verify every proof and its exact artifact before passing its
/// public inputs here; this structure deliberately carries no verification token.
#[derive(Clone, Copy)]
pub struct ZkCommonCredentialRootPublicInputs<'a> {
    /// ReallyMe root attestation proof.
    pub attestation: &'a [u8],
    /// Exact-instance active-status proof.
    pub status: &'a [u8],
    /// Issuer lineage proofs, in requested credential-role order.
    pub lineage: [&'a [u8]; 2],
    /// Selected-claim proofs, in the same credential-role order.
    pub selected_claim: [&'a [u8]; 2],
    /// Presenting persona's fresh session proof.
    pub session: &'a [u8],
    /// Issuer-signed validity and current status proofs, in credential-role order.
    pub issuer_credential_status: [&'a [u8]; 2],
}

/// Verifier-authenticated current issuer status list for one credential role.
///
/// The caller verifies the SSI status-list signature and trust key, exact list
/// identity and purpose, freshness, and a durable latest-list floor before
/// constructing this expectation. A holder-supplied root is never sufficient.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ZkCommonCredentialRootIssuerStatusExpectation {
    /// Merkle commitment to the authenticated current status bitstring.
    pub root: [u8; 32],
    /// Exact signed bitstring length.
    pub length: u64,
    /// Shared status-list identity, distinct from the private entry index.
    pub list_id: [u8; 32],
    /// SHA-256 of the issuer-signed status-list URL.
    pub url_hash: [u8; 32],
    /// Exact status meaning selected by verifier policy.
    pub purpose: ZkIssuerStatusPurpose,
}

/// One verifier-requested claim and trusted issuer key.
///
/// These expectations come from authenticated verifier policy. Copying the
/// holder's claimed name, issuer, or value into this structure would make the
/// comparison tautological and would not authorize the disclosure.
#[derive(Clone, Copy)]
pub struct ZkCommonCredentialRootClaimExpectation<'a> {
    /// Exact issuer key trusted for this credential role.
    pub issuer: ZkIssuerPublicKey,
    /// Hash of the claim name requested for this role.
    pub claim_name_hash: [u8; 32],
    /// Exact selected disclosure expected by this request.
    pub value: &'a [u8],
}

/// Verifier-owned session and assurance policy for one common-credential-root presentation.
///
/// The caller must independently validate the signature, freshness, and
/// issuer of the global active-status snapshot represented by `status_root`.
/// The active request and both claim expectations must be verifier-owned.
#[derive(Clone, Copy)]
pub struct ZkCommonCredentialRootJoinPolicy<'a> {
    /// OpenID4VP challenge computed from the active nonce.
    pub challenge: [u8; 32],
    /// Hash of the active verifier identity.
    pub audience_hash: [u8; 32],
    /// Active transaction-data hash or the canonical absence sentinel.
    pub transaction_data_hash: [u8; 32],
    /// Trusted verifier request time, never holder supplied.
    pub request_time_unix: u64,
    /// Verifier-owned time used to validate current issuer status.
    pub status_validation_time_unix: u64,
    /// Maximum age accepted for holder-produced current status proofs.
    pub status_validation_max_age_seconds: u64,
    /// Trusted ReallyMe attestation signing key.
    pub attestation_signer: ZkAttestationPublicKey,
    /// Accepted root-assurance policy identifier.
    pub assurance_policy_id: [u8; 32],
    /// Root of a separately authenticated, current active-status snapshot.
    pub status_root: [u8; 32],
    /// Credential roles in the order requested by the verifier.
    pub claims: [ZkCommonCredentialRootClaimExpectation<'a>; 2],
    /// Authenticated current issuer status lists, in credential-role order.
    pub issuer_status: [ZkCommonCredentialRootIssuerStatusExpectation; 2],
    /// Persona disclosure mode requested for this presentation.
    pub persona_mode: ZkCommonCredentialRootPersonaMode,
}

/// Checks canonical input shape, active request, trusted keys, ordered slots,
/// attestation/lineage/subject joins, claims, and persona session equality.
///
/// This is a policy and composition check, not cryptographic verification.
/// A caller must first verify all nine proofs against hash-lane-specific,
/// pinned artifacts; accepting this function's result alone is unsound.
pub fn check_common_credential_root_v1_joins(
    inputs: ZkCommonCredentialRootPublicInputs<'_>,
    policy: ZkCommonCredentialRootJoinPolicy<'_>,
) -> Result<(), ZkError> {
    if policy.request_time_unix == 0
        || policy.status_validation_time_unix < policy.request_time_unix
    {
        return Err(error(ZkErrorReason::PresentationExpired));
    }
    for claim in &policy.claims {
        if claim.value.is_empty() || claim.value.len() > CLAIM_VALUE_BYTES {
            return Err(error(ZkErrorReason::ClaimPayloadTooLarge));
        }
        if claim.claim_name_hash == RESERVED_LINEAGE_NAME_HASH {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
    }

    let attestation = Fields::new(inputs.attestation, ATTESTATION_FIELDS)?;
    let status = Fields::new(inputs.status, STATUS_FIELDS)?;
    let request = RequestFields::from_attestation(attestation)?;
    request.check_policy(&policy)?;
    if ZkP256PublicKey::from(attestation.key(0)?)
        != ZkP256PublicKey::from(policy.attestation_signer)
    {
        return Err(error(ZkErrorReason::UntrustedIssuer));
    }
    if attestation.bytes32(64)? != policy.assurance_policy_id
        || attestation.u64(96)? != policy.request_time_unix
        || status.bytes32(96)? != policy.status_root
    {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    request.check_fields(status, 0)?;
    let attestation_presentation_expiry = attestation.u64(97)?;
    check_expiry(attestation_presentation_expiry, policy.request_time_unix)?;
    let root_join = attestation.bytes32(194)?;
    let attestation_join = attestation.bytes32(226)?;
    if status.bytes32(128)? != root_join || status.bytes32(160)? != attestation_join {
        return Err(error(ZkErrorReason::BindingMismatch));
    }

    let (claim_fields, claim_offset, session_fields, session_offset) = match policy.persona_mode {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => (
            CREDENTIAL_SUBJECT_CLAIM_FIELDS,
            0,
            PRIVATE_SESSION_FIELDS,
            0,
        ),
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            (PUBLIC_CLAIM_FIELDS, 64, PUBLIC_SESSION_FIELDS, 64)
        }
    };
    let session = Fields::new(inputs.session, session_fields)?;
    request.check_fields(session, session_offset)?;
    let session_expiry = session.u64(field_index(session_offset, 96)?)?;
    check_expiry(session_expiry, policy.request_time_unix)?;
    if attestation_presentation_expiry != session_expiry {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    if session_expiry <= policy.status_validation_time_unix {
        return Err(error(ZkErrorReason::PresentationExpired));
    }
    let session_binding = session.bytes32(field_index(session_offset, 97)?)?;
    let persona_key = if policy.persona_mode == ZkCommonCredentialRootPersonaMode::PublicPersona {
        Some(session.key(0)?)
    } else {
        None
    };

    let mut previous_credential_binding = None;
    for (slot, expected) in policy.claims.iter().enumerate() {
        let lineage = Fields::new(inputs.lineage[slot], LINEAGE_FIELDS)?;
        let claim = Fields::new(inputs.selected_claim[slot], claim_fields)?;
        let issuer_status = Fields::new(
            inputs.issuer_credential_status[slot],
            ISSUER_CREDENTIAL_STATUS_FIELDS,
        )?;
        request.check_fields(lineage, 0)?;
        request.check_fields(claim, field_index(claim_offset, 64)?)?;
        request.check_fields(issuer_status, 0)?;

        let lineage_key = lineage.key(128)?;
        let claim_key = claim.key(0)?;
        let status_key = issuer_status.key(96)?;
        if lineage_key != expected.issuer
            || claim_key != expected.issuer
            || status_key != expected.issuer
        {
            return Err(error(ZkErrorReason::UntrustedIssuer));
        }
        let expiry = lineage.u64(192)?;
        check_expiry(expiry, policy.request_time_unix)?;
        let credential_binding = lineage.bytes32(193)?;
        if Some(credential_binding) == previous_credential_binding {
            return Err(error(ZkErrorReason::InvalidClaimProofBundle));
        }
        previous_credential_binding = Some(credential_binding);
        let expected_status = policy.issuer_status[slot];
        if issuer_status.u64(160)? != expiry
            || issuer_status.bytes32(161)? != credential_binding
            || issuer_status.bytes32(193)? != expected_status.root
            || issuer_status.u64(225)? != expected_status.length
            || issuer_status.bytes32(226)? != expected_status.list_id
            || issuer_status.bytes32(258)? != expected_status.url_hash
            || issuer_status.byte(290)? != expected_status.purpose.wire_value()
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }
        let issuer_status_validation_time = issuer_status.u64(291)?;
        let status_age = policy
            .status_validation_time_unix
            .checked_sub(issuer_status_validation_time)
            .ok_or(error(ZkErrorReason::PresentationExpired))?;
        if issuer_status_validation_time < policy.request_time_unix
            || issuer_status_validation_time >= expiry
            || issuer_status_validation_time > policy.status_validation_time_unix
            || status_age > policy.status_validation_max_age_seconds
        {
            return Err(error(ZkErrorReason::PresentationExpired));
        }
        if lineage.bytes32(96)? != root_join
            || lineage.bytes32(225)? != claim.bytes32(field_index(claim_offset, 225)?)?
            || expiry != claim.u64(field_index(claim_offset, 160)?)?
            || expiry != session_expiry
            || credential_binding != claim.bytes32(field_index(claim_offset, 193)?)?
            || session_binding != claim.bytes32(field_index(claim_offset, 161)?)?
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }
        if policy.persona_mode == ZkCommonCredentialRootPersonaMode::PublicPersona
            && Some(claim.key(64)?) != persona_key
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }

        let value_length = usize::try_from(claim.u32(field_index(claim_offset, 257)?)?)
            .map_err(|_| error(ZkErrorReason::LengthOverflow))?;
        if value_length == 0 || value_length > CLAIM_VALUE_BYTES {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        let value = claim.bytes64(field_index(claim_offset, 258)?)?;
        if value[value_length..].iter().any(|byte| *byte != 0) {
            return Err(error(ZkErrorReason::InvalidProofEncoding));
        }
        if value_length != expected.value.len()
            || value[..value_length] != *expected.value
            || claim.bytes32(field_index(claim_offset, 322)?)? != expected.claim_name_hash
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct RequestFields {
    challenge: [u8; 32],
    audience: [u8; 32],
    transaction: [u8; 32],
}

impl RequestFields {
    fn from_attestation(fields: Fields<'_>) -> Result<Self, ZkError> {
        Ok(Self {
            challenge: fields.bytes32(98)?,
            audience: fields.bytes32(130)?,
            transaction: fields.bytes32(162)?,
        })
    }

    fn check_policy(self, policy: &ZkCommonCredentialRootJoinPolicy<'_>) -> Result<(), ZkError> {
        if self.challenge != policy.challenge
            || self.audience != policy.audience_hash
            || self.transaction != policy.transaction_data_hash
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }

    fn check_fields(self, fields: Fields<'_>, offset: usize) -> Result<(), ZkError> {
        if self.challenge != fields.bytes32(offset)?
            || self.audience != fields.bytes32(field_index(offset, 32)?)?
            || self.transaction != fields.bytes32(field_index(offset, 64)?)?
        {
            return Err(error(ZkErrorReason::BindingMismatch));
        }
        Ok(())
    }
}

fn check_expiry(expiry: u64, request_time: u64) -> Result<(), ZkError> {
    let lifetime = expiry
        .checked_sub(request_time)
        .ok_or(error(ZkErrorReason::PresentationExpired))?;
    if lifetime == 0 {
        return Err(error(ZkErrorReason::PresentationExpired));
    }
    if lifetime > MAX_PRESENTATION_LIFETIME_SECONDS {
        return Err(error(ZkErrorReason::PresentationExpiryTooFar));
    }
    Ok(())
}

fn derive_root_join(
    salt: &[u8; JOIN_SALT_BYTES],
    inputs: &ZkCommonCredentialRootJoinDerivationInputs<'_>,
) -> Result<[u8; 32], ZkError> {
    let mut preimage = Zeroizing::new(
        [0_u8; ROOT_JOIN_DOMAIN.len() + FIELD_BYTES + JOIN_SALT_BYTES + FIELD_BYTES * 3],
    );
    let mut offset = 0_usize;
    write_bytes(preimage.as_mut(), offset, ROOT_JOIN_DOMAIN)?;
    offset = advance(offset, ROOT_JOIN_DOMAIN.len())?;
    write_bytes(preimage.as_mut(), offset, inputs.root)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(preimage.as_mut(), offset, salt)?;
    offset = advance(offset, JOIN_SALT_BYTES)?;
    write_request(preimage.as_mut(), offset, inputs.request)?;
    Ok(sha256_array(preimage.as_ref()))
}

fn derive_attestation_join(
    salt: &[u8; JOIN_SALT_BYTES],
    inputs: &ZkCommonCredentialRootJoinDerivationInputs<'_>,
) -> Result<[u8; 32], ZkError> {
    let mut preimage = Zeroizing::new(
        [0_u8; ATTESTATION_JOIN_DOMAIN.len() + FIELD_BYTES + JOIN_SALT_BYTES + FIELD_BYTES * 3],
    );
    let mut offset = 0_usize;
    write_bytes(preimage.as_mut(), offset, ATTESTATION_JOIN_DOMAIN)?;
    offset = advance(offset, ATTESTATION_JOIN_DOMAIN.len())?;
    write_bytes(preimage.as_mut(), offset, inputs.attestation_id)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(preimage.as_mut(), offset, salt)?;
    offset = advance(offset, JOIN_SALT_BYTES)?;
    write_request(preimage.as_mut(), offset, inputs.request)?;
    Ok(sha256_array(preimage.as_ref()))
}

fn derive_subject_join(
    salt: &[u8; JOIN_SALT_BYTES],
    request: ZkCommonCredentialRootRequestJoinContext,
    subject: ZkCommonCredentialRootSubjectPublicKey,
) -> Result<[u8; 32], ZkError> {
    let mut preimage = Zeroizing::new(
        [0_u8; SUBJECT_JOIN_DOMAIN.len() + FIELD_BYTES * 2 + JOIN_SALT_BYTES + FIELD_BYTES * 3],
    );
    let mut offset = 0_usize;
    write_bytes(preimage.as_mut(), offset, SUBJECT_JOIN_DOMAIN)?;
    offset = advance(offset, SUBJECT_JOIN_DOMAIN.len())?;
    write_bytes(preimage.as_mut(), offset, &subject.x)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(preimage.as_mut(), offset, &subject.y)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(preimage.as_mut(), offset, salt)?;
    offset = advance(offset, JOIN_SALT_BYTES)?;
    write_request(preimage.as_mut(), offset, request)?;
    Ok(sha256_array(preimage.as_ref()))
}

fn write_request(
    target: &mut [u8],
    offset: usize,
    request: ZkCommonCredentialRootRequestJoinContext,
) -> Result<(), ZkError> {
    write_bytes(target, offset, &request.challenge)?;
    let offset = advance(offset, FIELD_BYTES)?;
    write_bytes(target, offset, &request.audience_hash)?;
    let offset = advance(offset, FIELD_BYTES)?;
    write_bytes(target, offset, &request.transaction_data_hash)?;
    Ok(())
}

fn validate_request(request: ZkCommonCredentialRootRequestJoinContext) -> Result<(), ZkError> {
    validate_nonzero32(&request.challenge)?;
    validate_nonzero32(&request.audience_hash)?;
    validate_nonzero32(&request.transaction_data_hash)?;
    Ok(())
}

fn validate_key(key: impl Into<ZkP256PublicKey>) -> Result<(), ZkError> {
    let key = key.into();
    if key.x.iter().all(|byte| *byte == 0) && key.y.iter().all(|byte| *byte == 0) {
        return Err(error(ZkErrorReason::UntrustedIssuer));
    }
    Ok(())
}

fn validate_subject(subject: ZkCommonCredentialRootSubjectPublicKey) -> Result<(), ZkError> {
    if subject.x.iter().all(|byte| *byte == 0) && subject.y.iter().all(|byte| *byte == 0) {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn validate_nonzero32(value: &[u8; 32]) -> Result<(), ZkError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn validate_nonzero64(value: &[u8; SIGNATURE_BYTES]) -> Result<(), ZkError> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn sha256_array(preimage: &[u8]) -> [u8; 32] {
    let digest = sha2_256_digest(preimage);
    let mut output = [0_u8; 32];
    output.copy_from_slice(digest.as_bytes());
    output
}

fn write_bytes(target: &mut [u8], offset: usize, value: &[u8]) -> Result<(), ZkError> {
    let end = advance(offset, value.len())?;
    let slot = target
        .get_mut(offset..end)
        .ok_or(error(ZkErrorReason::LengthOverflow))?;
    slot.copy_from_slice(value);
    Ok(())
}

fn advance(offset: usize, count: usize) -> Result<usize, ZkError> {
    offset
        .checked_add(count)
        .ok_or(error(ZkErrorReason::LengthOverflow))
}

fn field_index(base: usize, offset: usize) -> Result<usize, ZkError> {
    base.checked_add(offset)
        .ok_or(error(ZkErrorReason::LengthOverflow))
}

const fn error(reason: ZkErrorReason) -> ZkError {
    ZkError::new(reason)
}

#[cfg(test)]
mod tests;
