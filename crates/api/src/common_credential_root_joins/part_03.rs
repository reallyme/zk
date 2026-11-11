// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn credential_slot_index(
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<usize, ZkCommonCredentialRootStageInputError> {
    match slot {
        ZkCommonCredentialRootProofSlot::Lineage0
        | ZkCommonCredentialRootProofSlot::SelectedClaim0
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => Ok(0),
        ZkCommonCredentialRootProofSlot::Lineage1
        | ZkCommonCredentialRootProofSlot::SelectedClaim1
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => Ok(1),
        _ => Err(ZkCommonCredentialRootStageInputError::MissingCredentialSlot),
    }
}

/// Derives the stable attestation identifier used by the active-status proof.
///
/// This is transcript derivation for witness construction only. It does not
/// verify `attestation_signature`, authenticate the attestation, or authorize a
/// status snapshot. The proving circuit, concrete provider, and verifier-owned
/// policy checks remain responsible for attestation authenticity.
pub fn derive_common_credential_root_attestation_id(
    material: ZkCommonCredentialRootAttestationMaterial<'_>,
) -> Result<[u8; 32], ZkError> {
    validate_nonzero32(material.root)?;
    if material.request_time_unix == 0
        || material.attestation_issued_unix > material.request_time_unix
        || material.request_time_unix >= material.attestation_expires_unix
    {
        return Err(error(ZkErrorReason::PresentationExpired));
    }
    let commitment = common_credential_root_root_commitment(material.root)?;
    derive_common_credential_root_attestation_id_from_commitment(
        ZkCommonCredentialRootAttestationCommitmentMaterial {
            reallyme_public_key: material.reallyme_public_key,
            assurance_policy_id: material.assurance_policy_id,
            root_commitment: &commitment,
            attestation_issued_unix: material.attestation_issued_unix,
            attestation_expires_unix: material.attestation_expires_unix,
            attestation_epoch: material.attestation_epoch,
            attestation_signature: material.attestation_signature,
        },
    )
}

/// Derive the active-set identifier from the authority-visible commitment.
///
/// This is low-level transcript derivation only. It deliberately accepts only
/// `C`, never the holder root `R`, and canonicalizes high-S P-256 signatures so
/// deterministic vector checks match the verified status-publication path.
/// It does not authenticate `attestation_signature`, pin the authority signer,
/// or enforce a deployment policy. Production status publication should use
/// the trusted attestation path:
/// [`crate::common_root::ZkRootAssuranceAttestation::attestation_id_for_status_publication`].
/// That ensures the active set is populated only after signature and
/// trust-policy checks.
pub fn derive_common_credential_root_attestation_id_from_commitment(
    material: ZkCommonCredentialRootAttestationCommitmentMaterial<'_>,
) -> Result<[u8; 32], ZkError> {
    validate_key(material.reallyme_public_key)?;
    validate_nonzero32(material.root_commitment)?;
    validate_nonzero32(&material.assurance_policy_id)?;
    validate_nonzero64(material.attestation_signature)?;
    if material.attestation_issued_unix == 0
        || material.attestation_expires_unix <= material.attestation_issued_unix
    {
        return Err(error(ZkErrorReason::PresentationExpired));
    }

    let attestation_digest = Zeroizing::new(common_credential_root_attestation_signing_digest(
        material.root_commitment,
        material.assurance_policy_id,
        material.attestation_issued_unix,
        material.attestation_expires_unix,
        material.attestation_epoch,
    )?);
    let signature = Zeroizing::new(normalize_common_credential_root_p256_signature_low_s(
        *material.attestation_signature,
    )?);

    let mut id_preimage = Zeroizing::new(
        [0_u8;
            ROOT_ATTESTATION_ID_DOMAIN.len()
                + FIELD_BYTES
                + FIELD_BYTES
                + FIELD_BYTES
                + SIGNATURE_BYTES],
    );
    let mut offset = 0;
    write_bytes(id_preimage.as_mut(), offset, ROOT_ATTESTATION_ID_DOMAIN)?;
    offset = advance(offset, ROOT_ATTESTATION_ID_DOMAIN.len())?;
    write_bytes(
        id_preimage.as_mut(),
        offset,
        &material.reallyme_public_key.x,
    )?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(
        id_preimage.as_mut(),
        offset,
        &material.reallyme_public_key.y,
    )?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(id_preimage.as_mut(), offset, attestation_digest.as_slice())?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(id_preimage.as_mut(), offset, signature.as_ref())?;
    Ok(sha256_array(id_preimage.as_ref()))
}

/// Return the canonical low-S representative for a P-256 `r || s` signature.
///
/// Noir's secp256r1 verifier accepts the canonical low-S form used by the
/// Barretenberg backend. This helper is deliberately independent of issuer,
/// holder, and persona roles so SDKs canonicalize at every ZK witness boundary
/// without changing the original credential envelope or transport bytes.
pub fn normalize_common_credential_root_p256_signature_low_s(
    signature: [u8; SIGNATURE_BYTES],
) -> Result<[u8; SIGNATURE_BYTES], ZkError> {
    validate_p256_signature_scalar(
        signature
            .get(..FIELD_BYTES)
            .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?,
    )?;
    validate_p256_signature_scalar(
        signature
            .get(FIELD_BYTES..)
            .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?,
    )?;

    let s = signature
        .get(FIELD_BYTES..)
        .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?;
    if p256_signature_scalar_cmp(s, &P256_HALF_CURVE_ORDER)? != core::cmp::Ordering::Greater {
        return Ok(signature);
    }

    let low_s = p256_signature_scalar_subtract(&P256_CURVE_ORDER, s)?;
    let mut normalized = signature;
    normalized
        .get_mut(FIELD_BYTES..)
        .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?
        .copy_from_slice(&low_s);
    Ok(normalized)
}

fn validate_p256_signature_scalar(scalar: &[u8]) -> Result<(), ZkError> {
    if scalar.len() != FIELD_BYTES
        || scalar.iter().all(|byte| *byte == 0)
        || p256_signature_scalar_cmp(scalar, &P256_CURVE_ORDER)? != core::cmp::Ordering::Less
    {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    Ok(())
}

fn p256_signature_scalar_cmp(
    left: &[u8],
    right: &[u8; FIELD_BYTES],
) -> Result<core::cmp::Ordering, ZkError> {
    if left.len() != FIELD_BYTES {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    for (left_byte, right_byte) in left.iter().zip(right.iter()) {
        match left_byte.cmp(right_byte) {
            core::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    Ok(core::cmp::Ordering::Equal)
}

fn p256_signature_scalar_subtract(
    left: &[u8; FIELD_BYTES],
    right: &[u8],
) -> Result<[u8; FIELD_BYTES], ZkError> {
    if right.len() != FIELD_BYTES {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    let mut output = [0_u8; FIELD_BYTES];
    let mut borrow = 0_u16;
    for ((output_byte, left_byte), right_byte) in output
        .iter_mut()
        .rev()
        .zip(left.iter().rev())
        .zip(right.iter().rev())
    {
        let minuend = u16::from(*left_byte);
        let subtrahend = u16::from(*right_byte)
            .checked_add(borrow)
            .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?;
        let (value, next_borrow) = if minuend >= subtrahend {
            (
                minuend
                    .checked_sub(subtrahend)
                    .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?,
                0_u16,
            )
        } else {
            (
                minuend
                    .checked_add(256)
                    .and_then(|value| value.checked_sub(subtrahend))
                    .ok_or_else(|| error(ZkErrorReason::BindingMismatch))?,
                1_u16,
            )
        };
        *output_byte = u8::try_from(value).map_err(|_| error(ZkErrorReason::BindingMismatch))?;
        borrow = next_borrow;
    }
    if borrow != 0 {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    Ok(output)
}

/// Commit to a wallet-owned random root before requesting ReallyMe assurance.
///
/// The commitment may be shown to the attestation authority. It must not be
/// reused as a public credential subject or verifier-facing identifier.
pub fn common_credential_root_root_commitment(
    root: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, ZkError> {
    validate_nonzero32(root)?;
    let mut root_preimage = Zeroizing::new([0_u8; ROOT_COMMITMENT_DOMAIN.len() + FIELD_BYTES]);
    write_bytes(root_preimage.as_mut(), 0, ROOT_COMMITMENT_DOMAIN)?;
    write_bytes(root_preimage.as_mut(), ROOT_COMMITMENT_DOMAIN.len(), root)?;
    Ok(Zeroizing::new(sha256_array(root_preimage.as_ref())))
}

/// Exact P-256 prehash signed by the ReallyMe root-assurance authority.
///
/// The issuer signs this digest directly with a digest-signing API. It must
/// not hash the returned digest a second time. The resulting signature is
/// privately bound to the root in the v1 attestation circuit.
pub fn common_credential_root_attestation_signing_digest(
    root_commitment: &[u8; 32],
    assurance_policy_id: [u8; 32],
    attestation_issued_unix: u64,
    attestation_expires_unix: u64,
    attestation_epoch: u32,
) -> Result<[u8; 32], ZkError> {
    validate_nonzero32(root_commitment)?;
    validate_nonzero32(&assurance_policy_id)?;
    if attestation_expires_unix <= attestation_issued_unix {
        return Err(error(ZkErrorReason::PresentationExpired));
    }

    let mut attestation_preimage = Zeroizing::new(
        [0_u8; ROOT_ATTESTATION_DOMAIN.len() + FIELD_BYTES + FIELD_BYTES + 8 + 8 + 4],
    );
    let mut offset = 0_usize;
    write_bytes(
        attestation_preimage.as_mut(),
        offset,
        ROOT_ATTESTATION_DOMAIN,
    )?;
    offset = advance(offset, ROOT_ATTESTATION_DOMAIN.len())?;
    write_bytes(attestation_preimage.as_mut(), offset, root_commitment)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(attestation_preimage.as_mut(), offset, &assurance_policy_id)?;
    offset = advance(offset, FIELD_BYTES)?;
    write_bytes(
        attestation_preimage.as_mut(),
        offset,
        &attestation_issued_unix.to_be_bytes(),
    )?;
    offset = advance(offset, 8)?;
    write_bytes(
        attestation_preimage.as_mut(),
        offset,
        &attestation_expires_unix.to_be_bytes(),
    )?;
    offset = advance(offset, 8)?;
    write_bytes(
        attestation_preimage.as_mut(),
        offset,
        &attestation_epoch.to_be_bytes(),
    )?;
    Ok(sha256_array(attestation_preimage.as_ref()))
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn common_credential_root_attestation_digest(
    material: &ZkCommonCredentialRootAttestationMaterial<'_>,
) -> Result<[u8; 32], ZkError> {
    let commitment = common_credential_root_root_commitment(material.root)?;
    common_credential_root_attestation_signing_digest(
        &commitment,
        material.assurance_policy_id,
        material.attestation_issued_unix,
        material.attestation_expires_unix,
        material.attestation_epoch,
    )
}

/// Verify a private attestation against a separately pinned ReallyMe signer
/// and assurance policy before wallet proving. The circuit repeats the
/// signature check and the remote verifier checks its own authority policy.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn verify_common_credential_root_attestation_material(
    material: ZkCommonCredentialRootAttestationMaterial<'_>,
    trust: ZkCommonCredentialRootAttestationTrustPolicy,
) -> Result<[u8; 32], ZkError> {
    if material.reallyme_public_key != trust.signer {
        return Err(error(ZkErrorReason::UntrustedIssuer));
    }
    if material.assurance_policy_id != trust.assurance_policy_id {
        return Err(error(ZkErrorReason::BindingMismatch));
    }
    // Preserve the digest/message type boundary and clear the digest owner on
    // drop; accepting an untyped slice here risks accidental double hashing.
    let digest =
        crypto_p256::P256Sha256Digest::new(common_credential_root_attestation_digest(&material)?);
    let signer = material.reallyme_public_key;
    let signature = Zeroizing::new(normalize_common_credential_root_p256_signature_low_s(
        *material.attestation_signature,
    )?);
    let normalized_material = ZkCommonCredentialRootAttestationMaterial {
        reallyme_public_key: material.reallyme_public_key,
        assurance_policy_id: material.assurance_policy_id,
        request_time_unix: material.request_time_unix,
        root: material.root,
        attestation_issued_unix: material.attestation_issued_unix,
        attestation_expires_unix: material.attestation_expires_unix,
        attestation_epoch: material.attestation_epoch,
        attestation_signature: &signature,
    };
    let id = Zeroizing::new(derive_common_credential_root_attestation_id(
        normalized_material,
    )?);
    let mut public_key = [0_u8; 65];
    public_key[0] = 0x04;
    public_key[1..33].copy_from_slice(&signer.x);
    public_key[33..65].copy_from_slice(&signer.y);
    let signature_der = Zeroizing::new(
        crypto_p256::p256_ecdsa_jose_signature_to_der(signature.as_ref())
            .map_err(|_| error(ZkErrorReason::InvalidProof))?,
    );
    crypto_p256::verify_p256_sha256_digest_low_s_der(
        signature_der.as_slice(),
        &digest,
        &public_key,
    )
    .map_err(|_| error(ZkErrorReason::InvalidProof))?;
    Ok(*id)
}

/// Consumes a one-use salt and derives all public joins for a presentation.
pub fn derive_common_credential_root_presentation_joins(
    salt: ZkCommonCredentialRootPresentationSalt,
    inputs: ZkCommonCredentialRootJoinDerivationInputs<'_>,
) -> Result<ZkCommonCredentialRootPresentationJoins, ZkError> {
    derive_common_credential_root_presentation_joins_for_material(&salt, &inputs)
}

fn derive_common_credential_root_presentation_joins_for_material(
    salt: &ZkCommonCredentialRootPresentationSalt,
    inputs: &ZkCommonCredentialRootJoinDerivationInputs<'_>,
) -> Result<ZkCommonCredentialRootPresentationJoins, ZkError> {
    validate_request(inputs.request)?;
    validate_nonzero32(inputs.root)?;
    validate_nonzero32(inputs.attestation_id)?;
    validate_subject(inputs.subject_public_keys[0])?;
    validate_subject(inputs.subject_public_keys[1])?;

    let root_join = derive_root_join(salt.as_bytes(), inputs)?;
    let attestation_join = derive_attestation_join(salt.as_bytes(), inputs)?;
    let subject_joins = [
        derive_subject_join(
            salt.as_bytes(),
            inputs.request,
            inputs.subject_public_keys[0],
        )?,
        derive_subject_join(
            salt.as_bytes(),
            inputs.request,
            inputs.subject_public_keys[1],
        )?,
    ];
    Ok(ZkCommonCredentialRootPresentationJoins {
        root_join,
        attestation_join,
        subject_joins,
    })
}

/// Generates one salt and derives the complete witness material from it.
pub fn derive_common_credential_root_presentation_material(
    rng: &mut impl SecureRandom,
    inputs: ZkCommonCredentialRootJoinDerivationInputs<'_>,
) -> Result<ZkCommonCredentialRootPresentationMaterial, ZkCommonCredentialRootJoinGenerationError> {
    let salt = ZkCommonCredentialRootPresentationSalt::generate(rng)?;
    let request = inputs.request;
    let joins = derive_common_credential_root_presentation_joins_for_material(&salt, &inputs)
        .map_err(
            |error| ZkCommonCredentialRootJoinGenerationError::InvalidInput {
                reason: error.reason(),
            },
        )?;
    Ok(ZkCommonCredentialRootPresentationMaterial {
        salt,
        request,
        joins,
    })
}

fn salt_slot_bit(
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<u8, ZkCommonCredentialRootStageSaltError> {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => Ok(SALT_SLOT_ROOT_ATTESTATION),
        ZkCommonCredentialRootProofSlot::RootStatus => Ok(SALT_SLOT_ROOT_STATUS),
        ZkCommonCredentialRootProofSlot::Lineage0 => Ok(SALT_SLOT_LINEAGE_0),
        ZkCommonCredentialRootProofSlot::Lineage1 => Ok(SALT_SLOT_LINEAGE_1),
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => Ok(SALT_SLOT_SELECTED_CLAIM_0),
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => Ok(SALT_SLOT_SELECTED_CLAIM_1),
        ZkCommonCredentialRootProofSlot::Session
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0
        | ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            Err(ZkCommonCredentialRootStageSaltError::UnsaltedSlot)
        }
    }
}
