// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical bulk publication of the signed active-attestation set.
//!
//! The status authority publishes every active identifier together. A holder
//! downloads the same bytes as every other holder and derives its path locally.
//!
//! Decoding is staged so unauthenticated bytes cannot force Merkle hashing:
//!
//! 1. [`admit_root_active_set_publication`](crate::common_credential_root_active_set_publication::admit_root_active_set_publication) bounds the input, checks the
//!    canonical encoding and the ordering of the identifier list, and decodes
//!    the embedded snapshot. It hashes nothing and trusts nothing.
//! 2. [`ZkAdmittedRootActiveSetPublication::authenticate`](crate::common_credential_root_active_set_publication::ZkAdmittedRootActiveSetPublication::authenticate) verifies the
//!    snapshot signature, sequence floor, and freshness against a
//!    caller-pinned status authority, and only then builds the active-set
//!    tree and compares its root to the signed root.
//!
//! The authority signature covers the root, validity interval, and sequence,
//! not the identifier list. The list is therefore authenticated only by the
//! final root comparison, which is why that comparison follows the signature.

use buffa::{DecodeOptions, Message, MessageField};
#[cfg(any(feature = "native", feature = "wasm"))]
use reallyme_zk_api::common_root::{
    verify_root_status_snapshot, ZkCommonCredentialRootAttestationTrustPolicy,
    ZkRootAssuranceAttestation, ZkRootStatusTrustPolicy, ZkVerifiedRootStatusSnapshot,
};
use reallyme_zk_api::common_root::{
    ZkCommonCredentialRootActiveSet, ZkRootStatusSnapshot, ZkRootStatusVerificationReason,
    COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH,
};
use reallyme_zk_proto::generated::proto::reallyme::zk::v1 as pb;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::common_credential_root_status_snapshot::{
    decode_root_status_snapshot, encode_root_status_snapshot, MAX_ROOT_STATUS_SNAPSHOT_BYTES,
};

const FORMAT_VERSION: u32 = 1;
const ID_BYTES: usize = 32;
const MAX_IDS: usize = 1_usize << COMMON_CREDENTIAL_ROOT_V1_STATUS_DEPTH;
const WIRE_OVERHEAD_BYTES: usize = 1_024;
/// Bounded canonical wire size for the complete v1 active-set publication.
pub const MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES: usize = MAX_IDS * ID_BYTES + WIRE_OVERHEAD_BYTES;
const RECURSION_LIMIT: u32 = 8;

/// Stable reason for rejecting a bulk active-set publication.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ZkRootActiveSetPublicationReason {
    /// Protobuf bytes, field lengths, or canonical encoding are invalid.
    #[error("invalid active-set publication encoding")]
    InvalidEncoding,
    /// An authority input is malformed, duplicated, revoked, or untrusted.
    #[error("invalid active-set authority input")]
    InvalidAuthorityInput,
    /// The publication exceeds the v1 active-set capacity.
    #[error("active-set publication too large")]
    Capacity,
    /// The IDs are not the canonical ordered set committed by the snapshot.
    #[error("active-set publication root mismatch")]
    RootMismatch,
    /// The embedded snapshot failed authority, signature, sequence, or
    /// freshness verification under the caller-pinned trust policy.
    #[error("active-set publication snapshot rejected: {0}")]
    Unauthenticated(ZkRootStatusVerificationReason),
}

/// Typed publication error without the signed root or attestation IDs.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("active-set publication rejected: {reason}")]
pub struct ZkRootActiveSetPublicationError {
    reason: ZkRootActiveSetPublicationReason,
}

impl ZkRootActiveSetPublicationError {
    /// Return a stable, non-sensitive failure reason.
    #[must_use]
    pub const fn reason(self) -> ZkRootActiveSetPublicationReason {
        self.reason
    }
}

/// Canonical publication whose content is not yet authenticated.
///
/// Admission established only that the bytes are bounded and canonical and
/// that the identifier list is strictly ascending. No Merkle node has been
/// hashed, the signature has not been checked, and the identifier list has not
/// been matched to the signed root. The only way to obtain the active set is
/// [`Self::authenticate`].
pub struct ZkAdmittedRootActiveSetPublication {
    packed_ids: Zeroizing<Vec<u8>>,
    snapshot: ZkRootStatusSnapshot,
}

/// Publication authenticated under a caller-pinned status authority.
///
/// The snapshot signature, sequence floor, and freshness were verified first;
/// the identifier list was then hashed and matched to the signed root.
#[cfg(any(feature = "native", feature = "wasm"))]
pub struct ZkAuthenticatedRootActiveSetPublication {
    active_set: ZkCommonCredentialRootActiveSet,
    snapshot: ZkRootStatusSnapshot,
    verified_snapshot: ZkVerifiedRootStatusSnapshot,
}

/// Authority-owned inputs for one single-feed active-set publication.
///
/// `active_attestations` are private root-assurance records already signed
/// over root commitments. The authority never receives holder root `R`; it
/// derives each active identifier from the commitment-side transcript. Each
/// attestation must be valid at the signed status snapshot issuance time.
/// Revoked identifiers are removed before the full set is published.
#[cfg(any(feature = "native", feature = "wasm"))]
pub struct ZkRootActiveSetAuthorityPublication<'a> {
    /// Signed root-commitment attestations currently eligible for publication.
    pub active_attestations: &'a [&'a ZkRootAssuranceAttestation],
    /// Commitment-derived attestation IDs to remove from this single feed.
    pub revoked_attestation_ids: &'a [[u8; ID_BYTES]],
    /// Pinned assurance-authority signer and policy for every attestation.
    pub attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    /// Signed status snapshot whose root must match the resulting active set.
    pub snapshot: &'a ZkRootStatusSnapshot,
}

/// Authority inputs used to derive the exact active root before signing it.
///
/// The authority signs the returned set's root in a `ZkRootStatusSnapshot`,
/// then passes the same inventory and snapshot to the publication encoder.
/// The encoder repeats this derivation so a changed inventory cannot be
/// published under the earlier signature.
#[cfg(any(feature = "native", feature = "wasm"))]
pub struct ZkRootActiveSetAuthorityInput<'a> {
    /// Signed root-commitment attestations eligible at `issued_unix`.
    pub active_attestations: &'a [&'a ZkRootAssuranceAttestation],
    /// Commitment-derived identifiers removed from the resulting set.
    pub revoked_attestation_ids: &'a [[u8; ID_BYTES]],
    /// Pinned assurance-authority signer and policy for every attestation.
    pub attestation_trust: ZkCommonCredentialRootAttestationTrustPolicy,
    /// Issuance time that will be signed in the status snapshot.
    pub issued_unix: u64,
}

impl ZkAdmittedRootActiveSetPublication {
    /// Embedded snapshot exactly as published, before any trust decision.
    ///
    /// It carries everything a signature check consumes: the signed root,
    /// validity interval, and sequence (and so the signing digest), the
    /// claimed signer key, and the signature. None of it is trusted yet.
    #[must_use]
    pub const fn unauthenticated_snapshot(&self) -> ZkRootStatusSnapshot {
        self.snapshot
    }

    /// Number of identifiers carried by the unauthenticated list.
    #[must_use]
    pub fn identifier_count(&self) -> usize {
        self.packed_ids.len() / ID_BYTES
    }

    /// Authenticate the publication and only then materialise its active set.
    ///
    /// The snapshot is verified with `verify_root_status_snapshot` against the
    /// pinned authority key, durable sequence floor, and age bound in `trust`.
    /// Any failure is returned as
    /// [`ZkRootActiveSetPublicationReason::Unauthenticated`] before a single
    /// Merkle node is hashed. After that the identifier list is hashed and
    /// its root compared to the signed root; a list that the authority did
    /// not commit to fails with
    /// [`ZkRootActiveSetPublicationReason::RootMismatch`].
    ///
    /// A deployment must still persist and advance `trust.minimum_sequence`
    /// from the returned verified snapshot. An earlier genuine snapshot above
    /// that floor and inside its validity interval passes the signature step,
    /// so the sequence floor and age bound are what limit replay.
    #[cfg(any(feature = "native", feature = "wasm"))]
    pub fn authenticate(
        self,
        trust: ZkRootStatusTrustPolicy,
        now_unix: u64,
    ) -> Result<ZkAuthenticatedRootActiveSetPublication, ZkRootActiveSetPublicationError> {
        let verified_snapshot = verify_root_status_snapshot(self.snapshot, trust, now_unix)
            .map_err(|rejected| {
                error(ZkRootActiveSetPublicationReason::Unauthenticated(
                    rejected.reason(),
                ))
            })?;
        // Admission proved the packed length is a whole number of identifiers,
        // so the chunk view covers every byte without copying the list.
        let (ids, remainder) = self.packed_ids.as_chunks::<ID_BYTES>();
        if !remainder.is_empty() {
            return Err(error(ZkRootActiveSetPublicationReason::InvalidEncoding));
        }
        let active_set = ZkCommonCredentialRootActiveSet::try_from_sorted_ids(ids)
            .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
        if !bool::from(active_set.root().ct_eq(&verified_snapshot.root())) {
            return Err(error(ZkRootActiveSetPublicationReason::RootMismatch));
        }
        Ok(ZkAuthenticatedRootActiveSetPublication {
            active_set,
            snapshot: self.snapshot,
            verified_snapshot,
        })
    }
}

#[cfg(any(feature = "native", feature = "wasm"))]
impl ZkAuthenticatedRootActiveSetPublication {
    /// Canonical set whose root equals the authority-signed root.
    #[must_use]
    pub const fn active_set(&self) -> &ZkCommonCredentialRootActiveSet {
        &self.active_set
    }

    /// Published snapshot whose signature was verified during authentication.
    #[must_use]
    pub const fn snapshot(&self) -> ZkRootStatusSnapshot {
        self.snapshot
    }

    /// Verified snapshot for deriving holder paths and advancing the durable
    /// sequence floor.
    #[must_use]
    pub const fn verified_snapshot(&self) -> ZkVerifiedRootStatusSnapshot {
        self.verified_snapshot
    }
}

/// Encode one full set with its matching signed snapshot.
///
/// The publisher must sign the set root before calling this function. This
/// check prevents accidentally publishing valid but mismatched components.
pub fn encode_root_active_set_publication(
    active_set: &ZkCommonCredentialRootActiveSet,
    snapshot: &ZkRootStatusSnapshot,
) -> Result<Zeroizing<Vec<u8>>, ZkRootActiveSetPublicationError> {
    if !bool::from(active_set.root().ct_eq(&snapshot.status_root())) {
        return Err(error(ZkRootActiveSetPublicationReason::RootMismatch));
    }
    let snapshot_bytes = Zeroizing::new(
        encode_root_status_snapshot(snapshot)
            .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?,
    );
    let snapshot_wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_element_memory_limit(MAX_ROOT_STATUS_SNAPSHOT_BYTES)
        .with_max_message_size(MAX_ROOT_STATUS_SNAPSHOT_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ZkRootStatusSnapshot>(&snapshot_bytes)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
    let packed_len = active_set
        .len()
        .checked_mul(ID_BYTES)
        .ok_or_else(|| error(ZkRootActiveSetPublicationReason::Capacity))?;
    let mut packed = Zeroizing::new(Vec::new());
    packed
        .try_reserve_exact(packed_len)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    for id in active_set.sorted_ids() {
        packed.extend_from_slice(id);
    }
    let mut wire = pb::ZkRootActiveSetPublication::default();
    wire.format_version = FORMAT_VERSION;
    wire.sorted_attestation_ids = core::mem::take(&mut *packed);
    wire.snapshot = MessageField::some(snapshot_wire);
    let encoded = Zeroizing::new(wire.encode_to_vec());
    wire.sorted_attestation_ids.zeroize();
    if encoded.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES {
        return Err(error(ZkRootActiveSetPublicationReason::Capacity));
    }
    Ok(encoded)
}

/// Build a full active-set publication from signed root commitments.
///
/// This is the single-feed authority boundary: it accepts only signed
/// `ZkRootAssuranceAttestation` records, derives status IDs without holder
/// roots, removes revoked IDs, rejects duplicates, and finally requires the
/// supplied signed snapshot to commit to the exact resulting root.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn encode_root_active_set_publication_from_authority(
    input: ZkRootActiveSetAuthorityPublication<'_>,
) -> Result<Zeroizing<Vec<u8>>, ZkRootActiveSetPublicationError> {
    let active_set = build_root_active_set_from_authority(ZkRootActiveSetAuthorityInput {
        active_attestations: input.active_attestations,
        revoked_attestation_ids: input.revoked_attestation_ids,
        attestation_trust: input.attestation_trust,
        issued_unix: input.snapshot.issued_unix(),
    })?;
    encode_root_active_set_publication(&active_set, input.snapshot)
}

/// Derive the canonical active set that the status authority must sign.
///
/// This is the only authority-side derivation of the commitment-based IDs and
/// their Merkle root. It validates every signed input before revocation is
/// applied, including records whose IDs are being removed.
#[cfg(any(feature = "native", feature = "wasm"))]
pub fn build_root_active_set_from_authority(
    input: ZkRootActiveSetAuthorityInput<'_>,
) -> Result<ZkCommonCredentialRootActiveSet, ZkRootActiveSetPublicationError> {
    // Bound the authority input before allocating. Revocation cannot be used
    // to hide an oversized or otherwise malformed source inventory.
    if input.active_attestations.len() > MAX_IDS || input.revoked_attestation_ids.len() > MAX_IDS {
        return Err(error(ZkRootActiveSetPublicationReason::Capacity));
    }
    let revoked = canonical_ids(input.revoked_attestation_ids)?;
    let mut ids = Zeroizing::new(Vec::new());
    ids.try_reserve_exact(input.active_attestations.len())
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    for attestation in input.active_attestations {
        let id = attestation
            .attestation_id_for_status_publication(input.attestation_trust, input.issued_unix)
            .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidAuthorityInput))?;
        let id = *id;
        ids.push(id);
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(error(
            ZkRootActiveSetPublicationReason::InvalidAuthorityInput,
        ));
    }
    // Validate the complete signed inventory before applying revocations.
    // Otherwise duplicate records for a revoked identifier disappear from the
    // publication and mask a corrupt authority source.
    ids.retain_mut(|id| {
        if revoked.binary_search(id).is_ok() {
            id.zeroize();
            false
        } else {
            true
        }
    });
    ZkCommonCredentialRootActiveSet::try_from_sorted_ids(&ids).map_err(|set_error| match set_error
        .reason()
    {
        reallyme_zk_api::common_root::ZkCommonCredentialRootActiveSetReason::Capacity => {
            error(ZkRootActiveSetPublicationReason::Capacity)
        }
        reallyme_zk_api::common_root::ZkCommonCredentialRootActiveSetReason::InvalidSet
        | reallyme_zk_api::common_root::ZkCommonCredentialRootActiveSetReason::NotActive
        | reallyme_zk_api::common_root::ZkCommonCredentialRootActiveSetReason::SnapshotMismatch => {
            error(ZkRootActiveSetPublicationReason::InvalidAuthorityInput)
        }
        _ => error(ZkRootActiveSetPublicationReason::InvalidAuthorityInput),
    })
}

/// Admit canonical publication bytes without authenticating or hashing them.
///
/// This step is safe to run on bytes from any source. It bounds the input,
/// rejects non-canonical encodings and unknown fields, requires a whole,
/// bounded, strictly ascending list of non-reserved identifiers, and decodes
/// the embedded snapshot. Its cost is linear in the input with no hashing.
///
/// Nothing in the returned owner is trusted. Pass it to
/// [`ZkAdmittedRootActiveSetPublication::authenticate`] with a pinned status
/// authority to obtain the active set.
pub fn admit_root_active_set_publication(
    bytes: &[u8],
) -> Result<ZkAdmittedRootActiveSetPublication, ZkRootActiveSetPublicationError> {
    if bytes.is_empty() || bytes.len() > MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES {
        return Err(error(ZkRootActiveSetPublicationReason::Capacity));
    }
    let mut wire = DecodeOptions::new()
        .with_recursion_limit(RECURSION_LIMIT)
        .with_element_memory_limit(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
        .with_max_message_size(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
        .with_unknown_field_limit(0)
        .decode_from_slice::<pb::ZkRootActiveSetPublication>(bytes)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
    let canonical = canonical_publication_bytes(&wire);
    // Move the list into its zeroizing owner before the first early return.
    let packed_ids = Zeroizing::new(core::mem::take(&mut wire.sorted_attestation_ids));
    let canonical = canonical?;
    if wire.format_version != FORMAT_VERSION || canonical.as_slice() != bytes {
        return Err(error(ZkRootActiveSetPublicationReason::InvalidEncoding));
    }
    let (ids, remainder) = packed_ids.as_chunks::<ID_BYTES>();
    if !remainder.is_empty() {
        return Err(error(ZkRootActiveSetPublicationReason::InvalidEncoding));
    }
    if ids.len() > MAX_IDS {
        return Err(error(ZkRootActiveSetPublicationReason::Capacity));
    }
    // The canonical list is strictly ascending and never contains the
    // reserved zero identifier. Comparing neighbours is linear and hashes
    // nothing, so a malformed list is rejected before authentication.
    if ids.iter().any(|id| id.iter().all(|byte| *byte == 0))
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(error(ZkRootActiveSetPublicationReason::InvalidEncoding));
    }
    let snapshot_wire = wire
        .snapshot
        .take()
        .ok_or_else(|| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
    // Bound the nested message before copying it for the snapshot decoder.
    let snapshot_len = snapshot_wire
        .try_encoded_len()
        .ok()
        .and_then(|length| usize::try_from(length).ok())
        .ok_or_else(|| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
    if snapshot_len > MAX_ROOT_STATUS_SNAPSHOT_BYTES {
        return Err(error(ZkRootActiveSetPublicationReason::InvalidEncoding));
    }
    let snapshot_bytes = Zeroizing::new(snapshot_wire.encode_to_vec());
    let snapshot = decode_root_status_snapshot(&snapshot_bytes)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::InvalidEncoding))?;
    Ok(ZkAdmittedRootActiveSetPublication {
        packed_ids,
        snapshot,
    })
}

/// Re-encode a decoded publication with a bounded, fallible allocation.
fn canonical_publication_bytes(
    wire: &pb::ZkRootActiveSetPublication,
) -> Result<Zeroizing<Vec<u8>>, ZkRootActiveSetPublicationError> {
    let maximum = u32::try_from(MAX_ROOT_ACTIVE_SET_PUBLICATION_BYTES)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    let encoded_len = wire
        .try_encoded_len()
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    if encoded_len > maximum {
        return Err(error(ZkRootActiveSetPublicationReason::Capacity));
    }
    let encoded_len = usize::try_from(encoded_len)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    let mut encoded = Zeroizing::new(Vec::new());
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    wire.try_encode_bounded(maximum, &mut *encoded)
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    Ok(encoded)
}

#[cfg(any(feature = "native", feature = "wasm"))]
fn canonical_ids(
    ids: &[[u8; ID_BYTES]],
) -> Result<Zeroizing<Vec<[u8; ID_BYTES]>>, ZkRootActiveSetPublicationError> {
    let mut copied = Zeroizing::new(Vec::new());
    copied
        .try_reserve_exact(ids.len())
        .map_err(|_| error(ZkRootActiveSetPublicationReason::Capacity))?;
    copied.extend_from_slice(ids);
    copied.sort();
    if copied.iter().any(|id| id.iter().all(|byte| *byte == 0))
        || copied.windows(2).any(|pair| pair[0] == pair[1])
    {
        return Err(error(
            ZkRootActiveSetPublicationReason::InvalidAuthorityInput,
        ));
    }
    Ok(copied)
}

const fn error(reason: ZkRootActiveSetPublicationReason) -> ZkRootActiveSetPublicationError {
    ZkRootActiveSetPublicationError { reason }
}

#[cfg(test)]
#[path = "common_credential_root_active_set_publication/admission_tests.rs"]
mod admission_tests;
#[cfg(test)]
#[path = "common_credential_root_active_set_publication/tests.rs"]
mod tests;
