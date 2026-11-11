// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Strict conversion from generated ReallyMe ZK protobuf messages into audited
//! domain types.

/// Strict artifact-manifest conversion.
pub mod artifact;

mod artifact_identity;
mod binding;
mod claim_tree;

/// Canonical release-wide circuit capability registry.
pub mod capability_registry;

mod domain;
/// Shared, validated issuer status-purpose conversions.
pub mod issuer_status;

/// Canonical request/response exchange validation for provider adapters.
pub mod exchange;

/// Strict common-credential-root raw-public-input conversion.
pub mod common_credential_root;

/// Canonical wallet-private active-set feed/path assignment.
pub mod common_credential_root_active_set_path_assignment;
/// Canonical bulk active-set publication for privacy-preserving local paths.
pub mod common_credential_root_active_set_publication;
/// Canonical private ReallyMe root-assurance attestation record.
pub mod common_credential_root_attestation;
/// Bounded Buffa encoding for wallet-encrypted common-credential-root claim openings.
pub mod common_credential_root_private_claims;
/// Canonical authority-signed common-credential-root active-status snapshot codec.
pub mod common_credential_root_status_snapshot;
pub mod wallet_stored_credential;

/// Strict structured-error conversion.
pub mod error;

/// Canonical provider-operation decoding and strict domain conversion.
pub mod operation;

/// Native C ABI helpers for canonical platform exchanges.
pub mod platform_abi;

/// Strict exact-proof and bundle conversion.
pub mod proof;

/// Canonical, validated prepared-presentation request and holder-authentication transcripts.
pub mod persona_credential_evidence_auth;
pub mod persona_credential_evidence_claim_root_builder;
/// Validated, private current-status proving input from an authenticated feed.
pub mod persona_credential_evidence_current_state_builder;
/// Typed issuer-envelope preparation from one authenticated Wallet credential.
pub mod persona_credential_evidence_issuer_envelope_builder;
/// Canonical prepared presentation acceptance over proofs and live holder auth.
pub mod persona_credential_evidence_presentation;
/// Canonical Wallet storage and admission of four joined prepared credential proofs.
pub mod persona_credential_evidence_proof_set;
pub mod persona_credential_evidence_selected_claim_builder;
pub mod persona_credential_evidence_signed_validity_builder;
/// Strict admission of prepared proof packages before backend verification.
pub mod persona_credential_evidence_stage_proof;
pub mod persona_credential_evidence_token;

/// Bounded Buffa ProtoJSON encoding and decoding for approved ZK messages.
pub mod protojson;

/// Canonical release-index ownership and matrix validation.
pub mod release;

/// Strict canonical provider-result conversion.
pub mod result;

/// Canonical transport for status-qualified direct/private claim bundles.
pub mod status_qualified;

/// Optional adapter from typed ZK errors to the shared SSI stack envelope.
#[cfg(feature = "stack-error")]
pub mod stack_error;

pub mod vector;

/// Strict post-manifest verification-vector conversion.
pub mod verification_vector;
