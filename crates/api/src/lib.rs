// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proof-system-agnostic ZK API for ReallyMe identity, protocol, wallet, and policy crates.
//! Concrete proving backends remain outside this crate.
//!
//! Public contracts are grouped by domain. Type names remain descriptive when
//! imported into applications, and verification state is explicit in each type.
//! Start with [`circuits`], [`proofs`], and [`claim_bundle`]; use [`common_root`]
//! or [`persona_evidence`] for the corresponding presentation protocol.
mod artifact_digest;
mod bundle;
mod bundle_statement;
/// Circuit capabilities and the security properties callers may rely on.
pub mod capabilities;
mod circuit;
mod circuit_registry;
mod claim_proof_bundle_verification;
mod common_credential_root;
mod common_credential_root_active_set;
mod common_credential_root_active_status;
mod common_credential_root_attestation;
mod common_credential_root_claim_commitment;
mod common_credential_root_credential_binding;
#[cfg(any(feature = "native", feature = "wasm"))]
mod common_credential_root_holder_assurance;
mod common_credential_root_issuer_status;
mod common_credential_root_joins;
mod common_credential_root_lineage;
mod common_credential_root_persona;
mod common_credential_root_status_snapshot;
mod common_credential_root_verification;
mod credential_status_verification;
mod error;
mod error_reason;
/// Authenticated issuer-status sources and credential-status proof contracts.
pub mod issuer_status;
mod metadata;
mod persona_credential_evidence;
mod persona_credential_evidence_claim_selector;
mod persona_credential_evidence_credential_binding;
mod persona_credential_evidence_exports;
mod persona_credential_evidence_joins;
mod persona_credential_evidence_public_inputs;
mod persona_credential_evidence_replay;
mod persona_credential_evidence_token_authorization;
mod persona_credential_evidence_verification;
mod proof;
mod public_inputs;
mod public_key;
mod suite;
mod traits;

/// Integrity identities for manifests and exact proving-artifact sets.
#[path = "public_api/artifacts.rs"]
pub mod artifacts;
/// Canonical circuit identity, source stages, revisions, and credential hash algorithms.
#[path = "public_api/circuits.rs"]
pub mod circuits;
/// Four-stage claim proof composition, request-bound status, and verification results.
#[path = "public_api/claim_bundle.rs"]
pub mod claim_bundle;
/// Common-credential-root proof composition, joins, commitments, and assurance.
#[path = "public_api/common_root.rs"]
pub mod common_root;
/// Typed, non-sensitive failures shared by ZK operations and transport adapters.
#[path = "public_api/errors.rs"]
pub mod errors;
/// Public-key representations with distinct issuer, persona, and authority roles.
#[path = "public_api/keys.rs"]
pub mod keys;
/// Persona credential evidence, current status, live-auth prerequisites, and replay contracts.
#[path = "public_api/persona_evidence.rs"]
pub mod persona_evidence;
/// Backend-independent proofs, secret witnesses, public inputs, and session bindings.
#[path = "public_api/proofs.rs"]
pub mod proofs;
