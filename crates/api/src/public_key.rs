// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Public P-256 coordinates and explicit domain roles.
//! These values may be copied because the corresponding keys are intentionally public.

/// Neutral P-256 coordinates, without an issuer or authority assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkP256PublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; 32],
    /// Big-endian affine y coordinate.
    pub y: [u8; 32],
}

/// Public key in the credential issuer role.
///
/// Construction identifies a protocol role; it does not validate curve
/// coordinates or establish issuer trust. Verification and trust policy remain
/// explicit checks at their respective boundaries.
///
/// Persona authorization does not establish issuer trust, so the roles cannot
/// be substituted without an explicit conversion through neutral coordinates.
/// ```compile_fail
/// use reallyme_zk_api::{keys::{ZkIssuerPublicKey, ZkPersonaPublicKey}};
/// fn issuer_policy(_: ZkIssuerPublicKey) {}
/// let persona = ZkPersonaPublicKey { x: [1; 32], y: [2; 32] };
/// issuer_policy(persona);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkIssuerPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; 32],
    /// Big-endian affine y coordinate.
    pub y: [u8; 32],
}

impl From<ZkIssuerPublicKey> for ZkP256PublicKey {
    fn from(key: ZkIssuerPublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

impl From<ZkP256PublicKey> for ZkIssuerPublicKey {
    fn from(key: ZkP256PublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

/// Disclosed persona key authorized to present a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkPersonaPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; 32],
    /// Big-endian affine y coordinate.
    pub y: [u8; 32],
}

impl From<ZkPersonaPublicKey> for ZkP256PublicKey {
    fn from(key: ZkPersonaPublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

impl From<ZkP256PublicKey> for ZkPersonaPublicKey {
    fn from(key: ZkP256PublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

/// Root-assurance attestation signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkAttestationPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; 32],
    /// Big-endian affine y coordinate.
    pub y: [u8; 32],
}

impl From<ZkAttestationPublicKey> for ZkP256PublicKey {
    fn from(key: ZkAttestationPublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

impl From<ZkP256PublicKey> for ZkAttestationPublicKey {
    fn from(key: ZkP256PublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

/// Active-root status publication signing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZkStatusAuthorityPublicKey {
    /// Big-endian affine x coordinate.
    pub x: [u8; 32],
    /// Big-endian affine y coordinate.
    pub y: [u8; 32],
}

impl From<ZkStatusAuthorityPublicKey> for ZkP256PublicKey {
    fn from(key: ZkStatusAuthorityPublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}

impl From<ZkP256PublicKey> for ZkStatusAuthorityPublicKey {
    fn from(key: ZkP256PublicKey) -> Self {
        Self { x: key.x, y: key.y }
    }
}
