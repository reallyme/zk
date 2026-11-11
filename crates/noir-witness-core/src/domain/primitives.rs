// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::{FIELD_ELEMENT_BYTES, SALT_BYTES, SIGNATURE_BYTES};

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct P256Coordinate([u8; FIELD_ELEMENT_BYTES]);

impl P256Coordinate {
    pub const fn new(bytes: [u8; FIELD_ELEMENT_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; FIELD_ELEMENT_BYTES] {
        &self.0
    }
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct P256PublicKey {
    pub x: P256Coordinate,
    pub y: P256Coordinate,
}

macro_rules! define_field_element_bytes_type {
    ($name:ident) => {
        #[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; FIELD_ELEMENT_BYTES]);

        impl $name {
            pub const fn new(bytes: [u8; FIELD_ELEMENT_BYTES]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; FIELD_ELEMENT_BYTES] {
                &self.0
            }
        }
    };
}

macro_rules! define_signature_type {
    ($name:ident) => {
        #[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; SIGNATURE_BYTES]);

        impl $name {
            pub const fn new(bytes: [u8; SIGNATURE_BYTES]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; SIGNATURE_BYTES] {
                &self.0
            }
        }
    };
}

define_field_element_bytes_type!(ActiveStatusRoot);
define_field_element_bytes_type!(AssurancePolicyId);
define_field_element_bytes_type!(AttestationId);
define_field_element_bytes_type!(AttestationJoinHash);
define_field_element_bytes_type!(AudienceHash);
define_field_element_bytes_type!(ChallengeNonceHash);
define_field_element_bytes_type!(ClaimBundleHash);
define_field_element_bytes_type!(ClaimNameHash);
define_field_element_bytes_type!(CredentialBindingHash);
define_field_element_bytes_type!(EnvelopeBindingHash);
define_field_element_bytes_type!(EnvelopeHash);
define_field_element_bytes_type!(JoinSalt);
define_field_element_bytes_type!(MerkleRoot);
define_field_element_bytes_type!(RelationshipDidHash);
define_field_element_bytes_type!(RelationshipNonce);
define_field_element_bytes_type!(RootCommitment);
define_field_element_bytes_type!(RootJoinHash);
define_field_element_bytes_type!(SessionBindingHash);
define_field_element_bytes_type!(SubjectJoinHash);
define_field_element_bytes_type!(TransactionDataHash);

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ClaimSalt([u8; SALT_BYTES]);

impl ClaimSalt {
    pub const fn new(bytes: [u8; SALT_BYTES]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; SALT_BYTES] {
        &self.0
    }
}

define_signature_type!(IssuerSignature);
define_signature_type!(IssuerRootBindingSignature);
define_signature_type!(IssuerSubjectBindingSignature);
define_signature_type!(SubjectSignature);
define_signature_type!(PersonaSignature);
define_signature_type!(SubjectLinkSignature);
define_signature_type!(PersonaFreshSignature);
