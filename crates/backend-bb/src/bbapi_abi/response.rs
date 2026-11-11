// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_zk_api::{
    artifacts::ZkArtifactSetIdentity,
    circuits::ZkCircuitRef,
    errors::{ZkError, ZkErrorReason},
    persona_evidence::{
        ZkPersonaCredentialEvidenceMode, ZkPersonaCredentialEvidenceRawPublicInputs,
        ZkPersonaCredentialEvidenceStageProof,
    },
    proofs::{ZkProofBytes, ZkProofSuite},
};
use reallyme_zk_artifacts::VerifiedArtifactBytes;
use zeroize::Zeroizing;

use crate::{
    bbapi_abi::{
        message::{
            ensure_array_size, ensure_map_size, validate_message_length, MsgpackErrorReason,
            MAX_BBAPI_BINARY_BYTES, MAX_BBAPI_STRING_BYTES,
        },
        pack::field_is_canonical,
    },
    public_input_codec::{BarretenbergPublicInputCodec, BARRETENBERG_FIELD_BYTES},
    BbCommonCredentialRootRawProveResponse, BbStageProveResponse,
};

type ProveResponseFieldOwners = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

const BB_CIRCUIT_VERIFY_INVALID_PROOF_MESSAGE: &[u8] = b"Proof verification failed";

/// Validates the exact upstream `CircuitProve` response schema.
pub(crate) fn decode_circuit_prove_response(
    circuit_ref: ZkCircuitRef,
    verification_key: &VerifiedArtifactBytes,
    bytes: &[u8],
) -> Result<BbStageProveResponse, ZkError> {
    let (public_inputs, proof) =
        decode_circuit_prove_response_field_owners(verification_key, bytes)?;
    BarretenbergPublicInputCodec::normalize_separate_result(
        circuit_ref,
        public_inputs.as_slice(),
        proof.as_slice(),
    )
}

/// Validates the exact upstream `CircuitProve` response schema and preserves
/// raw common-credential-root public inputs without compact ABI normalization.
pub(crate) fn decode_circuit_prove_raw_common_credential_root_response(
    circuit_ref: ZkCircuitRef,
    verification_key: &VerifiedArtifactBytes,
    bytes: &[u8],
) -> Result<BbCommonCredentialRootRawProveResponse, ZkError> {
    let (public_inputs, proof) =
        decode_circuit_prove_response_field_owners(verification_key, bytes)?;
    BbCommonCredentialRootRawProveResponse::try_from_raw_zeroizing_bytes(
        circuit_ref,
        proof,
        public_inputs,
    )
}

/// Admit a linked prover result only after validating the exact prepared ABI
/// and the mode-to-stage relationship. The caller verifies the proof with
/// the authenticated key before returning this package to an SDK.
pub(crate) fn decode_circuit_prove_raw_prepared_response(
    mode: ZkPersonaCredentialEvidenceMode,
    circuit_ref: ZkCircuitRef,
    proof_suite: ZkProofSuite,
    artifact_set_identity_sha256: ZkArtifactSetIdentity,
    verification_key: &VerifiedArtifactBytes,
    bytes: &[u8],
) -> Result<ZkPersonaCredentialEvidenceStageProof, ZkError> {
    let (mut public_inputs, mut proof) =
        decode_circuit_prove_response_field_owners(verification_key, bytes)?;
    ZkPersonaCredentialEvidenceStageProof::try_from_parts(
        mode,
        proof_suite,
        artifact_set_identity_sha256,
        ZkProofBytes::try_from_bytes(core::mem::take(&mut *proof))?,
        ZkPersonaCredentialEvidenceRawPublicInputs::try_from_bytes(
            circuit_ref,
            core::mem::take(&mut *public_inputs),
        )?,
    )
}

fn decode_circuit_prove_response_field_owners(
    verification_key: &VerifiedArtifactBytes,
    bytes: &[u8],
) -> Result<ProveResponseFieldOwners, ZkError> {
    validate_message_length(bytes.len())?;
    let mut decoder = ExactResponseDecoder::new(bytes);
    decoder.expect_array_len(2)?;
    let name = decoder.read_str()?;
    if name == b"CircuitProveResponse" {
        decoder.expect_map_len(3)?;
        decoder.expect_str(b"public_inputs")?;
        let public_inputs = decoder.read_field_vector()?;
        decoder.expect_str(b"proof")?;
        let proof = decoder.read_field_vector()?;
        decoder.expect_str(b"vk")?;
        decoder.read_matching_vk(verification_key)?;
        decoder.expect_end()?;
        Ok((public_inputs, proof))
    } else if name == b"ErrorResponse" {
        decoder.expect_map_len(1)?;
        decoder.expect_str(b"message")?;
        let _message = decoder.read_str()?;
        decoder.expect_end()?;
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    } else {
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }
}

fn circuit_verify_error_reason(message: &[u8]) -> ZkErrorReason {
    if message == BB_CIRCUIT_VERIFY_INVALID_PROOF_MESSAGE {
        ZkErrorReason::InvalidProof
    } else {
        ZkErrorReason::BackendFailure
    }
}

/// Validates the exact upstream `CircuitVerify` response schema.
pub(crate) fn decode_circuit_verify_response(bytes: &[u8]) -> Result<(), ZkError> {
    validate_message_length(bytes.len())?;
    let mut decoder = ExactResponseDecoder::new(bytes);
    decoder.expect_array_len(2)?;
    let name = decoder.read_str()?;
    if name == b"CircuitVerifyResponse" {
        decoder.expect_map_len(1)?;
        decoder.expect_str(b"verified")?;
        let verified = decoder.read_bool()?;
        decoder.expect_end()?;
        if verified {
            Ok(())
        } else {
            Err(ZkError::new(ZkErrorReason::InvalidProof))
        }
    } else if name == b"ErrorResponse" {
        decoder.expect_map_len(1)?;
        decoder.expect_str(b"message")?;
        let message = decoder.read_str()?;
        decoder.expect_end()?;
        Err(ZkError::new(circuit_verify_error_reason(message)))
    } else {
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }
}

/// Validates the exact upstream `SrsInitSrs` success schema.
pub(crate) fn decode_srs_init_response(bytes: &[u8]) -> Result<(), ZkError> {
    validate_message_length(bytes.len())?;
    let mut decoder = ExactResponseDecoder::new(bytes);
    decoder.expect_array_len(2)?;
    let name = decoder.read_str()?;
    if name == b"SrsInitSrsResponse" {
        decoder.expect_map_len(1)?;
        decoder.expect_str(b"points_buf")?;
        let points = decoder.read_bin()?;
        decoder.expect_end()?;
        if points.is_empty() {
            Ok(())
        } else {
            Err(ZkError::new(ZkErrorReason::BackendFailure))
        }
    } else if name == b"ErrorResponse" {
        decoder.expect_map_len(1)?;
        decoder.expect_str(b"message")?;
        let _message = decoder.read_str()?;
        decoder.expect_end()?;
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    } else {
        Err(ZkError::new(ZkErrorReason::BackendFailure))
    }
}

struct ExactResponseDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ExactResponseDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_array_len(&mut self, expected: u32) -> Result<(), ZkError> {
        let actual = self
            .read_array_len()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        if actual != expected {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(())
    }

    fn expect_map_len(&mut self, expected: u32) -> Result<(), ZkError> {
        let actual = self
            .read_map_len()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        if actual != expected {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(())
    }

    fn expect_str(&mut self, expected: &[u8]) -> Result<(), ZkError> {
        let actual = self.read_str()?;
        if actual != expected {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        Ok(())
    }

    fn expect_end(&self) -> Result<(), ZkError> {
        if self.offset != self.bytes.len() {
            return Err(ZkError::new(MsgpackErrorReason::TrailingBytes.zk_reason()));
        }
        Ok(())
    }

    fn read_bool(&mut self) -> Result<bool, ZkError> {
        let tag = self
            .read_u8()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        match tag {
            0xc2 => Ok(false),
            0xc3 => Ok(true),
            _ => Err(ZkError::new(ZkErrorReason::BackendFailure)),
        }
    }

    fn read_str(&mut self) -> Result<&'a [u8], ZkError> {
        let tag = self
            .read_u8()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        let size = match tag {
            0xa0..=0xbf => usize::from(tag & 0x1f),
            0xd9 => {
                let size = usize::from(
                    self.read_u8()
                        .map_err(|reason| ZkError::new(reason.zk_reason()))?,
                );
                if size <= 31 {
                    return Err(ZkError::new(
                        MsgpackErrorReason::NonCanonicalEncoding.zk_reason(),
                    ));
                }
                size
            }
            0xda => {
                let size = usize::from(
                    self.read_u16()
                        .map_err(|reason| ZkError::new(reason.zk_reason()))?,
                );
                if size <= u8::MAX.into() {
                    return Err(ZkError::new(
                        MsgpackErrorReason::NonCanonicalEncoding.zk_reason(),
                    ));
                }
                size
            }
            0xdb => {
                let size = usize::try_from(
                    self.read_u32()
                        .map_err(|reason| ZkError::new(reason.zk_reason()))?,
                )
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
                if size <= u16::MAX.into() {
                    return Err(ZkError::new(
                        MsgpackErrorReason::NonCanonicalEncoding.zk_reason(),
                    ));
                }
                size
            }
            _ => return Err(ZkError::new(ZkErrorReason::BackendFailure)),
        };
        if size > MAX_BBAPI_STRING_BYTES {
            return Err(ZkError::new(ZkErrorReason::BackendFailure));
        }
        self.read_exact(size)
            .map_err(|reason| ZkError::new(reason.zk_reason()))
    }

    fn read_bin(&mut self) -> Result<&'a [u8], ZkError> {
        let tag = self
            .read_u8()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        let size = match tag {
            0xc4 => usize::from(
                self.read_u8()
                    .map_err(|reason| ZkError::new(reason.zk_reason()))?,
            ),
            0xc5 => {
                let size = usize::from(
                    self.read_u16()
                        .map_err(|reason| ZkError::new(reason.zk_reason()))?,
                );
                if size <= u8::MAX.into() {
                    return Err(ZkError::new(
                        MsgpackErrorReason::NonCanonicalEncoding.zk_reason(),
                    ));
                }
                size
            }
            0xc6 => {
                let size = usize::try_from(
                    self.read_u32()
                        .map_err(|reason| ZkError::new(reason.zk_reason()))?,
                )
                .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
                if size <= u16::MAX.into() {
                    return Err(ZkError::new(
                        MsgpackErrorReason::NonCanonicalEncoding.zk_reason(),
                    ));
                }
                size
            }
            _ => return Err(ZkError::new(ZkErrorReason::BackendFailure)),
        };
        if size > MAX_BBAPI_BINARY_BYTES {
            return Err(ZkError::new(ZkErrorReason::MessageTooLarge));
        }
        self.read_exact(size)
            .map_err(|reason| ZkError::new(reason.zk_reason()))
    }

    fn read_field_vector(&mut self) -> Result<Zeroizing<Vec<u8>>, ZkError> {
        let field_count = self
            .read_array_len()
            .map_err(|reason| ZkError::new(reason.zk_reason()))?;
        let field_count = usize::try_from(field_count)
            .map_err(|_| ZkError::new(ZkErrorReason::LengthOverflow))?;
        let byte_len = field_count
            .checked_mul(BARRETENBERG_FIELD_BYTES)
            .ok_or(ZkError::new(ZkErrorReason::LengthOverflow))?;
        let mut output = Zeroizing::new(Vec::new());
        output
            .try_reserve_exact(byte_len)
            .map_err(|_| ZkError::new(ZkErrorReason::ResourceExhausted))?;
        for _ in 0..field_count {
            let field = self.read_bin()?;
            if field.len() != BARRETENBERG_FIELD_BYTES || !field_is_canonical(field)? {
                return Err(ZkError::new(ZkErrorReason::InvalidProofEncoding));
            }
            output.extend_from_slice(field);
        }
        Ok(output)
    }

    fn read_matching_vk(
        &mut self,
        _verification_key: &VerifiedArtifactBytes,
    ) -> Result<(), ZkError> {
        self.expect_map_len(3)?;
        self.expect_str(b"bytes")?;
        let returned_vk = self.read_bin()?;
        self.expect_str(b"fields")?;
        let fields = self.read_field_vector()?;
        self.expect_str(b"hash")?;
        let hash = self.read_bin()?;
        if returned_vk.is_empty() && fields.is_empty() && hash.is_empty() {
            return Ok(());
        }
        Err(ZkError::new(ZkErrorReason::ArtifactMismatch))
    }

    fn read_array_len(&mut self) -> Result<u32, MsgpackErrorReason> {
        let tag = self.read_u8()?;
        let len = match tag {
            0x90..=0x9f => u32::from(tag & 0x0f),
            0xdc => {
                let len = u32::from(self.read_u16()?);
                if len <= 15 {
                    return Err(MsgpackErrorReason::NonCanonicalEncoding);
                }
                len
            }
            0xdd => {
                let len = self.read_u32()?;
                if len <= u32::from(u16::MAX) {
                    return Err(MsgpackErrorReason::NonCanonicalEncoding);
                }
                len
            }
            _ => return Err(MsgpackErrorReason::RootNotArray),
        };
        ensure_array_size(len)?;
        Ok(len)
    }

    fn read_map_len(&mut self) -> Result<u32, MsgpackErrorReason> {
        let tag = self.read_u8()?;
        let len = match tag {
            0x80..=0x8f => u32::from(tag & 0x0f),
            0xde => {
                let len = u32::from(self.read_u16()?);
                if len <= 15 {
                    return Err(MsgpackErrorReason::NonCanonicalEncoding);
                }
                len
            }
            0xdf => {
                let len = self.read_u32()?;
                if len <= u32::from(u16::MAX) {
                    return Err(MsgpackErrorReason::NonCanonicalEncoding);
                }
                len
            }
            _ => return Err(MsgpackErrorReason::UnsupportedType),
        };
        ensure_map_size(len)?;
        Ok(len)
    }

    fn read_u8(&mut self) -> Result<u8, MsgpackErrorReason> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, MsgpackErrorReason> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, MsgpackErrorReason> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_exact(&mut self, size: usize) -> Result<&'a [u8], MsgpackErrorReason> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(MsgpackErrorReason::LengthOverflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(MsgpackErrorReason::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }
}
