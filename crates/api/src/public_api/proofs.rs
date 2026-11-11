// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Backend-independent proofs, secret witnesses, public inputs, and session bindings.

pub use crate::metadata::{NamedPublicInput, ZkProofMetadata};
pub use crate::proof::{
    ZkProof, ZkProofBytes, ZkProveRequest, ZkVerifyRequest, ZkWitness, ZkWitnessEncoding,
    MAX_PROOF_BYTES, MAX_WITNESS_BYTES,
};
pub use crate::public_inputs::{
    ZkDecodedPublicInputs, ZkPublicInputDescriptor, ZkPublicInputField, ZkPublicInputName,
    ZkPublicInputType, ZkPublicInputs, ZkSessionBinding, ZkSessionBindingPublicInputAbi,
    ABSENT_TRANSACTION_DATA_HASH, MAX_PUBLIC_INPUT_BYTES,
};
pub use crate::suite::{ZkProofSuite, ZkTranscriptHash};
pub use crate::traits::ZkProver;
