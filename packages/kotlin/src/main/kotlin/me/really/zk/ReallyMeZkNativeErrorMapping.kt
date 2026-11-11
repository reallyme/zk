// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import reallyme.zk.v1.Manifest

internal fun providerFailureReason(reason: Manifest.ZkErrorReason): ZkProviderFailureReason =
    when (reason) {
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNKNOWN_CIRCUIT,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_CIRCUIT,
        -> ZkProviderFailureReason.UNSUPPORTED_CIRCUIT
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_PROOF_SUITE -> ZkProviderFailureReason.UNSUPPORTED_SUITE
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSUPPORTED_TRANSPORT -> ZkProviderFailureReason.UNSUPPORTED_TRANSPORT
        Manifest.ZkErrorReason.ZK_ERROR_REASON_EMPTY_INPUT -> ZkProviderFailureReason.EMPTY_BUFFER
        Manifest.ZkErrorReason.ZK_ERROR_REASON_PROOF_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_PUBLIC_INPUTS_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_MESSAGE_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_ARTIFACT_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_WITNESS_TOO_LARGE,
        -> ZkProviderFailureReason.OVERSIZED_BUFFER
        Manifest.ZkErrorReason.ZK_ERROR_REASON_LENGTH_OVERFLOW,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_RESOURCE_EXHAUSTED,
        -> ZkProviderFailureReason.ARITHMETIC_OVERFLOW
        Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF_ENCODING,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_MALFORMED_PROTOBUF,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_MALFORMED_JSON,
        -> ZkProviderFailureReason.MALFORMED_PROOF
        Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_BINDING_MISMATCH,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_ARTIFACT_MISMATCH,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNTRUSTED_ISSUER,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_PRESENTATION_EXPIRED,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_PRESENTATION_EXPIRY_TOO_FAR,
        -> ZkProviderFailureReason.PROOF_REJECTED
        Manifest.ZkErrorReason.ZK_ERROR_REASON_BACKEND_UNAVAILABLE -> ZkProviderFailureReason.CRS_MISSING
        Manifest.ZkErrorReason.ZK_ERROR_REASON_BACKEND_FAILURE -> ZkProviderFailureReason.INTERNAL_FAILURE
        Manifest.ZkErrorReason.ZK_ERROR_REASON_UNSPECIFIED,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_PUBLIC_INPUT_NAME,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_PUBLIC_KEY_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_CLAIM_PAYLOAD_TOO_LARGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_INVALID_CLAIM_PROOF_BUNDLE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_DUPLICATE_STAGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_MISSING_STAGE,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_STAGE_MISMATCH,
        Manifest.ZkErrorReason.ZK_ERROR_REASON_MISSING_OPERATION,
        Manifest.ZkErrorReason.UNRECOGNIZED,
        -> ZkProviderFailureReason.INTERNAL_FAILURE
    }
