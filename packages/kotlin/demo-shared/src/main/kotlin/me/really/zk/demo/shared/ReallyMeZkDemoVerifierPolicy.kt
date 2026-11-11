// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import com.google.protobuf.ByteString
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.ZkProviderFailureReason
import me.really.zk.claimbundle.ZkPresentationBoundClaimBundleVerifyRequest
import reallyme.zk.v1.Manifest
import java.util.Base64

/**
 * Independent verifier policy for the reviewed synthetic demo fixtures.
 *
 * The sample fixtures are public test material, so the policy is intentionally
 * pinned in code instead of derived from the prover-owned witness input.
 */
public object ReallyMeZkDemoVerifierPolicy {
    public const val VERIFICATION_TIME_UNIX: Long = 1_749_999_999L

    public fun sessionBinding(): Manifest.ZkSessionBinding =
        Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(ByteString.copyFrom(VERIFIER_NONCE_HASH))
            .setAudienceHash(ByteString.copyFrom(VERIFIER_AUDIENCE_HASH))
            .setTransactionDataHash(ByteString.copyFrom(VERIFIER_TRANSACTION_DATA_HASH))
            .build()

    public fun trustedIssuer(): Manifest.ZkP256PublicKey =
        Manifest.ZkP256PublicKey
            .newBuilder()
            .setX(ByteString.copyFrom(VERIFIER_ISSUER_X))
            .setY(ByteString.copyFrom(VERIFIER_ISSUER_Y))
            .build()

    public fun bundleVerifyRequest(): ZkPresentationBoundClaimBundleVerifyRequest =
        ZkPresentationBoundClaimBundleVerifyRequest(
            expectedSessionBinding = sessionBinding(),
            trustedIssuers = listOf(trustedIssuer()),
            verificationTimeUnix = VERIFICATION_TIME_UNIX,
        )

    public fun validateReviewedFixtureSession(binding: Manifest.ZkSessionBinding) {
        if (binding != sessionBinding()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }

    public fun validateReviewedFixtureIssuer(issuer: Manifest.ZkP256PublicKey) {
        if (issuer != trustedIssuer()) {
            throw ReallyMeZkProviderException(ZkProviderFailureReason.MALFORMED_WITNESS)
        }
    }
}

private val VERIFIER_NONCE_HASH: ByteArray =
    reviewedFixtureBytes(REVIEWED_NONCE_HASH_BASE64)

private val VERIFIER_AUDIENCE_HASH: ByteArray =
    reviewedFixtureBytes(REVIEWED_AUDIENCE_HASH_BASE64)

private val VERIFIER_TRANSACTION_DATA_HASH: ByteArray =
    reviewedFixtureBytes(REVIEWED_TRANSACTION_DATA_HASH_BASE64)

private val VERIFIER_ISSUER_X: ByteArray =
    reviewedFixtureBytes(REVIEWED_ISSUER_X_BASE64)

private val VERIFIER_ISSUER_Y: ByteArray =
    reviewedFixtureBytes(REVIEWED_ISSUER_Y_BASE64)

private fun reviewedFixtureBytes(encoded: String): ByteArray {
    val decoded =
        try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            val failure = ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
            failure.addSuppressed(error)
            throw failure
        }
    if (decoded.size != REVIEWED_FIXTURE_BYTE_COUNT) {
        throw ReallyMeZkProviderException(ZkProviderFailureReason.INTERNAL_FAILURE)
    }
    return decoded
}

private const val REVIEWED_FIXTURE_BYTE_COUNT = 32
private const val REVIEWED_NONCE_HASH_BASE64 = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
private const val REVIEWED_AUDIENCE_HASH_BASE64 = "0bh5BQSVHC88dMYSmbnPuGNMobDcjjtq5XR1vDd5CiU="
private const val REVIEWED_TRANSACTION_DATA_HASH_BASE64 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
private const val REVIEWED_ISSUER_X_BASE64 = "PtETt4g7TFkGODedsMIc2hZ0LtAlUEi/QzOR03S8IdE="
private const val REVIEWED_ISSUER_Y_BASE64 = "kJkgmszEyKIkyEOvpPTGigkNBNpemIna4vju/OgqN0A="
