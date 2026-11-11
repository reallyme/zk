// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.shared

import com.google.protobuf.InvalidProtocolBufferException
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.claimbundle.ZkClaimProofBundleStage
import me.really.zk.fixturePrefix
import reallyme.zk.v1.Manifest

/**
 * Loads reviewed synthetic sample fixtures as canonical protobuf witness
 * inputs for demo apps. Production integrations should construct
 * ZkStageWitnessInput directly at their trusted boundary.
 */
public object ReallyMeZkDemoFixtureWitnessInputs {
    public fun fixtureResourceName(
        bundleKind: ZkClaimProofBundleKind,
        credentialHashAlgorithm: ZkCredentialHashAlgorithm =
            ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256,
        stage: ZkClaimProofBundleStage,
    ): String =
        "${credentialHashAlgorithm.fixturePrefix}_${demoFixtureProfileName(
            bundleKind,
        )}_${demoFixtureStageName(stage)}_inputs"

    public fun witnessInput(
        bundleKind: ZkClaimProofBundleKind,
        stage: ZkClaimProofBundleStage,
        protobufData: ByteArray,
    ): Manifest.ZkStageWitnessInput {
        if (protobufData.isEmpty() || protobufData.size > MAX_FIXTURE_PROTOBUF_BYTES) {
            malformedDemoFixtureWitness()
        }
        val input =
            try {
                Manifest.ZkStageWitnessInput.parseFrom(protobufData)
            } catch (ignored: InvalidProtocolBufferException) {
                malformedDemoFixtureWitness()
            }
        validateDemoFixtureInput(input, bundleKind, stage)
        return input
    }

    public fun sessionBinding(input: Manifest.ZkStageWitnessInput): Manifest.ZkSessionBinding {
        val sessionContext = demoFixtureSessionContext(input)
        validateDemoFixtureBytes32(sessionContext.challenge)
        validateDemoFixtureBytes32(sessionContext.audienceHash)
        validateDemoFixtureBytes32(sessionContext.transactionDataHash)
        return Manifest.ZkSessionBinding
            .newBuilder()
            .setNonceHash(sessionContext.challenge.value)
            .setAudienceHash(sessionContext.audienceHash.value)
            .setTransactionDataHash(sessionContext.transactionDataHash.value)
            .build()
    }

    public fun issuer(input: Manifest.ZkStageWitnessInput): Manifest.ZkP256PublicKey {
        val issuerContext = demoFixtureIssuerContext(input)
        validateDemoFixtureBytes32(issuerContext.issuerPublicKey.x)
        validateDemoFixtureBytes32(issuerContext.issuerPublicKey.y)
        return Manifest.ZkP256PublicKey
            .newBuilder()
            .setX(issuerContext.issuerPublicKey.x.value)
            .setY(issuerContext.issuerPublicKey.y.value)
            .build()
    }
}

private const val MAX_FIXTURE_PROTOBUF_BYTES = 16 * 1_024
