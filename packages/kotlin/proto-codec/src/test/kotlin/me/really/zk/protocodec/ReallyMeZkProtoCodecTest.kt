// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.protocodec

import reallyme.zk.v1.Manifest.ZkArtifactManifestOperation
import reallyme.zk.v1.Manifest.ZkError
import reallyme.zk.v1.Manifest.ZkErrorReason
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceClaimRootProveOperation
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceSelectedClaimProveOperation
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceSignedValidityProveOperation
import reallyme.zk.v1.Manifest.ZkPersonaCredentialEvidenceStageVerifyOperation
import reallyme.zk.v1.Manifest.ZkProofSuite
import reallyme.zk.v1.Manifest.ZkProviderOperationRequest
import reallyme.zk.v1.Manifest.ZkProviderOperationResponse
import reallyme.zk.v1.Manifest.ZkProviderOperationResult
import reallyme.zk.v1.Manifest.ZkStatusQualifiedClaimProofBundleVerifyOperation
import kotlin.test.Test
import kotlin.test.assertEquals

class ReallyMeZkProtoCodecTest {
    @Test
    fun personaCredentialEvidenceStageVerificationRequiresNativeProofValidation() {
        val request =
            ZkProviderOperationRequest
                .newBuilder()
                .setVerifyPersonaCredentialEvidenceStage(
                    ZkPersonaCredentialEvidenceStageVerifyOperation.getDefaultInstance(),
                ).build()

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_OPERATION),
            ReallyMeZkProtoCodec.admitProviderOperation(request),
        )
    }

    @Test
    fun statusQualifiedClaimProofBundleVerificationRequiresNativeProofValidation() {
        val request =
            ZkProviderOperationRequest
                .newBuilder()
                .setVerifyStatusQualifiedClaimProofBundle(
                    ZkStatusQualifiedClaimProofBundleVerifyOperation.getDefaultInstance(),
                ).build()

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_OPERATION),
            ReallyMeZkProtoCodec.admitProviderOperation(request),
        )
    }

    @Test
    fun personaCredentialEvidenceProofOperationsRequireNativeValidation() {
        val requests =
            listOf(
                ZkProviderOperationRequest
                    .newBuilder()
                    .setProvePersonaCredentialEvidenceIssuerEnvelope(
                        ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation.getDefaultInstance(),
                    ).build(),
                ZkProviderOperationRequest
                    .newBuilder()
                    .setProvePersonaCredentialEvidenceClaimRoot(
                        ZkPersonaCredentialEvidenceClaimRootProveOperation.getDefaultInstance(),
                    ).build(),
                ZkProviderOperationRequest
                    .newBuilder()
                    .setProvePersonaCredentialEvidenceSignedValidity(
                        ZkPersonaCredentialEvidenceSignedValidityProveOperation.getDefaultInstance(),
                    ).build(),
                ZkProviderOperationRequest
                    .newBuilder()
                    .setProvePersonaCredentialEvidenceSelectedClaim(
                        ZkPersonaCredentialEvidenceSelectedClaimProveOperation.getDefaultInstance(),
                    ).build(),
            )

        requests.forEach { request ->
            assertEquals(
                ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_OPERATION),
                ReallyMeZkProtoCodec.admitProviderOperation(request),
            )
        }
    }

    @Test
    fun missingOperationFailsClosed() {
        val result =
            ReallyMeZkProtoCodec.admitProviderOperation(
                ZkProviderOperationRequest.getDefaultInstance(),
            )

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_OPERATION),
            result,
        )
    }

    @Test
    fun unsupportedSuiteFailsClosed() {
        val request =
            ZkProviderOperationRequest
                .newBuilder()
                .setGetArtifactManifest(
                    ZkArtifactManifestOperation
                        .newBuilder()
                        .setProofSuite(ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_UNMASKED_NO_IPA)
                        .build(),
                ).build()

        val result = ReallyMeZkProtoCodec.admitProviderOperation(request)

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.UNSUPPORTED_PROOF_SUITE),
            result,
        )
    }

    @Test
    fun supportedSuiteIsConvertedToAuthoredDomainOperation() {
        val request =
            ZkProviderOperationRequest
                .newBuilder()
                .setGetArtifactManifest(
                    ZkArtifactManifestOperation
                        .newBuilder()
                        .setProofSuite(ZkProofSuite.ZK_PROOF_SUITE_BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA)
                        .build(),
                ).build()

        val operation = ReallyMeZkProtoCodec.admitProviderOperation(request)

        assertEquals(
            ZkProtoCodecResult.Success(
                ZkProviderOperation.ArtifactManifestRequest(
                    proofSuite = ZkProofSuiteId.BARRETENBERG_ULTRA_HONK_KECCAK_ZK_NO_IPA,
                ),
            ),
            operation,
        )
    }

    @Test
    fun providerErrorResponseIsNeverAdmitted() {
        val response =
            ZkProviderOperationResponse
                .newBuilder()
                .setError(ZkError.newBuilder().setReason(ZkErrorReason.ZK_ERROR_REASON_INVALID_PROOF))
                .build()

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.PROVIDER_FAILURE),
            ReallyMeZkProtoCodec.admitProviderResponse(response),
        )
    }

    @Test
    fun providerErrorWithoutReasonFailsClosed() {
        val response =
            ZkProviderOperationResponse
                .newBuilder()
                .setError(ZkError.getDefaultInstance())
                .build()

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_ERROR_REASON),
            ReallyMeZkProtoCodec.admitProviderResponse(response),
        )
    }

    @Test
    fun providerResultWithoutPayloadFailsClosed() {
        val response =
            ZkProviderOperationResponse
                .newBuilder()
                .setResult(ZkProviderOperationResult.getDefaultInstance())
                .build()

        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_RESULT),
            ReallyMeZkProtoCodec.admitProviderResponse(response),
        )
    }

    @Test
    fun providerResponseWithoutOutcomeFailsClosed() {
        assertEquals(
            ZkProtoCodecResult.Failure(ZkProtoCodecErrorReason.MISSING_OUTCOME),
            ReallyMeZkProtoCodec.admitProviderResponse(ZkProviderOperationResponse.getDefaultInstance()),
        )
    }
}
