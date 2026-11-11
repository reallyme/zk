// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk

import com.google.protobuf.ByteString
import reallyme.zk.v1.Manifest
import java.security.MessageDigest
import kotlin.test.assertEquals

/** Records common-credential-root verification dispatches without exposing proof material. */
internal class CommonCredentialRootRecordingBridge(
    private val verifiedProofCount: Int,
) : ReallyMeZkPlatformNativeBridge {
    var verifyCalls: Int = 0
        private set

    override fun contextCreate(request: ZkNativeContextCreateRequest): ZkNativeContextResult =
        ZkNativeContextResult(statusCode = 0, errorReasonCode = 0, contextHandle = 7L)

    override fun dispatch(
        contextHandle: Long,
        request: ByteArray,
    ): ZkNativeDispatchResult {
        assertEquals(7L, contextHandle)
        val operation = Manifest.ZkProviderOperationRequest.parseFrom(request)
        assertEquals(
            Manifest.ZkProviderOperationRequest.OperationCase.VERIFY_COMMON_CREDENTIAL_ROOT,
            operation.operationCase,
        )
        verifyCalls += 1
        val verification =
            Manifest.ZkCommonCredentialRootVerification
                .newBuilder()
                .setPersonaMode(operation.verifyCommonCredentialRoot.presentation.personaMode)
                .setVerifiedProofCount(verifiedProofCount)
                .setProofSuite(PROOF_SUITE)
                .build()
        val response =
            Manifest.ZkProviderOperationResponse
                .newBuilder()
                .setRequestSha256(ByteString.copyFrom(MessageDigest.getInstance("SHA-256").digest(request)))
                .setResult(
                    Manifest.ZkProviderOperationResult
                        .newBuilder()
                        .setCommonCredentialRootVerification(verification)
                        .build(),
                ).build()
        return ZkNativeDispatchResult(statusCode = 0, errorReasonCode = 0, output = response.toByteArray())
    }

    override fun contextDestroy(contextHandle: Long) = ZkNativeStatus(statusCode = 0, errorReasonCode = 0)
}
