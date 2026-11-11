// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKDemoSupport
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKSampleRunnerTests {
  @Test
  func everyBundleKindRunsProductionBundleFlow() async throws {
    for bundleKind in ZKClaimProofBundleKind.allCases {
      let provider = RecordingProvider()
      let runner = sampleRunner(provider: provider)
      let progressRecorder = ProgressRecorder()

      let result = try await runner.runFlow(bundleKind: bundleKind) { line in
        progressRecorder.append(line)
      }
      let progressLines = progressRecorder.snapshot()

      #expect(result.bundleKind == bundleKind)
      #expect(result.fixtureBundleVerified)
      #expect(result.verificationKeySize == 0)
      #expect(result.publicInputsSize == 0)
      #expect(result.proofSize == 4 * 96)
      #expect(
        await provider.operations
          == expectedOperations(for: bundleKind, credentialHashAlgorithm: .sha256)
      )
      #expect(progressLines.filter { $0.hasPrefix("UI_PROGRESS|") }.count == 6)
      let startLine = "UI_STATUS|Starting \(bundleKind.displayName) SHA-256 proof flow."
      #expect(progressLines.contains(startLine))
      #expect(progressLines.contains("UI_PROGRESS|6|6|Bundle verified."))
    }
  }

  @Test
  func sampleFlowUsesGeneratedProtoBundleKindAndStageEnums() {
    #expect(
      ZKClaimProofBundleKind.allCases.map(\.protoBundleKind) == [
        .credentialSubjectClaimV1,
        .privatePersonaClaimV1,
      ])
    #expect(
      ZKClaimProofBundleStage.allCases.map(\.protoStage) == [
        .session,
        .credentialEnvelope,
        .credentialRoot,
        .claim,
      ])
    #expect(
      ZKCredentialHashAlgorithm.allCases.map(\.protoCredentialHashAlgorithm) == [
        .sha256,
        .poseidon2,
      ])
  }

  @Test
  func poseidon2HashSelectionIsPassedToProviderCoordinates() async throws {
    let provider = RecordingProvider()
    let runner = sampleRunner(provider: provider)

    _ = try await runner.runFlow(bundleKind: .privatePersona, credentialHashAlgorithm: .poseidon2)

    let expected = expectedOperations(for: .privatePersona, credentialHashAlgorithm: .poseidon2)
    #expect(await provider.operations == expected)
  }

  @Test
  func unsupportedProviderFailsClosed() async throws {
    let runner = sampleRunner(provider: UnsupportedReallyMeZKClaimProofBundleProvider())

    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      try await runner.runFlow(bundleKind: .privatePersona)
    }
  }

  @Test
  func unsupportedBundleVerifierFailsClosed() async throws {
    let verifier = UnsupportedReallyMeZKPresentationBoundClaimBundleVerifier()

    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      try await verifier.verifyPresentationBoundClaimBundle(
        request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: expectedSessionBinding(),
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle:
          UnsupportedReallyMeZKPresentationBoundClaimBundleVerifier
          .UnsupportedClaimProofBundleHandle()
      )
    }
  }

  @Test
  func singleFlightRejectsConcurrentRun() async throws {
    let provider = DelayedProvider()
    let runner = sampleRunner(provider: provider)

    async let first: ZKSampleResult = runner.runFlow(bundleKind: .privatePersona)
    await provider.waitUntilWitnessStarted()

    await #expect(throws: ReallyMeZKError.alreadyRunning) {
      try await runner.runFlow(bundleKind: .credentialSubjectClaim)
    }

    await provider.resume()
    _ = try await first
  }

  @Test
  func generatedWitnessesAreReleasedWhenBundleProveFails() async throws {
    let provider = ProveFailingProvider()
    let runner = sampleRunner(provider: provider)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await runner.runFlow(bundleKind: .privatePersona)
    }

    #expect(await provider.releaseCount == ZKClaimProofBundleStage.allCases.count)
  }

  @Test
  func generatedWitnessIsReleasedWhenGenerationFailsBeforeBundleDispatch() async throws {
    let provider = ReleaseFailingAfterWitnessGenerationFailureProvider()
    let runner = sampleRunner(provider: provider)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await runner.runFlow(bundleKind: .privatePersona)
    }

    #expect(await provider.releaseCount == 1)
  }

  @Test
  func nativeProviderUsesGeneratedProtoOperationLifecycle() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    var input = Reallyme_Zk_V1_ZkStageWitnessInput()
    input.credentialSubjectClaimSession = Reallyme_Zk_V1_ZkCredentialSubjectClaimSessionInput()
    let request = ReallyMeZKWitnessRequest(
      coordinate: ReallyMeZKStageCoordinate(
        credentialHashAlgorithm: .sha256,
        family: .credentialSubjectClaimV1,
        stage: .session,
        circuitRevision: 1,
        proofSuite: .barretenbergUltraHonkKeccakZkNoIpa
      ),
      input: input
    )

    let witness = try await provider.generateWitness(request: request)
    let proof = try await provider.prove(
      request: ReallyMeZKStageProveRequest(coordinate: request.coordinate),
      witness: witness.handle
    )
    let verified = try await provider.verifyDiagnosticStage(
      request: ReallyMeZKStageVerifyRequest(
        coordinate: request.coordinate,
        expectedSessionBinding: expectedSessionBinding()
      ),
      proof: proof.handle
    )
    try await provider.releaseWitness(witness.handle)

    #expect(verified)
    #expect(witness.metrics.byteCount == nil)
    #expect(proof.metrics.verificationKeyByteCount == nil)
    #expect(
      await transport.operationCases == [
        .nativeWitness,
        .nativeProve,
        .nativeVerify,
        .nativeRelease,
      ])
    #expect(await transport.verifyExpectedBindings == [expectedSessionBinding()])
  }

  @Test
  func nativeProviderSurfacesRejectedTransactionBindingFromBridge() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    var input = Reallyme_Zk_V1_ZkStageWitnessInput()
    input.credentialSubjectClaimSession = Reallyme_Zk_V1_ZkCredentialSubjectClaimSessionInput()
    let request = ReallyMeZKWitnessRequest(
      coordinate: ReallyMeZKStageCoordinate(
        credentialHashAlgorithm: .sha256,
        family: .credentialSubjectClaimV1,
        stage: .session,
        circuitRevision: 1,
        proofSuite: .barretenbergUltraHonkKeccakZkNoIpa
      ),
      input: input
    )
    let witness = try await provider.generateWitness(request: request)
    let proof = try await provider.prove(
      request: ReallyMeZKStageProveRequest(coordinate: request.coordinate),
      witness: witness.handle
    )
    let transactionBoundRequest = ReallyMeZKStageVerifyRequest(
      coordinate: request.coordinate,
      expectedSessionBinding: expectedSessionBinding(
        transactionDataHash: Data(repeating: 3, count: 32)
      )
    )

    let verified = try await provider.verifyDiagnosticStage(
      request: transactionBoundRequest,
      proof: proof.handle
    )
    #expect(verified == false)
    try await provider.releaseWitness(witness.handle)
  }

  @Test
  func nativeProviderProvesAndVerifiesBundleFromRetainedWitnesses() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)
    let verified: ReallyMeZKPresentationBoundClaimBundleVerification =
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )

    #expect(bundle.metrics.stageCount == 4)
    #expect(bundle.metrics.proofByteCount.value == 4 * 96)
    #expect(verified.bundleKind == .credentialSubjectClaim)
    #expect(verified.verifiedStageCount == 4)
    #expect(verified.issuer == trustedIssuer())
    #expect(verified.claimValueLength == 3)
    #expect(verified.sessionBinding == binding)
    verified.credentialBinding.withUnsafeBytes { bytes in
      #expect(Array(bytes) == Array(repeating: 13, count: 32))
    }
    #expect(
      await transport.operationCases == [
        .nativeWitness,
        .nativeWitness,
        .nativeWitness,
        .nativeWitness,
        .nativeBundleProve,
        .nativeBundleVerify,
      ])
  }

  @Test
  func nativeProviderReleasesWitnessesWhenBundleCountValidationFailsBeforeDispatch() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let witnesses = try await credentialSubjectClaimWitnesses(
      provider: provider, stages: [.session])

    await #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      try await provider.proveClaimProofBundle(
        request: ReallyMeZKClaimProofBundleProveRequest(
          bundleKind: .credentialSubjectClaim,
          sessionBinding: expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
        ),
        witnesses: witnesses
      )
    }

    #expect(
      await transport.operationCases == [
        .nativeWitness,
        .nativeRelease,
      ])
  }

  @Test
  func nativeProviderReleasesWitnessesWhenBundleBindingValidationFailsBeforeDispatch()
    async throws
  {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let witnesses = try await credentialSubjectClaimWitnesses(provider: provider)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await provider.proveClaimProofBundle(
        request: ReallyMeZKClaimProofBundleProveRequest(
          bundleKind: .credentialSubjectClaim,
          sessionBinding: expectedSessionBinding(transactionDataHash: Data(repeating: 7, count: 32))
        ),
        witnesses: witnesses
      )
    }

    #expect(
      await transport.operationCases == [
        .nativeWitness,
        .nativeWitness,
        .nativeWitness,
        .nativeWitness,
        .nativeRelease,
        .nativeRelease,
        .nativeRelease,
        .nativeRelease,
      ])
  }

  @Test
  func nativeProviderRejectsMalformedBundleCredentialBinding() async throws {
    let transport = RecordingNativeTransport(
      bundleCredentialBinding: Data(repeating: 13, count: 31)
    )
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )
    }
  }

  @Test
  func nativeProviderRejectsMissingBundleCredentialBinding() async throws {
    let transport = RecordingNativeTransport(bundleCredentialBinding: Data())
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )
    }
  }

  @Test
  func nativeProviderRejectsBundleVerifyWhenIssuerIsNotTrusted() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [wrongIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )
    }
  }

  @Test
  func bundleVerifyRequestRejectsZeroVerifierTime() throws {
    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
        expectedSessionBinding: expectedSessionBinding(),
        trustedIssuers: [trustedIssuer()],
        verificationTimeUnix: 0
      )
    }
  }

  @Test
  func nativeProviderRejectsExpiredBundlePresentation() async throws {
    let transport = RecordingNativeTransport(bundlePresentationExpiryUnix: 100)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )
    }
  }

  @Test
  func nativeProviderRejectsBundlePresentationBeyondWindow() async throws {
    let transport = RecordingNativeTransport(bundlePresentationExpiryUnix: 401)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let bundle = try await credentialSubjectClaimProofBundle(provider: provider, binding: binding)

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [trustedIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: bundle.handle
      )
    }
  }

  @Test
  func verifiedClaimProofBundleAndSensitiveBytesDescriptionsAreRedacted() throws {
    var witnessInput = Reallyme_Zk_V1_ZkStageWitnessInput()
    witnessInput.credentialSubjectClaimSession =
      Reallyme_Zk_V1_ZkCredentialSubjectClaimSessionInput()
    let stageRequest = ZKStageRequest(
      bundleKind: .credentialSubjectClaim,
      stage: .session,
      witnessInput: witnessInput
    )
    let providerWitnessRequest = stageRequest.providerWitnessRequest()
    let providerProveRequest = stageRequest.providerProveRequest()
    let binding = expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
    let providerVerifyRequest = stageRequest.providerVerifyRequest(
      expectedSessionBinding: binding
    )
    let bundleProveRequest = ReallyMeZKClaimProofBundleProveRequest(
      bundleKind: .credentialSubjectClaim,
      sessionBinding: binding
    )
    let bundleVerifyRequest = try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
      expectedSessionBinding: binding,
      trustedIssuers: [trustedIssuer()],
      verificationTimeUnix: 100
    )
    let sensitiveBytes = try ReallyMeZKSensitiveBytes(Data(repeating: 26, count: 4))
    for display in [
      String(describing: stageRequest),
      String(reflecting: stageRequest),
      String(describing: providerWitnessRequest),
      String(reflecting: providerWitnessRequest),
      String(describing: providerVerifyRequest),
      String(reflecting: providerVerifyRequest),
      String(describing: bundleProveRequest),
      String(reflecting: bundleProveRequest),
      String(describing: bundleVerifyRequest),
      String(reflecting: bundleVerifyRequest),
    ] {
      #expect(display.contains("<redacted>"))
      #expect(!display.contains("credentialSubjectClaimSession"))
      #expect(!display.contains("nonceHash"))
      #expect(!display.contains("trustedIssuers: ["))
    }
    for display in [
      String(describing: providerProveRequest),
      String(reflecting: providerProveRequest),
    ] {
      #expect(display.contains("ReallyMeZKStageProveRequest"))
      #expect(!display.contains("credentialSubjectClaimSession"))
      #expect(!display.contains("nonceHash"))
    }
    let sensitiveDescription = String(describing: sensitiveBytes)
    let sensitiveDebugDescription = String(reflecting: sensitiveBytes)
    #expect(sensitiveDescription.contains("<redacted>"))
    #expect(sensitiveDebugDescription.contains("<redacted>"))
    #expect(!sensitiveDescription.contains("26"))
    #expect(!sensitiveDebugDescription.contains("26"))

    let verified = try ReallyMeZKPresentationBoundClaimBundleVerification(
      bundleKind: .credentialSubjectClaim,
      verifiedStageCount: 4,
      sessionBinding: binding,
      issuer: trustedIssuer(),
      persona: wrongIssuer(),
      claimNameHash: ReallyMeZKSensitiveBytes(Data(repeating: 25, count: 32)),
      claimValue: ReallyMeZKSensitiveBytes(Data([26, 27, 28])),
      claimValueLength: 3,
      credentialBinding: ReallyMeZKSensitiveBytes(Data(repeating: 29, count: 32)),
      sessionLinkCommitment: ReallyMeZKSensitiveBytes(Data(repeating: 27, count: 32)),
      presentationExpiryUnix: 100
    )
    let verifiedDescription = String(describing: verified)
    let verifiedDebugDescription = String(reflecting: verified)

    #expect(verifiedDescription.contains("ReallyMeZKPresentationBoundClaimBundleVerification"))
    #expect(verifiedDebugDescription.contains("ReallyMeZKPresentationBoundClaimBundleVerification"))
    #expect(verifiedDescription.contains("claimValue: <redacted>"))
    #expect(verifiedDescription.contains("credentialBinding: <redacted>"))
    #expect(verifiedDebugDescription.contains("sessionLinkCommitment: <redacted>"))
    #expect(!verifiedDescription.contains("25"))
    #expect(!verifiedDescription.contains("26"))
    #expect(!verifiedDescription.contains("27"))
    #expect(!verifiedDebugDescription.contains("25"))
    #expect(!verifiedDebugDescription.contains("26"))
    #expect(!verifiedDebugDescription.contains("27"))
  }

  private func expectedOperations(
    for bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm
  ) -> [Operation] {
    var operations = ZKClaimProofBundleStage.allCases.map { stage in
      Operation(
        bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm, stage: stage,
        kind: .witness)
    }
    operations.append(
      Operation(
        bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm, stage: nil,
        kind: .bundleProve)
    )
    operations.append(
      Operation(
        bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm, stage: nil,
        kind: .bundleVerify)
    )
    return operations
  }
}
