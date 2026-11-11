// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKDemoSupport
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing
import os

@testable import ReallyMeZKKit

func sampleRunner<Provider: ReallyMeZKClaimProofBundleProvider>(
  provider: Provider
) -> ReallyMeZKSampleRunner<Provider> {
  ReallyMeZKRuntime.makeSampleRunner(
    provider: provider,
    bundleVerifyRequestProvider: { _, _ throws(ReallyMeZKError) in
      try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
        expectedSessionBinding: expectedSessionBinding(),
        trustedIssuers: [trustedIssuer()],
        verificationTimeUnix: 100
      )
    }
  )
}

func expectedSessionBinding(
  transactionDataHash: Data = Data()
) -> Reallyme_Zk_V1_ZkSessionBinding {
  var binding = Reallyme_Zk_V1_ZkSessionBinding()
  binding.nonceHash = Data(repeating: 1, count: 32)
  binding.audienceHash = Data(repeating: 2, count: 32)
  binding.transactionDataHash = transactionDataHash
  return binding
}

func stageInput(for stage: ZKClaimProofBundleStage) -> Reallyme_Zk_V1_ZkStageWitnessInput {
  _ = stage
  var input = Reallyme_Zk_V1_ZkStageWitnessInput()
  input.credentialSubjectClaimSession = Reallyme_Zk_V1_ZkCredentialSubjectClaimSessionInput()
  return input
}

func circuitStage(for stage: ZKClaimProofBundleStage) -> Reallyme_Zk_V1_ZkCircuitStage {
  switch stage {
  case .session:
    return .session
  case .credentialEnvelope:
    return .credentialEnvelope
  case .credentialRoot:
    return .credentialRoot
  case .claim:
    return .claim
  default:
    return .unspecified
  }
}

func productionStage(
  for stage: Reallyme_Zk_V1_ZkCircuitStage
) -> Reallyme_Zk_V1_ZkClaimProofBundleStage {
  switch stage {
  case .session:
    return .session
  case .credentialEnvelope:
    return .credentialEnvelope
  case .credentialRoot:
    return .credentialRoot
  case .claim:
    return .claim
  default:
    return .unspecified
  }
}

func trustedIssuer() -> Reallyme_Zk_V1_ZkP256PublicKey {
  var issuer = Reallyme_Zk_V1_ZkP256PublicKey()
  issuer.x = Data(repeating: 8, count: 32)
  issuer.y = Data(repeating: 9, count: 32)
  return issuer
}

func wrongIssuer() -> Reallyme_Zk_V1_ZkP256PublicKey {
  var issuer = trustedIssuer()
  issuer.x = Data(repeating: 10, count: 32)
  return issuer
}

func credentialSubjectClaimProofBundle<Transport: ReallyMeZKNativeTransport>(
  provider: ReallyMeZKNativeProvider<Transport>,
  binding: Reallyme_Zk_V1_ZkSessionBinding
) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<
  ReallyMeZKNativeClaimProofBundleHandle
> {
  let witnesses = try await credentialSubjectClaimWitnesses(provider: provider)
  return try await provider.proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest(
      bundleKind: .credentialSubjectClaim,
      sessionBinding: binding
    ),
    witnesses: witnesses
  )
}

func credentialSubjectClaimWitnesses<Transport: ReallyMeZKNativeTransport>(
  provider: ReallyMeZKNativeProvider<Transport>,
  stages: [ZKClaimProofBundleStage] = ZKClaimProofBundleStage.allCases
) async throws(ReallyMeZKError) -> [ReallyMeZKNativeWitnessHandle] {
  var witnesses: [ReallyMeZKNativeWitnessHandle] = []
  for stage in stages {
    let witness = try await provider.generateWitness(
      request: ReallyMeZKWitnessRequest(
        coordinate: ReallyMeZKStageCoordinate(
          credentialHashAlgorithm: .sha256,
          family: .credentialSubjectClaimV1,
          stage: circuitStage(for: stage),
          circuitRevision: 1,
          proofSuite: .barretenbergUltraHonkKeccakZkNoIpa
        ),
        input: stageInput(for: stage)
      )
    )
    witnesses.append(witness.handle)
  }
  return witnesses
}

struct ProgressRecorder: Sendable {
  private let lines = OSAllocatedUnfairLock(initialState: [String]())

  func append(_ line: String) {
    lines.withLock { storedLines in
      storedLines.append(line)
    }
  }

  func snapshot() -> [String] {
    lines.withLock { storedLines in
      storedLines
    }
  }
}

enum OperationKind: Equatable, Sendable {
  case witness
  case prove
  case verify
  case bundleProve
  case bundleVerify
}

struct Operation: Equatable, Sendable {
  let bundleKind: ZKClaimProofBundleKind
  let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  let stage: ZKClaimProofBundleStage?
  let kind: OperationKind
}

actor RecordingProvider: ReallyMeZKClaimProofBundleProvider {
  struct WitnessHandle: Sendable {
    let stage: ZKClaimProofBundleStage
  }

  struct ProofHandle: Sendable {
    let stage: ZKClaimProofBundleStage
  }

  struct ClaimProofBundleHandle: Sendable {
    let bundleKind: ZKClaimProofBundleKind
    let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  }

  private(set) var operations: [Operation] = []

  func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle> {
    let coordinate = try uiCoordinate(from: request.coordinate)
    operations.append(
      Operation(
        bundleKind: coordinate.bundleKind,
        credentialHashAlgorithm: coordinate.credentialHashAlgorithm,
        stage: coordinate.stage,
        kind: .witness
      )
    )
    return try ZKProviderWitnessResult(
      handle: WitnessHandle(stage: coordinate.stage),
      metrics: ZKWitnessMetrics(byteCount: ZKWitnessByteCount(64))
    )
  }

  func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle> {
    _ = witness
    let coordinate = try uiCoordinate(from: request.coordinate)
    operations.append(
      Operation(
        bundleKind: coordinate.bundleKind,
        credentialHashAlgorithm: coordinate.credentialHashAlgorithm,
        stage: coordinate.stage,
        kind: .prove
      )
    )
    return try ZKProviderProofResult(
      handle: ProofHandle(stage: coordinate.stage),
      metrics: ZKProofMetrics(
        verificationKeyByteCount: ZKVerificationKeyByteCount(32),
        publicInputByteCount: ZKPublicInputByteCount(16),
        proofByteCount: ZKProofByteCount(96)
      )
    )
  }

  func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = proof
    #expect(request.expectedSessionBinding == expectedSessionBinding())
    let coordinate = try uiCoordinate(from: request.coordinate)
    operations.append(
      Operation(
        bundleKind: coordinate.bundleKind,
        credentialHashAlgorithm: coordinate.credentialHashAlgorithm,
        stage: coordinate.stage,
        kind: .verify
      )
    )
    return true
  }

  func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
  }

  func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle> {
    #expect(witnesses.map(\.stage) == ZKClaimProofBundleStage.allCases)
    operations.append(
      Operation(
        bundleKind: request.bundleKind,
        credentialHashAlgorithm: request.credentialHashAlgorithm,
        stage: nil,
        kind: .bundleProve
      )
    )
    return try ZKProviderClaimProofBundleResult(
      handle: ClaimProofBundleHandle(
        bundleKind: request.bundleKind, credentialHashAlgorithm: request.credentialHashAlgorithm),
      metrics: ZKClaimProofBundleMetrics(
        stageCount: ZKClaimProofBundleStage.allCases.count,
        proofByteCount: ZKClaimProofBundleByteCount(4 * 96)
      )
    )
  }

  func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    #expect(request.expectedSessionBinding == expectedSessionBinding())
    #expect(request.trustedIssuers == [trustedIssuer()])
    operations.append(
      Operation(
        bundleKind: claimProofBundle.bundleKind,
        credentialHashAlgorithm: claimProofBundle.credentialHashAlgorithm,
        stage: nil,
        kind: .bundleVerify
      )
    )
    return try verifiedClaimProofBundle(
      bundleKind: claimProofBundle.bundleKind, binding: request.expectedSessionBinding)
  }
}

actor DelayedProvider: ReallyMeZKClaimProofBundleProvider {
  struct WitnessHandle: Sendable {}
  struct ProofHandle: Sendable {}
  struct ClaimProofBundleHandle: Sendable {}

  private var witnessStarted = false
  private var resumed = false

  func waitUntilWitnessStarted() async {
    while !witnessStarted {
      await Task.yield()
    }
  }

  func resume() {
    resumed = true
  }

  func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle> {
    _ = request
    witnessStarted = true
    while !resumed {
      await Task.yield()
    }
    return try ZKProviderWitnessResult(
      handle: WitnessHandle(),
      metrics: ZKWitnessMetrics(byteCount: ZKWitnessByteCount(64))
    )
  }

  func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle> {
    _ = request
    _ = witness
    return try ZKProviderProofResult(
      handle: ProofHandle(),
      metrics: ZKProofMetrics(
        verificationKeyByteCount: ZKVerificationKeyByteCount(32),
        publicInputByteCount: ZKPublicInputByteCount(16),
        proofByteCount: ZKProofByteCount(96)
      )
    )
  }

  func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = request
    _ = proof
    return true
  }

  func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
  }

  func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle> {
    _ = request
    _ = witnesses
    return try ZKProviderClaimProofBundleResult(
      handle: ClaimProofBundleHandle(),
      metrics: ZKClaimProofBundleMetrics(
        stageCount: ZKClaimProofBundleStage.allCases.count,
        proofByteCount: ZKClaimProofBundleByteCount(4 * 96)
      )
    )
  }

  func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    _ = claimProofBundle
    return try verifiedClaimProofBundle(
      bundleKind: .privatePersona, binding: request.expectedSessionBinding)
  }
}

actor ProveFailingProvider: ReallyMeZKClaimProofBundleProvider {
  struct WitnessHandle: Sendable {}
  struct ProofHandle: Sendable {}
  struct ClaimProofBundleHandle: Sendable {}

  private(set) var releaseCount = 0

  func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle> {
    _ = request
    return try ZKProviderWitnessResult(
      handle: WitnessHandle(),
      metrics: ZKWitnessMetrics(byteCount: ZKWitnessByteCount(64))
    )
  }

  func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle> {
    _ = request
    _ = witness
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }

  func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = request
    _ = proof
    return false
  }

  func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
    releaseCount += 1
  }

  func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle> {
    _ = request
    _ = witnesses
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }

  func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    _ = request
    _ = claimProofBundle
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }
}

actor ReleaseFailingAfterWitnessGenerationFailureProvider: ReallyMeZKClaimProofBundleProvider {
  struct WitnessHandle: Sendable {}
  struct ProofHandle: Sendable {}
  struct ClaimProofBundleHandle: Sendable {}

  private var generated = false
  private(set) var releaseCount = 0

  func generateWitness(
    request: ReallyMeZKWitnessRequest
  ) async throws(ReallyMeZKError) -> ZKProviderWitnessResult<WitnessHandle> {
    _ = request
    if generated == false {
      generated = true
      return try ZKProviderWitnessResult(
        handle: WitnessHandle(),
        metrics: ZKWitnessMetrics(byteCount: ZKWitnessByteCount(64))
      )
    }
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }

  func proveClaimProofBundle(
    request: ReallyMeZKClaimProofBundleProveRequest,
    witnesses: [WitnessHandle]
  ) async throws(ReallyMeZKError) -> ZKProviderClaimProofBundleResult<ClaimProofBundleHandle> {
    _ = request
    _ = witnesses
    return try ZKProviderClaimProofBundleResult(
      handle: ClaimProofBundleHandle(),
      metrics: ZKClaimProofBundleMetrics(
        stageCount: ZKClaimProofBundleStage.allCases.count,
        proofByteCount: ZKClaimProofBundleByteCount(4 * 96)
      )
    )
  }

  func prove(
    request: ReallyMeZKStageProveRequest,
    witness: WitnessHandle
  ) async throws(ReallyMeZKError) -> ZKProviderProofResult<ProofHandle> {
    _ = request
    _ = witness
    throw ReallyMeZKError.providerRejected(.proofRejected)
  }

  func verifyDiagnosticStage(
    request: ReallyMeZKStageVerifyRequest,
    proof: ProofHandle
  ) async throws(ReallyMeZKError) -> Bool {
    _ = request
    _ = proof
    return false
  }

  func releaseWitness(
    _ witness: WitnessHandle
  ) async throws(ReallyMeZKError) {
    _ = witness
    releaseCount += 1
    throw ReallyMeZKError.providerRejected(.malformedWitness)
  }

  func verifyPresentationBoundClaimBundle(
    request: ReallyMeZKPresentationBoundClaimBundleVerifyRequest,
    claimProofBundle: ClaimProofBundleHandle
  ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
    _ = claimProofBundle
    return try verifiedClaimProofBundle(
      bundleKind: .privatePersona, binding: request.expectedSessionBinding)
  }
}

func verifiedClaimProofBundle(
  bundleKind: ZKClaimProofBundleKind,
  binding: Reallyme_Zk_V1_ZkSessionBinding
) throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerification {
  try ReallyMeZKPresentationBoundClaimBundleVerification(
    bundleKind: bundleKind,
    verifiedStageCount: ZKClaimProofBundleStage.allCases.count,
    sessionBinding: binding,
    issuer: trustedIssuer(),
    persona: nil,
    claimNameHash: ReallyMeZKSensitiveBytes(Data(repeating: 11, count: 32)),
    claimValue: ReallyMeZKSensitiveBytes(Data([1, 2, 3])),
    claimValueLength: 3,
    credentialBinding: ReallyMeZKSensitiveBytes(Data(repeating: 13, count: 32)),
    sessionLinkCommitment: ReallyMeZKSensitiveBytes(Data(repeating: 12, count: 32)),
    presentationExpiryUnix: 500
  )
}

func uiCoordinate(
  from coordinate: ReallyMeZKStageCoordinate
) throws(ReallyMeZKError) -> (
  bundleKind: ZKClaimProofBundleKind,
  credentialHashAlgorithm: ZKCredentialHashAlgorithm,
  stage: ZKClaimProofBundleStage
) {
  let bundleKind: ZKClaimProofBundleKind
  switch coordinate.family {
  case .credentialSubjectClaimV1:
    bundleKind = .credentialSubjectClaim
  case .privatePersonaClaimV1:
    bundleKind = .privatePersona
  default:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }

  let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  switch coordinate.credentialHashAlgorithm {
  case .sha256:
    credentialHashAlgorithm = .sha256
  case .poseidon2:
    credentialHashAlgorithm = .poseidon2
  default:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }

  let stage: ZKClaimProofBundleStage
  switch coordinate.stage {
  case .session:
    stage = .session
  case .credentialEnvelope:
    stage = .credentialEnvelope
  case .credentialRoot:
    stage = .credentialRoot
  case .claim:
    stage = .claim
  default:
    throw ReallyMeZKError.invalidProviderResponse(.malformedProof)
  }

  return (bundleKind, credentialHashAlgorithm, stage)
}
