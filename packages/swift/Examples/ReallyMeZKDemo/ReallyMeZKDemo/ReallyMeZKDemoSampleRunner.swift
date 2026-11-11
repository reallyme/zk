// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKDemoSupport
import ReallyMeZKKit
import ReallyMeZKPlatformNative
import ReallyMeZkProtoGenerated

public enum ProofOracleHash {
  case poseidon2
  case keccak
}

public struct ProofOptions {
  public var ipaAccumulation: Bool
  public var disableZk: Bool
  public var oracleHash: ProofOracleHash
  public var circuitCredentialHashAlgorithm: ZKCredentialHashAlgorithm
  public var threadCount: Int

  public init(
    ipaAccumulation: Bool = false,
    disableZk: Bool = false,
    oracleHash: ProofOracleHash = .keccak,
    circuitCredentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    threadCount: Int = 0
  ) {
    self.ipaAccumulation = ipaAccumulation
    self.disableZk = disableZk
    self.oracleHash = oracleHash
    self.circuitCredentialHashAlgorithm = circuitCredentialHashAlgorithm
    self.threadCount = threadCount
  }
}

public struct ProofSampleResult {
  public let circuitLabel: String
  public let circuitName: String
  public let verificationKeySize: Int?
  public let publicInputsSize: Int
  public let proofSize: Int
  public let writeVkMilliseconds: Double?
  public let witnessMilliseconds: Double
  public let proveMilliseconds: Double
  public let verifyMilliseconds: Double
  public let fixtureBundleVerified: Bool
}

public enum ProofSampleError: Error, Equatable {
  case providerUnavailable
  case artifactMismatch
  case operationCancelled
  case alreadyRunning
  case proofRejected
  case malformedFixture
  case invalidOptions
  case internalFailure
}

extension ProofSampleError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .providerUnavailable:
      return "ZK provider is unavailable."
    case .artifactMismatch:
      return "The bundled ZK artifacts do not match this provider."
    case .operationCancelled:
      return "The proof job was cancelled."
    case .alreadyRunning:
      return "Another proof job is already running."
    case .proofRejected:
      return "The generated proof was rejected."
    case .malformedFixture:
      return "The demo fixture is malformed."
    case .invalidOptions:
      return "The proof options do not match the reviewed demo configuration."
    case .internalFailure:
      return "The proof provider failed."
    }
  }
}

public enum ReallyMeZKDemoSampleRunner {
  public typealias ProgressHandler = @Sendable (String) -> Void

  public enum BundleKind: String, CaseIterable, Identifiable, Sendable {
    case credentialSubjectClaim = "credential_subject_claim"
    case privatePersona = "private_persona"

    public var id: String { rawValue }

    public var displayName: String {
      switch self {
      case .credentialSubjectClaim:
        return "Credential subject claim"
      case .privatePersona:
        return "Private Persona"
      }
    }
  }

  public static func runFlow(
    bundleKind: BundleKind,
    bundle: Bundle = .main,
    options: ProofOptions = ProofOptions(
      ipaAccumulation: false,
      disableZk: false,
      oracleHash: .keccak,
      circuitCredentialHashAlgorithm: .sha256,
      threadCount: 1
    ),
    progress: ProgressHandler? = nil
  ) async throws(ProofSampleError) -> ProofSampleResult {
    guard options.ipaAccumulation == false,
      options.disableZk == false,
      options.oracleHash == .keccak,
      options.threadCount == 1
    else {
      throw ProofSampleError.invalidOptions
    }
    if Task.isCancelled {
      throw ProofSampleError.operationCancelled
    }
    let context = try DemoNativeContext(bundle: bundle)
    let provider: ReallyMeZKNativeProvider<ReallyMeZKPlatformTransport>
    do {
      provider = try ReallyMeZKNativeProvider(
        contextHandle: context.contextHandle,
        transport: context.transport
      )
    } catch {
      throw ProofSampleError.providerUnavailable
    }
    let runner = ReallyMeZKRuntime.makeSampleRunner(
      provider: provider,
      bundleVerifyRequestProvider: { _, _ async throws(ReallyMeZKError) in
        try ReallyMeZKDemoVerifierPolicy.bundleVerifyRequest()
      },
      witnessInputProvider: {
        bundleKind,
        credentialHashAlgorithm,
        stage async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitnessInput in
        let input = try fixtureWitnessInput(
          bundleKind: bundleKind,
          credentialHashAlgorithm: credentialHashAlgorithm,
          stage: stage,
          bundle: bundle
        )
        if stage == .session {
          let binding = try ReallyMeZKDemoFixtureWitnessInputs.sessionBinding(input: input)
          try ReallyMeZKDemoVerifierPolicy.validateReviewedFixtureSession(binding)
        } else if stage == .credentialEnvelope {
          let issuer = try ReallyMeZKDemoFixtureWitnessInputs.issuer(input: input)
          try ReallyMeZKDemoVerifierPolicy.validateReviewedFixtureIssuer(issuer)
        }
        return input
      }
    )
    let result: ZKSampleResult
    do {
      result = try await runner.runFlow(
        bundleKind: bundleKind.zkBundleKind,
        credentialHashAlgorithm: options.circuitCredentialHashAlgorithm,
        progress: progress
      )
    } catch {
      do {
        try await context.close()
      } catch {
        throw mapError(error)
      }
      throw mapError(error)
    }
    do {
      try await context.close()
    } catch {
      throw mapError(error)
    }
    return ProofSampleResult(
      circuitLabel:
        "\(bundleKind.displayName) \(options.circuitCredentialHashAlgorithm.displayName)",
      circuitName: "\(options.circuitCredentialHashAlgorithm.rawValue)_\(bundleKind.rawValue)",
      verificationKeySize: nil,
      publicInputsSize: result.publicInputsSize,
      proofSize: result.proofSize,
      writeVkMilliseconds: nil,
      witnessMilliseconds: result.witnessMilliseconds,
      proveMilliseconds: result.proveMilliseconds,
      verifyMilliseconds: result.verifyMilliseconds,
      fixtureBundleVerified: result.fixtureBundleVerified
    )
  }
}

extension ReallyMeZKDemoSampleRunner.BundleKind {
  fileprivate var zkBundleKind: ZKClaimProofBundleKind {
    switch self {
    case .credentialSubjectClaim:
      return .credentialSubjectClaim
    case .privatePersona:
      return .privatePersona
    }
  }
}

private func mapError(_ error: Error) -> ProofSampleError {
  guard let zkError = error as? ReallyMeZKError else {
    return .internalFailure
  }
  switch zkError {
  case .providerUnavailable:
    return .providerUnavailable
  case .providerRejected(.artifactMismatch), .invalidProviderResponse(.artifactMismatch):
    return .artifactMismatch
  case .alreadyRunning:
    return .alreadyRunning
  case .operationCancelled:
    return .operationCancelled
  case .providerRejected(.malformedWitness), .invalidProviderResponse(.malformedWitness):
    return .malformedFixture
  case .providerRejected(.proofRejected), .invalidProviderResponse(.proofRejected):
    return .proofRejected
  case .providerRejected(.crsMissing), .providerRejected(.crsHashMismatch),
    .invalidProviderResponse(.crsMissing), .invalidProviderResponse(.crsHashMismatch):
    return .providerUnavailable
  case .invalidProviderResponse, .providerRejected:
    return .internalFailure
  }
}

private func fixtureWitnessInput(
  bundleKind: ZKClaimProofBundleKind,
  credentialHashAlgorithm: ZKCredentialHashAlgorithm,
  stage: ZKClaimProofBundleStage,
  bundle: Bundle
) throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitnessInput {
  try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
    bundleKind: bundleKind,
    credentialHashAlgorithm: credentialHashAlgorithm,
    stage: stage,
    bundle: bundle
  )
}
