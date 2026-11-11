// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKKit
import ReallyMeZkProtoGenerated
import Synchronization

/// Runs the sample app proof flow through the production bundle boundary.
///
/// The demo still surfaces per-stage witness progress, but the success decision
/// uses `verifyPresentationBoundClaimBundle` with independent verifier policy.
/// This fixture flow establishes presentation evidence, not credential acceptance
/// or single-use enforcement for live sessions.
public final class ReallyMeZKSampleRunner<Provider: ReallyMeZKClaimProofBundleProvider>: Sendable {
  public typealias ProgressHandler = @Sendable (String) -> Void
  public typealias WitnessInputProvider =
    @Sendable (
      ZKClaimProofBundleKind,
      ZKCredentialHashAlgorithm,
      ZKClaimProofBundleStage
    ) async throws(ReallyMeZKError) -> Reallyme_Zk_V1_ZkStageWitnessInput
  public typealias BundleVerifyRequestProvider =
    @Sendable (
      ZKClaimProofBundleKind,
      ZKCredentialHashAlgorithm
    ) async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerifyRequest

  private let provider: Provider
  private let bundleVerifyRequestProvider: BundleVerifyRequestProvider
  private let witnessInputProvider: WitnessInputProvider
  private let singleFlight: SingleFlightGate

  public init(
    provider: Provider,
    bundleVerifyRequestProvider: @escaping BundleVerifyRequestProvider,
    witnessInputProvider: @escaping WitnessInputProvider = { _, _, _ in
      Reallyme_Zk_V1_ZkStageWitnessInput()
    }
  ) {
    self.provider = provider
    self.bundleVerifyRequestProvider = bundleVerifyRequestProvider
    self.witnessInputProvider = witnessInputProvider
    self.singleFlight = SingleFlightGate()
  }

  public func runFlow(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm = .sha256,
    progress: ProgressHandler? = nil
  ) async throws(ReallyMeZKError) -> ZKSampleResult {
    try checkCancellation()
    guard singleFlight.tryAcquire() else {
      throw ReallyMeZKError.alreadyRunning
    }

    do {
      let result = try await runFlowImpl(
        bundleKind: bundleKind,
        credentialHashAlgorithm: credentialHashAlgorithm,
        progress: progress
      )
      singleFlight.release()
      return result
    } catch {
      singleFlight.release()
      throw error
    }
  }

  private func runFlowImpl(
    bundleKind: ZKClaimProofBundleKind,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    progress: ProgressHandler?
  ) async throws(ReallyMeZKError) -> ZKSampleResult {
    let totalProgressSteps = ZKClaimProofBundleStage.allCases.count + 2
    var progressStep = 0
    var proofSize = 0
    var witnessMilliseconds = 0.0
    var proveMilliseconds = 0.0
    var verifyMilliseconds = 0.0
    var retainedWitnesses: [Provider.WitnessHandle] = []

    progress?(
      "UI_STATUS|Starting \(bundleKind.displayName) \(credentialHashAlgorithm.displayName) proof flow."
    )
    let verifyRequest: ReallyMeZKPresentationBoundClaimBundleVerifyRequest
    do {
      verifyRequest = try await bundleVerifyRequestProvider(bundleKind, credentialHashAlgorithm)
      for stage in ZKClaimProofBundleStage.allCases {
        try checkCancellation()
        let witnessInput = try await witnessInputProvider(
          bundleKind, credentialHashAlgorithm, stage)
        let request = ZKStageRequest(
          bundleKind: bundleKind,
          credentialHashAlgorithm: credentialHashAlgorithm,
          stage: stage,
          witnessInput: witnessInput
        )
        let witnessRequest = request.providerWitnessRequest()

        progress?("UI_STATUS|Generating \(stage.label) witness.")
        let witnessMeasurement = try await measure { () async throws(ReallyMeZKError) in
          try await provider.generateWitness(request: witnessRequest)
        }
        retainedWitnesses.append(witnessMeasurement.value.handle)
        witnessMilliseconds += witnessMeasurement.milliseconds
        progressStep += 1
        progress?(
          "UI_PROGRESS|\(progressStep)|\(totalProgressSteps)|Generated \(stage.label) witness."
        )
      }
    } catch {
      let primaryError = error
      await releaseRetainedWitnesses(retainedWitnesses)
      throw primaryError
    }

    let bundleMeasurement:
      TimedValue<ZKProviderClaimProofBundleResult<Provider.ClaimProofBundleHandle>>
    do {
      try checkCancellation()
      progress?("UI_STATUS|Proving proof bundle.")
      let proveRequest = ReallyMeZKClaimProofBundleProveRequest(
        bundleKind: bundleKind,
        credentialHashAlgorithm: credentialHashAlgorithm,
        sessionBinding: verifyRequest.expectedSessionBinding
      )
      bundleMeasurement = try await measure { () async throws(ReallyMeZKError) in
        try await provider.proveClaimProofBundle(
          request: proveRequest,
          witnesses: retainedWitnesses
        )
      }
      retainedWitnesses.removeAll()
    } catch {
      let primaryError = error
      await releaseRetainedWitnesses(retainedWitnesses)
      throw primaryError
    }
    proveMilliseconds += bundleMeasurement.milliseconds
    proofSize = bundleMeasurement.value.metrics.proofByteCount.value
    progressStep += 1
    progress?(
      "UI_PROGRESS|\(progressStep)|\(totalProgressSteps)|Generated proof bundle."
    )

    try checkCancellation()
    progress?("UI_STATUS|Verifying proof bundle.")
    let verificationMeasurement = try await measure { () async throws(ReallyMeZKError) in
      try await provider.verifyPresentationBoundClaimBundle(
        request: verifyRequest,
        claimProofBundle: bundleMeasurement.value.handle
      )
    }
    let verifiedClaimProofBundle = verificationMeasurement.value
    guard verifiedClaimProofBundle.bundleKind == bundleKind,
      verifiedClaimProofBundle.verifiedStageCount == ZKClaimProofBundleStage.allCases.count,
      verifiedClaimProofBundle.sessionBinding == verifyRequest.expectedSessionBinding
    else {
      throw ReallyMeZKError.providerRejected(.proofRejected)
    }
    verifyMilliseconds += verificationMeasurement.milliseconds
    progressStep += 1
    progress?("UI_PROGRESS|\(progressStep)|\(totalProgressSteps)|Bundle verified.")

    return ZKSampleResult(
      bundleKind: bundleKind,
      verificationKeySize: 0,
      publicInputsSize: 0,
      proofSize: proofSize,
      witnessMilliseconds: witnessMilliseconds,
      proveMilliseconds: proveMilliseconds,
      verifyMilliseconds: verifyMilliseconds,
      fixtureBundleVerified: true
    )
  }

  private func releaseRetainedWitnesses(
    _ witnesses: [Provider.WitnessHandle]
  ) async {
    for witness in witnesses {
      do {
        try await provider.releaseWitness(witness)
      } catch {
        continue
      }
    }
  }
}

private func checkCancellation() throws(ReallyMeZKError) {
  if Task.isCancelled {
    throw ReallyMeZKError.operationCancelled
  }
}

private final class SingleFlightGate: Sendable {
  private let inFlight = Mutex(false)

  func tryAcquire() -> Bool {
    inFlight.withLock { isInFlight in
      if isInFlight {
        return false
      }
      isInFlight = true
      return true
    }
  }

  func release() {
    inFlight.withLock { isInFlight in
      isInFlight = false
    }
  }
}

private struct TimedValue<Value: Sendable>: Sendable {
  let value: Value
  let milliseconds: Double
}

private func measure<Value: Sendable>(
  _ operation: () async throws(ReallyMeZKError) -> Value
) async throws(ReallyMeZKError) -> TimedValue<Value> {
  let start = ContinuousClock.now
  let value = try await operation()
  let elapsed = start.duration(to: ContinuousClock.now)
  return TimedValue(value: value, milliseconds: elapsed.milliseconds)
}

extension Duration {
  fileprivate var milliseconds: Double {
    let components = self.components
    let seconds = Double(components.seconds) * 1_000.0
    let fractional = Double(components.attoseconds) / 1_000_000_000_000_000.0
    return seconds + fractional
  }
}
