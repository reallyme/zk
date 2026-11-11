// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Darwin
import Foundation
import ReallyMeZKDemoSupport
import ReallyMeZKKit
import ReallyMeZKPlatformNative
import ReallyMeZkProtoGenerated
import XCTest
import os

@testable import ReallyMeZKDemo

final class ReallyMeZKDemoIntegrationTests: XCTestCase {
  func testPreparedPublicStagesCanBeVerifiedRepeatedlyWithoutNewProving() async throws {
    let prepared = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.prepare(
      mode: .publicPersona,
      credentialHashAlgorithm: .sha256,
      bundle: .main
    )
    XCTAssertGreaterThan(prepared.generationMilliseconds, 0)
    let first = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.verifyCachedStages(
      prepared, bundle: .main)
    let second = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.verifyCachedStages(
      prepared, bundle: .main)
    let third = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.verifyCachedStages(
      prepared, bundle: .main)
    XCTAssertGreaterThanOrEqual(first, 0)
    XCTAssertGreaterThanOrEqual(second, 0)
    XCTAssertGreaterThanOrEqual(third, 0)
  }

  func testPreparedPrivateStagesGenerateAndVerifyOnce() async throws {
    let prepared = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.prepare(
      mode: .privatePersona,
      credentialHashAlgorithm: .sha256,
      bundle: .main
    )
    XCTAssertGreaterThan(prepared.generationMilliseconds, 0)
    let verificationMilliseconds =
      try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.verifyCachedStages(
        prepared, bundle: .main)
    XCTAssertGreaterThanOrEqual(verificationMilliseconds, 0)
  }

  func testNativeContextReportsReleaseIndexMismatch() throws {
    let resourceRoot = try XCTUnwrap(Bundle.main.url(forResource: "zk_demo", withExtension: nil))
    let artifactRoot = resourceRoot.appendingPathComponent("artifacts", isDirectory: true)
    let indexURL = resourceRoot.appendingPathComponent("release-index.pb")
    let g1URL = resourceRoot.appendingPathComponent("crs/bn254_g1.prover")
    let g2URL = resourceRoot.appendingPathComponent("crs/bn254_g2")

    XCTAssertThrowsError(
      try ReallyMeZKPlatformContext(
        artifactRoot: artifactRoot,
        releaseIndexURL: indexURL,
        approvedReleaseIndexSHA256: Data(repeating: 0, count: 32),
        crsG1URL: g1URL,
        crsG2URL: g2URL,
        crsMode: .fullProver
      )
    ) { error in
      XCTAssertEqual(error as? ReallyMeZKError, .providerRejected(.artifactMismatch))
    }
  }

  func testCommonCredentialRootPreparedSamplesVerifyEveryPersonaAndHashChoice() async throws {
    for mode in [ZKCommonCredentialRootPersonaMode.privatePersona, .publicPersona] {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        let result = try await ReallyMeZKDemoCommonCredentialRootRunner.verifyBundledSample(
          mode: mode,
          credentialHashAlgorithm: credentialHashAlgorithm,
          bundle: .main
        )
        XCTAssertEqual(9, result.verifiedProofCount)
        XCTAssertGreaterThanOrEqual(result.verificationMilliseconds, 0)
      }
    }
  }

  func testCommonCredentialRootGeneratedSamplesProveAndVerifyEveryPersonaAndHashChoice()
    async throws
  {
    for mode in [ZKCommonCredentialRootPersonaMode.privatePersona, .publicPersona] {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        let completedStages = OSAllocatedUnfairLock(initialState: [Int]())
        let result = try await ReallyMeZKDemoCommonCredentialRootRunner.generateSample(
          mode: mode,
          credentialHashAlgorithm: credentialHashAlgorithm,
          bundle: .main,
          progress: { count in completedStages.withLock { $0.append(count) } }
        )
        XCTAssertEqual(Array(1...9), completedStages.withLock { $0 })
        XCTAssertEqual(9, result.verifiedProofCount)
        XCTAssertGreaterThan(result.generationMilliseconds, 0)
        XCTAssertGreaterThanOrEqual(result.verificationMilliseconds, 0)
      }
    }
  }

  func testCommonCredentialRootGeneratedSampleRejectsAlteredSession() async throws {
    let completedStages = OSAllocatedUnfairLock(initialState: [Int]())
    let result =
      try await ReallyMeZKDemoCommonCredentialRootRunner.generateSampleAndRejectAlteredSession(
        mode: .privatePersona,
        credentialHashAlgorithm: .poseidon2,
        bundle: .main,
        progress: { count in completedStages.withLock { $0.append(count) } }
      )
    XCTAssertEqual(Array(1...9), completedStages.withLock { $0 })
    XCTAssertEqual(9, result.acceptedVerifiedProofCount)
    XCTAssertTrue(result.rejectedWrongSession)
    XCTAssertGreaterThan(result.generationMilliseconds, 0)
    XCTAssertGreaterThanOrEqual(result.acceptedVerificationMilliseconds, 0)
    XCTAssertGreaterThanOrEqual(result.rejectedVerificationMilliseconds, 0)
  }

  func testApplicationBundleContainsEveryDemoFixture() throws {
    var expectedNames = Set<String>()
    for bundleKind in ReallyMeZKDemoSampleRunner.BundleKind.allCases {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        for stage in ZKClaimProofBundleStage.allCases {
          let resourceName = try ReallyMeZKDemoFixtureWitnessInputs.fixtureResourceName(
            bundleKind: zkProfile(for: bundleKind),
            credentialHashAlgorithm: credentialHashAlgorithm,
            stage: stage
          )
          expectedNames.insert("\(resourceName).pb")
          let url = Bundle.main.url(forResource: resourceName, withExtension: "pb")
          XCTAssertNotNil(url, "Missing demo fixture resource: \(resourceName).pb")
        }
      }
    }
    let protobufNames = fixtureResourceNames(extension: "pb")
    XCTAssertEqual(expectedNames, protobufNames)
    XCTAssertTrue(fixtureResourceNames(extension: "json").isEmpty)
  }

  func testSampleRunnerRejectsVerifierPolicyBeforeDispatch() async throws {
    let provider = try ReallyMeZKNativeProvider(
      contextHandle: 1,
      transport: RejectingNativeTransport()
    )
    let runner = ReallyMeZKRuntime.makeSampleRunner(
      provider: provider,
      bundleVerifyRequestProvider: {
        _,
        _ async throws(ReallyMeZKError) -> ReallyMeZKPresentationBoundClaimBundleVerifyRequest in
        throw ReallyMeZKError.providerUnavailable
      }
    )

    do {
      _ = try await runner.runFlow(bundleKind: .credentialSubjectClaim)
      XCTFail("the verifier policy must fail before native dispatch")
    } catch {
      XCTAssertEqual(.providerUnavailable, error)
    }
  }

  func testAllProfilesRunWitnessProveVerifyFromApplicationBundle() async throws {
    var footprintEvidence: [DemoFlowCoordinate: FootprintSample] = [:]
    for bundleKind in ReallyMeZKDemoSampleRunner.BundleKind.allCases {
      for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
        let recorder = ProgressRecorder()
        let footprintSampler = FootprintSampler()
        let footprintTask = footprintSampler.start()
        let result: ProofSampleResult
        do {
          result = try await ReallyMeZKDemoSampleRunner.runFlow(
            bundleKind: bundleKind,
            bundle: .main,
            options: ProofOptions(
              circuitCredentialHashAlgorithm: credentialHashAlgorithm, threadCount: 1)
          ) { line in
            recorder.append(line)
          }
        } catch {
          footprintTask.cancel()
          await footprintTask.value
          XCTFail(
            "bundleKind \(bundleKind.rawValue) hash \(credentialHashAlgorithm.rawValue) failed with \(error); progress=\(recorder.snapshot())"
          )
          continue
        }
        footprintTask.cancel()
        await footprintTask.value
        let footprintSample = footprintSampler.snapshot()
        let coordinate = DemoFlowCoordinate(
          bundleKind: bundleKind, credentialHashAlgorithm: credentialHashAlgorithm)
        footprintEvidence[coordinate] = footprintSample

        XCTAssertEqual(
          "\(credentialHashAlgorithm.rawValue)_\(bundleKind.rawValue)", result.circuitName)
        XCTAssertTrue(result.fixtureBundleVerified)
        XCTAssertGreaterThan(result.proofSize, 0)
        XCTAssertEqual(0, result.publicInputsSize)
        XCTAssertEqual(6, recorder.progressLines().count)
        XCTAssertGreaterThan(footprintSample.samples, 0)
        XCTAssertGreaterThan(footprintSample.maxPhysFootprintBytes, 0)
        print(
          footprintLogLine(
            bundleKind: bundleKind,
            credentialHashAlgorithm: credentialHashAlgorithm,
            sample: footprintSample
          )
        )
      }
    }
    for bundleKind in ReallyMeZKDemoSampleRunner.BundleKind.allCases {
      let sha256Coordinate = DemoFlowCoordinate(
        bundleKind: bundleKind, credentialHashAlgorithm: .sha256)
      let poseidon2Coordinate = DemoFlowCoordinate(
        bundleKind: bundleKind, credentialHashAlgorithm: .poseidon2)
      let sha256 = footprintEvidence[sha256Coordinate]
      let poseidon2 = footprintEvidence[poseidon2Coordinate]
      XCTAssertNotNil(sha256)
      XCTAssertNotNil(poseidon2)
      if let sha256, let poseidon2 {
        print(footprintComparisonLine(bundleKind: bundleKind, sha256: sha256, poseidon2: poseidon2))
      }
    }
  }

  func testInvalidOptionsFailClosedBeforeNativeProvider() async {
    do {
      _ = try await ReallyMeZKDemoSampleRunner.runFlow(
        bundleKind: .privatePersona,
        bundle: .main,
        options: ProofOptions(
          ipaAccumulation: true,
          disableZk: false,
          oracleHash: .keccak,
          threadCount: 1
        )
      )
      XCTFail("invalid proof options should fail closed")
    } catch {
      XCTAssertEqual(.invalidOptions, error)
    }
  }

  func testNativeProviderRejectsAlteredSessionBinding() async throws {
    for credentialHashAlgorithm in ZKCredentialHashAlgorithm.allCases {
      let context = try DemoNativeContext(bundle: .main)
      do {
        let provider = try ReallyMeZKNativeProvider(
          contextHandle: context.contextHandle,
          transport: context.transport
        )
        let request = try stageRequest(
          bundleKind: .privatePersona,
          credentialHashAlgorithm: credentialHashAlgorithm,
          stage: .session
        )
        let witness = try await provider.generateWitness(request: request.providerWitnessRequest())
        let proof: ZKProviderProofResult<ReallyMeZKNativeProofHandle>
        do {
          proof = try await provider.prove(
            request: request.providerProveRequest(),
            witness: witness.handle
          )
        } catch {
          try? await provider.releaseWitness(witness.handle)
          throw error
        }

        let expectedBinding = try ReallyMeZKDemoFixtureWitnessInputs.sessionBinding(
          input: request.witnessInput
        )
        try await assertRejectedBinding(
          request: request,
          proof: proof.handle,
          provider: provider,
          binding: alteredNonce(expectedBinding),
          message: "\(credentialHashAlgorithm.rawValue) altered nonce must not verify"
        )
        try await assertRejectedBinding(
          request: request,
          proof: proof.handle,
          provider: provider,
          binding: alteredAudience(expectedBinding),
          message: "\(credentialHashAlgorithm.rawValue) altered audience must not verify"
        )
        try await assertRejectedBinding(
          request: request,
          proof: proof.handle,
          provider: provider,
          binding: alteredTransactionData(expectedBinding),
          message: "\(credentialHashAlgorithm.rawValue) altered transaction data must not verify"
        )
        try await context.close()
      } catch {
        try? await context.close()
        throw error
      }
    }
  }

  func testMissingDemoResourcesFailClosed() async {
    do {
      _ = try await ReallyMeZKDemoSampleRunner.runFlow(
        bundleKind: .privatePersona,
        bundle: Bundle(for: Self.self)
      )
      XCTFail("missing demo resources should fail closed")
    } catch {
      XCTAssertEqual(.providerUnavailable, error)
    }
  }

  func testLargestClaimBundle4DiagnosticProveVerifyRecordsPeakMemoryOnDevice() async throws {
    let demoRoot = try diagnosticDemoRoot()
    let diagnosticRoot = demoRoot.appendingPathComponent(
      "diagnostic_claim_bundle4",
      isDirectory: true
    )
    guard FileManager.default.fileExists(atPath: diagnosticRoot.path) else {
      throw XCTSkip("claim_bundle_4 diagnostic assets are not staged")
    }
    let exactSourceRoot = diagnosticRoot.appendingPathComponent("exact_source", isDirectory: true)
    var proveRequestBytes = try readDiagnosticData(
      diagnosticRoot.appendingPathComponent("prove_request.pb"),
      maximumBytes: maxClaimBundle4RequestBytes
    )
    let proveRequest = try Reallyme_Zk_V1_ZkProviderOperationRequest(
      serializedBytes: proveRequestBytes
    )
    guard case .proveStage(let proveStage) = proveRequest.operation else {
      XCTFail("diagnostic request must be a stage prove operation")
      zeroizeData(&proveRequestBytes)
      return
    }
    XCTAssertEqual(.claimBundle4, proveStage.circuitRef.stage)

    let context = try diagnosticContext(demoRoot: demoRoot, exactSourceRoot: exactSourceRoot)
    let sampler = FootprintSampler()
    let sampleTask = sampler.start()
    let started = DispatchTime.now().uptimeNanoseconds
    do {
      let proveResponse = try await dispatchSuccess(
        context: context,
        requestBytes: proveRequestBytes
      )
      guard case .stageProof(let proof)? = proveResponse.result.result else {
        XCTFail("diagnostic prove response must contain a stage proof")
        sampleTask.cancel()
        await sampleTask.value
        try? await context.close()
        zeroizeData(&proveRequestBytes)
        return
      }
      XCTAssertEqual(.claimBundle4, proof.circuitRef.stage)
      XCTAssertGreaterThan(proof.proof.count, 0)
      XCTAssertGreaterThan(proof.publicInputs.encoded.count, 0)

      var verifyRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
      var verifyStage = Reallyme_Zk_V1_ZkStageVerifyOperation()
      verifyStage.proof = proof
      verifyStage.expectedBinding = proveStage.sessionBinding
      verifyStage.expectedProofSuite = proveStage.proofSuite
      verifyRequest.verifyStage = verifyStage
      var verifyRequestBytes = try verifyRequest.serializedData()
      defer {
        zeroizeData(&verifyRequestBytes)
      }
      let verifyResponse = try await dispatchSuccess(
        context: context,
        requestBytes: verifyRequestBytes
      )
      guard case .stageVerification(let verification)? = verifyResponse.result.result else {
        XCTFail("diagnostic verify response must contain stage verification")
        sampleTask.cancel()
        await sampleTask.value
        try? await context.close()
        zeroizeData(&proveRequestBytes)
        return
      }
      XCTAssertEqual(.claimBundle4, verification.circuitRef.stage)
      let elapsedMilliseconds = elapsedMillisecondsSince(started)
      sampleTask.cancel()
      await sampleTask.value
      let footprint = sampler.snapshot()
      XCTAssertGreaterThan(elapsedMilliseconds, 0)
      XCTAssertLessThanOrEqual(
        footprint.maxPhysFootprintBytes,
        maxClaimBundle4DiagnosticFootprintBytes
      )
      print(
        claimBundle4DiagnosticLine(
          requestBytes: proveRequestBytes.count,
          proof: proof,
          elapsedMilliseconds: elapsedMilliseconds,
          footprint: footprint
        )
      )
      try await context.close()
      zeroizeData(&proveRequestBytes)
    } catch {
      sampleTask.cancel()
      await sampleTask.value
      try? await context.close()
      zeroizeData(&proveRequestBytes)
      throw error
    }
  }
}

private struct RejectingNativeTransport: ReallyMeZKNativeTransport {
  func dispatch(
    contextHandle: UInt64,
    request: Data
  ) async throws(ReallyMeZKError) -> Data {
    throw ReallyMeZKError.providerUnavailable
  }
}

private func stageRequest(
  bundleKind: ZKClaimProofBundleKind,
  credentialHashAlgorithm: ZKCredentialHashAlgorithm,
  stage: ZKClaimProofBundleStage
) throws -> ZKStageRequest {
  let input = try ReallyMeZKDemoFixtureWitnessInputs.witnessInput(
    bundleKind: bundleKind,
    credentialHashAlgorithm: credentialHashAlgorithm,
    stage: stage,
    bundle: .main
  )
  return ZKStageRequest(
    bundleKind: bundleKind,
    credentialHashAlgorithm: credentialHashAlgorithm,
    stage: stage,
    witnessInput: input
  )
}

private func assertRejectedBinding<Transport: ReallyMeZKNativeTransport>(
  request: ZKStageRequest,
  proof: ReallyMeZKNativeProofHandle,
  provider: ReallyMeZKNativeProvider<Transport>,
  binding: Reallyme_Zk_V1_ZkSessionBinding,
  message: String,
  file: StaticString = #filePath,
  line: UInt = #line
) async throws {
  let verified = try await provider.verifyDiagnosticStage(
    request: request.providerVerifyRequest(expectedSessionBinding: binding),
    proof: proof
  )
  XCTAssertFalse(verified, message, file: file, line: line)
}

private func alteredNonce(
  _ binding: Reallyme_Zk_V1_ZkSessionBinding
) -> Reallyme_Zk_V1_ZkSessionBinding {
  var altered = binding
  altered.nonceHash = alteredDigest(binding.nonceHash)
  return altered
}

private func alteredAudience(
  _ binding: Reallyme_Zk_V1_ZkSessionBinding
) -> Reallyme_Zk_V1_ZkSessionBinding {
  var altered = binding
  altered.audienceHash = alteredDigest(binding.audienceHash)
  return altered
}

private func alteredTransactionData(
  _ binding: Reallyme_Zk_V1_ZkSessionBinding
) -> Reallyme_Zk_V1_ZkSessionBinding {
  var altered = binding
  altered.transactionDataHash = alteredDigest(binding.transactionDataHash)
  return altered
}

private func alteredDigest(_ digest: Data) -> Data {
  var altered = digest
  if altered.isEmpty {
    return Data(repeating: 1, count: 32)
  }
  altered[altered.startIndex] ^= 0x01
  return altered
}

private func fixtureResourceNames(extension resourceExtension: String) -> Set<String> {
  let urls = Bundle.main.urls(forResourcesWithExtension: resourceExtension, subdirectory: nil) ?? []
  return Set(
    urls.map(\.lastPathComponent).filter { name in
      name.starts(with: "sha256_flow_") || name.starts(with: "poseidon2_flow_")
    })
}

private func diagnosticDemoRoot() throws -> URL {
  guard let url = Bundle.main.url(forResource: "zk_demo", withExtension: nil) else {
    throw ReallyMeZKError.providerUnavailable
  }
  return url
}

private func diagnosticContext(
  demoRoot: URL,
  exactSourceRoot: URL
) throws -> ReallyMeZKPlatformContext {
  let indexURL = demoRoot.appendingPathComponent("release-index.pb")
  let g1URL = demoRoot.appendingPathComponent("crs/bn254_g1.prover")
  let g2URL = demoRoot.appendingPathComponent("crs/bn254_g2")
  return try ReallyMeZKPlatformContext(
    artifactRoot: exactSourceRoot,
    releaseIndexURL: indexURL,
    approvedReleaseIndexSHA256: checkedDiagnosticHexDigest(approvedReleaseIndexSha256),
    crsG1URL: g1URL,
    crsG2URL: g2URL,
    crsMode: .fullProver
  )
}

private func dispatchSuccess(
  context: ReallyMeZKPlatformContext,
  requestBytes: Data
) async throws -> Reallyme_Zk_V1_ZkProviderOperationResponse {
  let responseBytes = try await context.transport.dispatch(
    contextHandle: context.contextHandle,
    request: requestBytes
  )
  let response = try Reallyme_Zk_V1_ZkProviderOperationResponse(serializedBytes: responseBytes)
  XCTAssertEqual(Data(SHA256.hash(data: requestBytes)), response.requestSha256)
  guard case .result = response.outcome else {
    if case .error(let error)? = response.outcome {
      if error.reason == .unsupportedCircuit {
        throw XCTSkip("claim_bundle_4 diagnostic requires diagnostic-exact-source platform FFI")
      }
      XCTFail("provider returned typed error \(error.reason)")
    }
    throw ReallyMeZKError.providerRejected(.internalFailure)
  }
  return response
}

private func readDiagnosticData(
  _ url: URL,
  maximumBytes: Int
) throws -> Data {
  let values = try url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
  guard values.isRegularFile == true,
    let fileSize = values.fileSize,
    fileSize > 0,
    fileSize <= maximumBytes
  else {
    throw ReallyMeZKError.providerUnavailable
  }
  let data = try Data(contentsOf: url, options: [])
  guard data.isEmpty == false, data.count <= maximumBytes else {
    throw ReallyMeZKError.providerUnavailable
  }
  return data
}

private func checkedDiagnosticHexDigest(_ value: String) throws -> Data {
  guard value.count == sha256HexCharacters else {
    throw ReallyMeZKError.providerUnavailable
  }
  var bytes = Data()
  bytes.reserveCapacity(sha256Bytes)
  var index = value.startIndex
  while index < value.endIndex {
    let next = value.index(index, offsetBy: hexCharactersPerByte)
    guard let byte = UInt8(value[index..<next], radix: hexRadix) else {
      throw ReallyMeZKError.providerUnavailable
    }
    bytes.append(byte)
    index = next
  }
  return bytes
}

private func zeroizeData(_ value: inout Data) {
  _ = value.withUnsafeMutableBytes { bytes in
    bytes.initializeMemory(as: UInt8.self, repeating: 0)
  }
  value.removeAll(keepingCapacity: false)
}

private func zkProfile(for bundleKind: ReallyMeZKDemoSampleRunner.BundleKind)
  -> ZKClaimProofBundleKind
{
  switch bundleKind {
  case .credentialSubjectClaim:
    return .credentialSubjectClaim
  case .privatePersona:
    return .privatePersona
  }
}

private func footprintLogLine(
  bundleKind: ReallyMeZKDemoSampleRunner.BundleKind,
  credentialHashAlgorithm: ZKCredentialHashAlgorithm,
  sample: FootprintSample
) -> String {
  [
    "ReallyMeZKFootprint",
    "bundleKind=\(bundleKind.rawValue)",
    "hash=\(credentialHashAlgorithm.rawValue)",
    "sampledMaxPhysFootprintBytes=\(sample.maxPhysFootprintBytes)",
    "samples=\(sample.samples)",
    "intervalMs=\(sample.intervalMilliseconds)",
  ].joined(separator: " ")
}

private func footprintComparisonLine(
  bundleKind: ReallyMeZKDemoSampleRunner.BundleKind,
  sha256: FootprintSample,
  poseidon2: FootprintSample
) -> String {
  [
    "ReallyMeZKFootprintCompare",
    "bundleKind=\(bundleKind.rawValue)",
    "sha256Bytes=\(sha256.maxPhysFootprintBytes)",
    "poseidon2Bytes=\(poseidon2.maxPhysFootprintBytes)",
    "samplingIntervalMs=\(FootprintSampler.intervalMilliseconds)",
    "scope=full_flow_sampled",
  ].joined(separator: " ")
}

private func claimBundle4DiagnosticLine(
  requestBytes: Int,
  proof: Reallyme_Zk_V1_ZkProofPackage,
  elapsedMilliseconds: Double,
  footprint: FootprintSample
) -> String {
  [
    "ReallyMeZKClaimBundle4Diagnostic",
    "circuit=poseidon2/families/private_persona_claim_v1/claim_bundle_4",
    "requestBytes=\(requestBytes)",
    "proofBytes=\(proof.proof.count)",
    "publicInputBytes=\(proof.publicInputs.encoded.count)",
    "proveVerifyMs=\(elapsedMilliseconds)",
    "maxPhysFootprintBytes=\(footprint.maxPhysFootprintBytes)",
    "samples=\(footprint.samples)",
    "intervalMs=\(footprint.intervalMilliseconds)",
  ].joined(separator: " ")
}

private struct ProgressRecorder: Sendable {
  private let lines = OSAllocatedUnfairLock(initialState: [String]())

  func append(_ line: String) {
    lines.withLock { storedLines in
      storedLines.append(line)
    }
  }

  func progressLines() -> [String] {
    lines.withLock { storedLines in
      storedLines.filter { line in
        line.starts(with: "UI_PROGRESS|")
      }
    }
  }

  func snapshot() -> [String] {
    lines.withLock { storedLines in
      storedLines
    }
  }
}

private struct DemoFlowCoordinate: Hashable {
  let bundleKind: ReallyMeZKDemoSampleRunner.BundleKind
  let credentialHashAlgorithm: ZKCredentialHashAlgorithm
}

private struct FootprintSample {
  let maxPhysFootprintBytes: UInt64
  let samples: UInt64
  let intervalMilliseconds: UInt64
}

private struct FootprintState {
  var maxPhysFootprintBytes: UInt64
  var samples: UInt64
}

private final class FootprintSampler: @unchecked Sendable {
  static let intervalMilliseconds: UInt64 = 20

  private let state = OSAllocatedUnfairLock(
    initialState: FootprintState(maxPhysFootprintBytes: 0, samples: 0)
  )

  func start() -> Task<Void, Never> {
    record()
    return Task.detached(priority: .utility) { [self] in
      while Task.isCancelled == false {
        do {
          try await Task.sleep(nanoseconds: Self.intervalMilliseconds * nanosecondsPerMillisecond)
        } catch {
          return
        }
        if Task.isCancelled {
          return
        }
        record()
      }
    }
  }

  func snapshot() -> FootprintSample {
    state.withLock { storedState in
      FootprintSample(
        maxPhysFootprintBytes: storedState.maxPhysFootprintBytes,
        samples: storedState.samples,
        intervalMilliseconds: Self.intervalMilliseconds
      )
    }
  }

  private func record() {
    guard let footprint = currentPhysicalFootprintBytes() else {
      return
    }
    state.withLock { storedState in
      storedState.maxPhysFootprintBytes = max(storedState.maxPhysFootprintBytes, footprint)
      storedState.samples += 1
    }
  }
}

private func currentPhysicalFootprintBytes() -> UInt64? {
  var info = task_vm_info_data_t()
  var count = mach_msg_type_number_t(
    MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size
  )
  let result = withUnsafeMutablePointer(to: &info) { pointer in
    pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { rebound in
      task_info(
        mach_task_self_,
        task_flavor_t(TASK_VM_INFO),
        rebound,
        &count
      )
    }
  }
  guard result == KERN_SUCCESS else {
    return nil
  }
  return UInt64(info.phys_footprint)
}

private func elapsedMillisecondsSince(_ started: UInt64) -> Double {
  let elapsed = DispatchTime.now().uptimeNanoseconds - started
  return Double(elapsed) / Double(nanosecondsPerMillisecond)
}

private let maxClaimBundle4RequestBytes = 8 * 1_024 * 1_024
private let maxClaimBundle4DiagnosticFootprintBytes = UInt64(2 * 1_024 * 1_024 * 1_024)
private let approvedReleaseIndexSha256 =
  "9260afdb9a3a0133a679af141a310b6aacbf2e814724692ca964d2711ae49ce7"
private let sha256Bytes = 32
private let sha256HexCharacters = 64
private let hexCharactersPerByte = 2
private let hexRadix = 16
private let nanosecondsPerMillisecond: UInt64 = 1_000_000
