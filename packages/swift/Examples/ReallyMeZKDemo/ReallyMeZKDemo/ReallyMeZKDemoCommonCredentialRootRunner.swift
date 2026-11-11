// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import ReallyMeZKKit
import ReallyMeZKPlatformNative
import ReallyMeZkProtoGenerated

struct CommonCredentialRootSampleResult {
  let verifiedProofCount: Int
  let verificationMilliseconds: Double
  let generationMilliseconds: Double
}

struct CommonCredentialRootSessionNegativeResult {
  let acceptedVerifiedProofCount: Int
  let rejectedWrongSession: Bool
  let generationMilliseconds: Double
  let acceptedVerificationMilliseconds: Double
  let rejectedVerificationMilliseconds: Double
}

enum ReallyMeZKDemoCommonCredentialRootRunner {
  private static let maxPreparedRequestBytes = 256 * 1_024
  private static let maxStageRequestBytes = 16 * 1_024
  private static let expectedStageManifestSha256 =
    "46939ce0bdac43a132b45707f22b8f3c838ed8325714e16a01a769daebc39afa"

  static func verifyBundledSample(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    bundle: Bundle
  ) async throws(ProofSampleError) -> CommonCredentialRootSampleResult {
    let request = try preparedRequest(
      mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, bundle: bundle)
    let context = try DemoNativeContext(bundle: bundle)
    let provider: ReallyMeZKNativeProvider<ReallyMeZKPlatformTransport>
    do {
      provider = try ReallyMeZKNativeProvider(
        contextHandle: context.contextHandle,
        transport: context.transport
      )
    } catch {
      try? await context.close()
      throw .providerUnavailable
    }
    let started = Date()
    let verified: ReallyMeZKVerifiedCommonCredentialRoot
    do {
      verified = try await provider.verifyCommonCredentialRoot(request: request)
    } catch {
      try? await context.close()
      throw .proofRejected
    }
    let milliseconds = Date().timeIntervalSince(started) * 1_000
    do {
      try await context.close()
    } catch {
      throw .internalFailure
    }
    return CommonCredentialRootSampleResult(
      verifiedProofCount: verified.verifiedProofCount,
      verificationMilliseconds: milliseconds,
      generationMilliseconds: 0
    )
  }

  static func generateSample(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    bundle: Bundle,
    progress: @escaping @Sendable (Int) -> Void
  ) async throws(ProofSampleError) -> CommonCredentialRootSampleResult {
    let prepared = try preparedRequest(
      mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, bundle: bundle)
    let stageDigests = try pinnedStageDigests(bundle: bundle)
    let context = try DemoNativeContext(bundle: bundle)
    let provider: ReallyMeZKNativeProvider<ReallyMeZKPlatformTransport>
    do {
      provider = try ReallyMeZKNativeProvider(
        contextHandle: context.contextHandle,
        transport: context.transport
      )
    } catch {
      try? await context.close()
      throw .providerUnavailable
    }
    let result: CommonCredentialRootSampleResult
    do {
      var presentation = prepared.presentation
      presentation.proofs.removeAll()
      let started = Date()
      for slotIndex in 0..<9 {
        let stage = try stageRequest(
          mode: mode,
          credentialHashAlgorithm: credentialHashAlgorithm,
          slotIndex: slotIndex,
          digests: stageDigests,
          bundle: bundle
        )
        defer { stage.close() }
        guard stage.expectedBinding == prepared.presentation.sessionBinding else {
          throw ProofSampleError.proofRejected
        }
        let proof = try await provider.proveCommonCredentialRootStage(request: stage)
        guard prepared.presentation.proofs.indices.contains(slotIndex),
          proof.package.publicInputs.rawFields
            == prepared.presentation.proofs[slotIndex].publicInputs.rawFields
        else {
          throw ProofSampleError.malformedFixture
        }
        presentation.proofs.append(proof.package)
        progress(slotIndex + 1)
      }
      let generationMilliseconds = Date().timeIntervalSince(started) * 1_000
      let request = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: mode,
        presentation: presentation,
        policy: prepared.policy
      )
      let verifyStarted = Date()
      let verified = try await provider.verifyCommonCredentialRoot(request: request)
      result = CommonCredentialRootSampleResult(
        verifiedProofCount: verified.verifiedProofCount,
        verificationMilliseconds: Date().timeIntervalSince(verifyStarted) * 1_000,
        generationMilliseconds: generationMilliseconds
      )
    } catch {
      try? await context.close()
      if let sampleError = error as? ProofSampleError { throw sampleError }
      throw .proofRejected
    }
    do {
      try await context.close()
    } catch {
      throw .internalFailure
    }
    return result
  }

  static func generateSampleAndRejectAlteredSession(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    bundle: Bundle,
    progress: @escaping @Sendable (Int) -> Void
  ) async throws(ProofSampleError) -> CommonCredentialRootSessionNegativeResult {
    let prepared = try preparedRequest(
      mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, bundle: bundle)
    let stageDigests = try pinnedStageDigests(bundle: bundle)
    let context = try DemoNativeContext(bundle: bundle)
    let provider: ReallyMeZKNativeProvider<ReallyMeZKPlatformTransport>
    do {
      provider = try ReallyMeZKNativeProvider(
        contextHandle: context.contextHandle,
        transport: context.transport
      )
    } catch {
      try? await context.close()
      throw .providerUnavailable
    }

    let result: CommonCredentialRootSessionNegativeResult
    do {
      var presentation = prepared.presentation
      presentation.proofs.removeAll()
      let started = Date()
      for slotIndex in 0..<9 {
        let stage = try stageRequest(
          mode: mode,
          credentialHashAlgorithm: credentialHashAlgorithm,
          slotIndex: slotIndex,
          digests: stageDigests,
          bundle: bundle
        )
        defer { stage.close() }
        guard stage.expectedBinding == prepared.presentation.sessionBinding else {
          throw ProofSampleError.proofRejected
        }
        let proof = try await provider.proveCommonCredentialRootStage(request: stage)
        guard prepared.presentation.proofs.indices.contains(slotIndex),
          proof.package.publicInputs.rawFields
            == prepared.presentation.proofs[slotIndex].publicInputs.rawFields
        else {
          throw ProofSampleError.malformedFixture
        }
        presentation.proofs.append(proof.package)
        progress(slotIndex + 1)
      }
      let generationMilliseconds = Date().timeIntervalSince(started) * 1_000

      let acceptedRequest = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: mode,
        presentation: presentation,
        policy: prepared.policy
      )
      let acceptedStarted = Date()
      let accepted = try await provider.verifyCommonCredentialRoot(request: acceptedRequest)
      let acceptedVerificationMilliseconds = Date().timeIntervalSince(acceptedStarted) * 1_000

      let rejectedStarted = Date()
      let rejectedWrongSession = try await rejectsAlteredSession(
        mode: mode,
        presentation: presentation,
        policy: prepared.policy,
        provider: provider
      )
      result = CommonCredentialRootSessionNegativeResult(
        acceptedVerifiedProofCount: accepted.verifiedProofCount,
        rejectedWrongSession: rejectedWrongSession,
        generationMilliseconds: generationMilliseconds,
        acceptedVerificationMilliseconds: acceptedVerificationMilliseconds,
        rejectedVerificationMilliseconds: Date().timeIntervalSince(rejectedStarted) * 1_000
      )
    } catch {
      try? await context.close()
      if let sampleError = error as? ProofSampleError { throw sampleError }
      throw .proofRejected
    }
    do {
      try await context.close()
    } catch {
      throw .internalFailure
    }
    return result
  }

  private static func preparedRequest(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    bundle: Bundle
  ) throws(ProofSampleError) -> ReallyMeZKCommonCredentialRootVerifyRequest {
    let modeName =
      switch mode {
      case .privatePersona: "private"
      case .publicPersona: "public"
      }
    let lane: String
    if credentialHashAlgorithm == .sha256 {
      lane = "sha256"
    } else if credentialHashAlgorithm == .poseidon2 {
      lane = "poseidon2"
    } else {
      throw .invalidOptions
    }
    let name = "common-credential-root-\(lane)-\(modeName)"
    let expectedDigest: String
    switch name {
    case "common-credential-root-sha256-private":
      expectedDigest = "8eff0e80317c7eda620a35f5beb4b63b7dd5162a2cf2ab8fad3be4d74e18c8d4"
    case "common-credential-root-sha256-public":
      expectedDigest = "77b4a74aedadfb0df3c8c4a8b3fb2d8253b32d29f3b298d938c5a342f426931a"
    case "common-credential-root-poseidon2-private":
      expectedDigest = "0ca57395f3a6d5124433ba932e93bed467dc56be2764b3c5a6b2c2513d547b2a"
    case "common-credential-root-poseidon2-public":
      expectedDigest = "4bdd5f4fdc2cbcd71b54ecbc543ca7b3d84efe729aa444b01fcf018376f99a2c"
    default:
      throw .invalidOptions
    }
    guard let url = bundle.url(forResource: name, withExtension: "pb", subdirectory: "zk_demo"),
      let bytes = try? Data(contentsOf: url),
      bytes.isEmpty == false,
      bytes.count <= maxPreparedRequestBytes,
      SHA256.hash(data: bytes).map({ String(format: "%02x", $0) }).joined() == expectedDigest,
      let operation = try? Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: bytes)
    else {
      throw .malformedFixture
    }
    guard case .verifyCommonCredentialRoot(let verify)? = operation.operation else {
      throw .malformedFixture
    }
    do {
      return try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: mode,
        presentation: verify.presentation,
        policy: verify.joinPolicy
      )
    } catch {
      throw .malformedFixture
    }
  }

  private static func pinnedStageDigests(
    bundle: Bundle
  ) throws(ProofSampleError) -> [String: String] {
    guard
      let url = bundle.url(
        forResource: "sha256",
        withExtension: "tsv",
        subdirectory: "zk_demo/common-credential-root-stage-requests-v1"
      ),
      let bytes = try? Data(contentsOf: url),
      bytes.count <= 4 * 1_024,
      hexSha256(bytes) == expectedStageManifestSha256,
      let contents = String(data: bytes, encoding: .utf8)
    else { throw .malformedFixture }
    let lines = contents.split(separator: "\n")
    guard lines.count == 37, lines.first == "filename\tsha256" else { throw .malformedFixture }
    var expectedNames = Set<String>()
    for lane in ["sha256", "poseidon2"] {
      for mode in ["private", "public"] {
        for slot in 0..<9 { expectedNames.insert("\(lane)-\(mode)-\(slot).pb") }
      }
    }
    var digests = [String: String]()
    for line in lines.dropFirst() {
      let fields = line.split(separator: "\t")
      guard fields.count == 2,
        expectedNames.remove(String(fields[0])) != nil,
        fields[1].count == 64,
        fields[1].allSatisfy({ $0.isASCII && $0.isHexDigit })
      else { throw .malformedFixture }
      digests[String(fields[0])] = String(fields[1])
    }
    guard expectedNames.isEmpty else { throw .malformedFixture }
    return digests
  }

  private static func stageRequest(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    slotIndex: Int,
    digests: [String: String],
    bundle: Bundle
  ) throws(ProofSampleError) -> ReallyMeZKCommonCredentialRootStageProveRequest {
    guard (0..<9).contains(slotIndex) else { throw .invalidOptions }
    let lane = credentialHashAlgorithm == .sha256 ? "sha256" : "poseidon2"
    let persona = mode == .privatePersona ? "private" : "public"
    let expectedPersonaMode: Reallyme_Zk_V1_ZkCommonCredentialRootPersonaMode =
      mode == .privatePersona ? .privatePersonaV1 : .publicPersonaV1
    let name = "\(lane)-\(persona)-\(slotIndex)"
    guard let digest = digests["\(name).pb"],
      let url = bundle.url(
        forResource: name, withExtension: "pb",
        subdirectory: "zk_demo/common-credential-root-stage-requests-v1"
      ), var bytes = try? Data(contentsOf: url),
      bytes.isEmpty == false, bytes.count <= maxStageRequestBytes
    else { throw .malformedFixture }
    defer { zeroizeStageBytes(&bytes) }
    guard hexSha256(bytes) == digest else { throw .malformedFixture }
    do {
      let request = try ReallyMeZKCommonCredentialRootStageProveRequest(
        canonicalRequestBytes: bytes)
      guard request.personaMode == expectedPersonaMode,
        request.slot.rawValue == slotIndex + 1,
        request.circuitRef.credentialHashAlgorithm
          == credentialHashAlgorithm.protoCredentialHashAlgorithm
      else {
        request.close()
        throw ProofSampleError.malformedFixture
      }
      return request
    } catch {
      throw .malformedFixture
    }
  }

  private static func hexSha256(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private static func rejectsAlteredSession(
    mode: ZKCommonCredentialRootPersonaMode,
    presentation: Reallyme_Zk_V1_ZkCommonCredentialRootPresentation,
    policy: Reallyme_Zk_V1_ZkCommonCredentialRootJoinPolicy,
    provider: ReallyMeZKNativeProvider<ReallyMeZKPlatformTransport>
  ) async throws(ProofSampleError) -> Bool {
    var alteredPresentation = presentation
    var alteredPolicy = policy
    alteredPresentation.sessionBinding.nonceHash =
      alteredDigest(alteredPresentation.sessionBinding.nonceHash)
    alteredPolicy.challenge = alteredPresentation.sessionBinding.nonceHash
    let request: ReallyMeZKCommonCredentialRootVerifyRequest
    do {
      request = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: mode,
        presentation: alteredPresentation,
        policy: alteredPolicy
      )
    } catch {
      throw .malformedFixture
    }
    do {
      _ = try await provider.verifyCommonCredentialRoot(request: request)
      return false
    } catch ReallyMeZKError.providerRejected(.proofRejected) {
      return true
    } catch {
      throw .proofRejected
    }
  }

  private static func alteredDigest(_ digest: Data) -> Data {
    var altered = digest
    if altered.isEmpty {
      return Data(repeating: 1, count: 32)
    }
    altered[altered.startIndex] ^= 0x01
    return altered
  }

  private static func zeroizeStageBytes(_ data: inout Data) {
    _ = data.withUnsafeMutableBytes { bytes in
      bytes.initializeMemory(as: UInt8.self, repeating: 0)
    }
    data.removeAll(keepingCapacity: false)
  }
}
