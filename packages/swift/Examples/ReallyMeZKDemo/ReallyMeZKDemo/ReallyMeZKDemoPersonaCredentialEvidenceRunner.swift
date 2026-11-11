// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import ReallyMeZKKit
import ReallyMeZKPlatformNative
import ReallyMeZkProtoGenerated

struct PersonaCredentialEvidenceSampleProofs: Sendable {
  let mode: ZKCommonCredentialRootPersonaMode
  let credentialHashAlgorithm: ZKCredentialHashAlgorithm
  let issuer: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  let root: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  let validity: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  let claim: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  let status: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  let generationMilliseconds: Double
}

enum ReallyMeZKDemoPersonaCredentialEvidenceRunner {
  private static let expectedManifestSha256 =
    "83d1a4fea99dc405936b99e42af80452c22df2141bef48761931dc47346e6df8"
  private static let maxManifestBytes = 2 * 1_024
  private static let maxRequestBytes = 1_024 * 1_024
  private static let joinedFieldBytes = 194 * 32

  static func prepare(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    bundle: Bundle
  ) async throws(ProofSampleError) -> PersonaCredentialEvidenceSampleProofs {
    let digests = try pinnedRequestDigests(bundle: bundle)
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
    do {
      let started = Date()
      let issuerRequest = try sampleRequest(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, part: "issuer",
        digests: digests,
        bundle: bundle
      )
      defer { issuerRequest.close() }
      let issuer = try await provider.provePersonaCredentialEvidenceStage(request: issuerRequest)
      let rootRequest = try sampleRequest(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, part: "root",
        digests: digests,
        bundle: bundle
      )
      defer { rootRequest.close() }
      let root = try await provider.provePersonaCredentialEvidenceStage(request: rootRequest)
      let validityRequest = try sampleRequest(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, part: "validity",
        digests: digests,
        bundle: bundle
      )
      defer { validityRequest.close() }
      let validity = try await provider.provePersonaCredentialEvidenceStage(
        request: validityRequest)
      let claimRequest = try sampleRequest(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, part: "claim",
        digests: digests,
        bundle: bundle
      )
      defer { claimRequest.close() }
      let claim = try await provider.provePersonaCredentialEvidenceStage(request: claimRequest)
      let statusRequest = try sampleRequest(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, part: "status",
        digests: digests,
        bundle: bundle
      )
      defer { statusRequest.close() }
      let status = try await provider.provePersonaCredentialEvidenceStage(request: statusRequest)
      guard stagesJoin(issuer, root, validity, claim, status) else {
        throw ProofSampleError.proofRejected
      }
      let elapsed = Date().timeIntervalSince(started) * 1_000
      try await context.close()
      return PersonaCredentialEvidenceSampleProofs(
        mode: mode, credentialHashAlgorithm: credentialHashAlgorithm, issuer: issuer, root: root,
        validity: validity, claim: claim, status: status,
        generationMilliseconds: elapsed
      )
    } catch {
      try? await context.close()
      if let sampleError = error as? ProofSampleError { throw sampleError }
      throw .proofRejected
    }
  }

  static func verifyCachedStages(
    _ proofs: PersonaCredentialEvidenceSampleProofs,
    bundle: Bundle
  ) async throws(ProofSampleError) -> Double {
    guard stagesJoin(proofs.issuer, proofs.root, proofs.validity, proofs.claim, proofs.status)
    else {
      throw .proofRejected
    }
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
    do {
      let started = Date()
      let issuer = try await provider.verifyPersonaCredentialEvidenceStage(proof: proofs.issuer)
      let root = try await provider.verifyPersonaCredentialEvidenceStage(proof: proofs.root)
      let validity = try await provider.verifyPersonaCredentialEvidenceStage(proof: proofs.validity)
      let claim = try await provider.verifyPersonaCredentialEvidenceStage(proof: proofs.claim)
      let status = try await provider.verifyPersonaCredentialEvidenceStage(proof: proofs.status)
      guard issuer.proofSlot == .issuerEnvelope, root.proofSlot == .claimRoot,
        validity.proofSlot == .signedValidity, claim.proofSlot == .selectedClaim,
        status.proofSlot == .currentState,
        [issuer, root, validity, claim, status].allSatisfy({
          $0.mode == claim.mode
            && $0.circuitRef.credentialHashAlgorithm
              == proofs.credentialHashAlgorithm.protoCredentialHashAlgorithm
        })
      else { throw ProofSampleError.proofRejected }
      let elapsed = Date().timeIntervalSince(started) * 1_000
      try await context.close()
      return elapsed
    } catch {
      try? await context.close()
      if let sampleError = error as? ProofSampleError { throw sampleError }
      throw .proofRejected
    }
  }

  private static func stagesJoin(
    _ issuer: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    _ root: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    _ validity: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    _ claim: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof,
    _ status: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
  ) -> Bool {
    let stages = [issuer, root, validity, claim, status]
    return claim.mode == status.mode
      && issuer.proofSlot == .issuerEnvelope
      && root.proofSlot == .claimRoot
      && validity.proofSlot == .signedValidity
      && claim.proofSlot == .selectedClaim
      && status.proofSlot == .currentState
      && stages.allSatisfy({
        $0.mode == claim.mode
          && $0.circuitRef.credentialHashAlgorithm == claim.circuitRef.credentialHashAlgorithm
          && $0.publicInputs.rawFields.count >= joinedFieldBytes
          && $0.publicInputs.rawFields.prefix(joinedFieldBytes)
            == claim.publicInputs.rawFields.prefix(joinedFieldBytes)
      })
      && validity.publicInputs.rawFields.count >= 259 * 32
      && status.publicInputs.rawFields.count >= 292 * 32
      && validity.publicInputs.rawFields[(194 * 32)..<(259 * 32)]
        == status.publicInputs.rawFields[(227 * 32)..<(292 * 32)]
  }

  private static func pinnedRequestDigests(bundle: Bundle) throws(ProofSampleError)
    -> [String: String]
  {
    guard
      let url = bundle.url(
        forResource: "sha256", withExtension: "tsv",
        subdirectory: "zk_demo/persona-credential-evidence-mobile-requests-v1"
      ), let bytes = try? Data(contentsOf: url),
      bytes.count <= maxManifestBytes,
      digestHex(bytes) == expectedManifestSha256,
      let contents = String(data: bytes, encoding: .utf8)
    else { throw .malformedFixture }
    let lines = contents.split(separator: "\n")
    guard lines.count == 21, lines.first == "filename\tsha256" else {
      throw .malformedFixture
    }
    var expected = Set<String>()
    for lane in ["sha256", "poseidon2"] {
      for mode in ["public", "private"] {
        for part in ["issuer", "root", "validity", "claim", "status"] {
          expected.insert("\(lane)-\(mode)-\(part).pb")
        }
      }
    }
    var digests = [String: String]()
    for line in lines.dropFirst() {
      let fields = line.split(separator: "\t")
      guard fields.count == 2, expected.remove(String(fields[0])) != nil,
        fields[1].count == 64, fields[1].allSatisfy(\.isHexDigit)
      else { throw .malformedFixture }
      digests[String(fields[0])] = String(fields[1])
    }
    guard expected.isEmpty else { throw .malformedFixture }
    return digests
  }

  private static func sampleRequest(
    mode: ZKCommonCredentialRootPersonaMode,
    credentialHashAlgorithm: ZKCredentialHashAlgorithm,
    part: String,
    digests: [String: String],
    bundle: Bundle
  ) throws(ProofSampleError) -> ReallyMeZKPersonaCredentialEvidenceStageProveRequest {
    let lane = credentialHashAlgorithm == .sha256 ? "sha256" : "poseidon2"
    let persona = mode == .privatePersona ? "private" : "public"
    let name = "\(lane)-\(persona)-\(part)"
    guard let digest = digests["\(name).pb"],
      let url = bundle.url(
        forResource: name, withExtension: "pb",
        subdirectory: "zk_demo/persona-credential-evidence-mobile-requests-v1"
      ), var bytes = try? Data(contentsOf: url),
      bytes.isEmpty == false, bytes.count <= maxRequestBytes
    else { throw .malformedFixture }
    defer { clear(&bytes) }
    guard digestHex(bytes) == digest else { throw .malformedFixture }
    do {
      let mode: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceMode =
        mode == .privatePersona ? .privatePersonaOneTimeV1 : .publicPersonaV1
      var reference = Reallyme_Zk_V1_ZkCircuitRef()
      reference.family = .personaCredentialEvidenceV1
      switch part {
      case "issuer": reference.stage = .evidenceIssuerEnvelope
      case "root": reference.stage = .evidenceClaimRoot
      case "validity": reference.stage = .evidenceSignedValidity
      case "status": reference.stage = .evidenceCurrentState
      case "claim":
        reference.stage =
          mode == .privatePersonaOneTimeV1
          ? .evidencePrivateClaim : .evidencePublicClaim
      default: throw ProofSampleError.malformedFixture
      }
      reference.credentialHashAlgorithm = credentialHashAlgorithm.protoCredentialHashAlgorithm
      reference.circuitRevision = 1
      return try ReallyMeZKPersonaCredentialEvidenceStageProveRequest(
        canonicalRequestBytes: bytes, mode: mode, circuitRef: reference
      )
    } catch {
      throw .malformedFixture
    }
  }

  private static func digestHex(_ bytes: Data) -> String {
    SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
  }

  private static func clear(_ bytes: inout Data) {
    _ = bytes.withUnsafeMutableBytes { buffer in
      buffer.initializeMemory(as: UInt8.self, repeating: 0)
    }
    bytes.removeAll(keepingCapacity: false)
  }
}
