// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKPersonaCredentialEvidenceStageTests {
  @Test
  func personaCredentialEvidenceRequestAdmitsEveryProofStageForBothPersonaModes() throws {
    let sharedStages: [Reallyme_Zk_V1_ZkCircuitStage] = [
      .evidenceIssuerEnvelope, .evidenceClaimRoot, .evidenceSignedValidity,
      .evidenceCurrentState,
    ]
    for mode: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceMode in [
      .publicPersonaV1, .privatePersonaOneTimeV1,
    ] {
      for stage in sharedStages {
        var reference = Reallyme_Zk_V1_ZkCircuitRef()
        reference.family = .personaCredentialEvidenceV1
        reference.stage = stage
        reference.credentialHashAlgorithm = .sha256
        reference.circuitRevision = 1
        let request = try ReallyMeZKPersonaCredentialEvidenceStageProveRequest(
          canonicalRequestBytes: Data([1]), mode: mode, circuitRef: reference
        )
        request.close()
      }
    }
  }

  @Test
  func personaCredentialEvidenceRequestRejectsClaimFromAnotherPersonaMode() {
    var reference = Reallyme_Zk_V1_ZkCircuitRef()
    reference.family = .personaCredentialEvidenceV1
    reference.stage = .evidencePrivateClaim
    reference.credentialHashAlgorithm = .sha256
    reference.circuitRevision = 1
    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      _ = try ReallyMeZKPersonaCredentialEvidenceStageProveRequest(
        canonicalRequestBytes: Data([1]), mode: .publicPersonaV1,
        circuitRef: reference
      )
    }
  }

  @Test
  func everyEvidenceSourceStageHasItsExactResponseStage() throws {
    let pairs:
      [(Reallyme_Zk_V1_ZkCircuitStage, Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSlot)] =
        [
          (.evidenceIssuerEnvelope, .issuerEnvelope),
          (.evidenceClaimRoot, .claimRoot),
          (.evidenceSignedValidity, .signedValidity),
          (.evidencePublicClaim, .selectedClaim),
          (.evidencePrivateClaim, .selectedClaim),
          (.evidenceCurrentState, .currentState),
        ]
    for (circuitStage, evidenceStage) in pairs {
      #expect(try personaCredentialEvidenceStage(for: circuitStage) == evidenceStage)
    }
    #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try personaCredentialEvidenceStage(for: .session)
    }
  }

  @Test
  func personaCredentialEvidenceProveDispatchesOnceAndAdmitsMatchingStage() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let request = try personaCredentialEvidenceStageProveRequest()

    let proof = try await provider.provePersonaCredentialEvidenceStage(request: request)

    #expect(proof.mode == .publicPersonaV1)
    #expect(proof.proofSlot == .selectedClaim)
    #expect(await transport.operationCases == [.nativePersonaCredentialEvidenceStageProve])
    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.provePersonaCredentialEvidenceStage(request: request)
    }
  }

  @Test
  func personaCredentialEvidenceProveRejectsSubstitutedStage() async throws {
    let transport = RecordingNativeTransport(evidenceStageResponseMatches: false)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let request = try personaCredentialEvidenceStageProveRequest()

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await provider.provePersonaCredentialEvidenceStage(request: request)
    }
  }

  @Test
  func dispatchesExactPersonaCredentialEvidenceStageAndAdmitsMatchingNativeReport() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let package = personaCredentialEvidenceStageProof()

    let verified = try await provider.verifyPersonaCredentialEvidenceStage(proof: package)

    #expect(verified.mode == package.mode)
    #expect(verified.proofSlot == package.proofSlot)
    #expect(verified.circuitRef == package.circuitRef)
    #expect(await transport.operationCases == [.nativePersonaCredentialEvidenceStageVerify])
  }

  @Test
  func rejectsSubstitutedNativeStageReport() async throws {
    let transport = RecordingNativeTransport(evidenceStageResponseMatches: false)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await provider.verifyPersonaCredentialEvidenceStage(
        proof: personaCredentialEvidenceStageProof())
    }
  }

  @Test
  func rejectsInconsistentPackageBeforeNativeDispatch() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    var package = personaCredentialEvidenceStageProof()
    package.publicInputs.proofSlot = .currentState

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await provider.verifyPersonaCredentialEvidenceStage(proof: package)
    }
    #expect(await transport.operationCases.isEmpty)
  }

  @Test
  func protectedKeySigningAndAssemblyUseDistinctCanonicalOperations() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let evidence = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSet()
    let currentState = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof()
    let request = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceVerifierRequestV1()
    let signature = Data(repeating: 9, count: 64)

    let digest = try await provider.preparePersonaCredentialEvidencePresentationSigning(
      evidence: evidence, currentState: currentState, verifiedRequest: request, nowUnix: 10)
    #expect(digest == Data(repeating: 7, count: 32))
    let presentation = try await provider.assemblePersonaCredentialEvidencePresentation(
      evidence: evidence, currentState: currentState, verifiedRequest: request,
      nowUnix: 10, holderSignatureP256Raw: signature)
    #expect(presentation.holderSignatureP256Raw == signature)
    #expect(await transport.operationCases == [.nativePreparedSigning, .nativePreparedAssembly])
  }

  @Test
  func assemblyRejectsWrongSignatureLengthBeforeDispatch() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await provider.assemblePersonaCredentialEvidencePresentation(
        evidence: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceProofSet(),
        currentState: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof(),
        verifiedRequest: Reallyme_Zk_V1_ZkPersonaCredentialEvidenceVerifierRequestV1(),
        nowUnix: 10, holderSignatureP256Raw: Data(repeating: 1, count: 63))
    }
    #expect(await transport.operationCases.isEmpty)
  }
}

private func personaCredentialEvidenceStageProveRequest() throws
  -> ReallyMeZKPersonaCredentialEvidenceStageProveRequest
{
  let reference = personaCredentialEvidenceStageProof().circuitRef
  var witness = Reallyme_Zk_V1_ZkWitness()
  witness.circuitRef = reference
  witness.encoding = .noirWitnessStackV1
  witness.encoded = Data([1, 2, 3])
  var operation = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProveOperation()
  operation.mode = .publicPersonaV1
  operation.circuitRef = reference
  operation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  operation.witness = witness
  var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
  request.provePersonaCredentialEvidenceStage = operation
  return try ReallyMeZKPersonaCredentialEvidenceStageProveRequest(
    canonicalRequestBytes: request.serializedData(), mode: .publicPersonaV1,
    circuitRef: reference
  )
}

private func personaCredentialEvidenceStageProof()
  -> Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof
{
  var reference = Reallyme_Zk_V1_ZkCircuitRef()
  reference.family = .personaCredentialEvidenceV1
  reference.stage = .evidencePublicClaim
  reference.credentialHashAlgorithm = .sha256
  reference.circuitRevision = 1

  var inputs = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceRawPublicInputs()
  inputs.mode = .publicPersonaV1
  inputs.proofSlot = .selectedClaim
  inputs.circuitRef = reference
  inputs.rawFields = Data(repeating: 1, count: 32)

  var digest = Reallyme_Zk_V1_ZkArtifactSetIdentity()
  digest.value = Data(repeating: 2, count: 32)

  var package = Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageProof()
  package.mode = .publicPersonaV1
  package.proofSlot = .selectedClaim
  package.circuitRef = reference
  package.proof = Data(repeating: 3, count: 96)
  package.publicInputs = inputs
  package.artifactSetIdentitySha256 = digest
  package.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  return package
}
