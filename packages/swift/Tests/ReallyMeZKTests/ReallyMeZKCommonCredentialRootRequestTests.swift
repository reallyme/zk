// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKCommonCredentialRootRequestTests {
  @Test
  func admitsCanonicalNineSlotShapeWithoutRenderingPrivatePolicy() throws {
    let (presentation, policy) = makeCommonCredentialRootInput()
    let request = try ReallyMeZKCommonCredentialRootVerifyRequest(
      mode: .privatePersona,
      presentation: presentation,
      policy: policy
    )

    #expect(request.presentation.proofs.count == 9)
    #expect(request.description.contains("<redacted>"))
    #expect(request.description.contains("claimValue") == false)
  }

  @Test
  func rejectsReorderedProofSlots() {
    var (presentation, policy) = makeCommonCredentialRootInput()
    presentation.proofs.swapAt(2, 3)

    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: .privatePersona,
        presentation: presentation,
        policy: policy
      )
    }
  }

  @Test
  func rejectsVerifierBindingMismatch() {
    let (presentation, originalPolicy) = makeCommonCredentialRootInput()
    var policy = originalPolicy
    policy.challenge = Data(repeating: 9, count: 32)

    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: .privatePersona,
        presentation: presentation,
        policy: policy
      )
    }
  }

  @Test
  func rejectsOversizedProofBeforeNativeDispatch() {
    var (presentation, policy) = makeCommonCredentialRootInput()
    presentation.proofs[0].proof = Data(repeating: 1, count: 256 * 1_024 + 1)

    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: .privatePersona,
        presentation: presentation,
        policy: policy
      )
    }
  }

  @Test
  func nativeProviderAdmitsOnlyNineProofVerificationResult() async throws {
    let (presentation, policy) = makeCommonCredentialRootInput()
    let request = try ReallyMeZKCommonCredentialRootVerifyRequest(
      mode: .privatePersona,
      presentation: presentation,
      policy: policy
    )
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    let result = try await provider.verifyCommonCredentialRoot(request: request)

    #expect(result.mode == .privatePersona)
    #expect(result.verifiedProofCount == 9)
    #expect(await transport.operationCases == [.nativeCommonCredentialRootVerify])
  }

  @Test
  func nativeProviderRejectsIncompleteVerificationResult() async throws {
    let (presentation, policy) = makeCommonCredentialRootInput()
    let request = try ReallyMeZKCommonCredentialRootVerifyRequest(
      mode: .privatePersona,
      presentation: presentation,
      policy: policy
    )
    let transport = RecordingNativeTransport(commonCredentialRootVerifiedProofCount: 8)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await provider.verifyCommonCredentialRoot(request: request)
    }
  }

  @Test
  func rejectsMissingIssuerStatusPolicyBeforeNativeDispatch() {
    let (presentation, originalPolicy) = makeCommonCredentialRootInput()
    var policy = originalPolicy
    policy.issuerStatus.removeLast()

    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: .privatePersona,
        presentation: presentation,
        policy: policy
      )
    }
  }

  @Test
  func rejectsMalformedIssuerStatusPolicyBeforeNativeDispatch() {
    let (presentation, originalPolicy) = makeCommonCredentialRootInput()
    var policy = originalPolicy
    policy.issuerStatus[0].listID = Data()

    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try ReallyMeZKCommonCredentialRootVerifyRequest(
        mode: .privatePersona,
        presentation: presentation,
        policy: policy
      )
    }
  }

  @Test
  func typedStageRequestRejectsWrongCircuitAndInputBeforeDispatch() {
    let valid = commonCredentialRootStageOperation()
    var wrongStage = valid
    wrongStage.circuitRef.stage = .lineage
    var wrongInput = valid
    wrongInput.input = .rootStatus(Reallyme_Zk_V1_ZkCommonCredentialRootStatusInput())

    for operation in [wrongStage, wrongInput] {
      #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
        _ = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: operation)
      }
    }
  }

  @Test
  func typedStageRequestRejectsMalformedBindingAndRedactsInput() throws {
    let valid = commonCredentialRootStageOperation()
    let accepted = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: valid)
    #expect(accepted.description.contains("<redacted>"))
    var malformed = valid
    malformed.expectedBinding.nonceHash = Data()
    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      _ = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: malformed)
    }
  }

  @Test
  func issuerCredentialStatusStageRequiresMatchingInput() throws {
    var operation = commonCredentialRootStageOperation()
    operation.slot = .issuerCredentialStatus0
    operation.circuitRef.stage = .issuerCredentialStatus
    operation.input = .issuerCredentialStatus(
      Reallyme_Zk_V1_ZkCommonCredentialRootIssuerCredentialStatusInput())
    _ = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: operation)

    operation.input = .rootAttestation(Reallyme_Zk_V1_ZkCommonCredentialRootAttestationInput())
    #expect(throws: ReallyMeZKError.providerRejected(.malformedWitness)) {
      _ = try ReallyMeZKCommonCredentialRootStageProveRequest(operation: operation)
    }
  }

  @Test
  func objectBuiltStageDoesNotReachNativeTransport() async throws {
    let request = try ReallyMeZKCommonCredentialRootStageProveRequest(
      operation: commonCredentialRootStageOperation()
    )
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.proveCommonCredentialRootStage(request: request)
    }
    #expect(await transport.operationCases.isEmpty)
  }

  @Test
  func canonicalStageBytesReachNativeTransportUnchangedAndOnlyOnce() async throws {
    let fixture = try canonicalStageFixture()
    let request = try ReallyMeZKCommonCredentialRootStageProveRequest(
      canonicalRequestBytes: fixture)
    let transport = CanonicalStageRecordingTransport(expectedRequest: fixture)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      _ = try await provider.proveCommonCredentialRootStage(request: request)
    }
    #expect(await transport.receivedExactRequest)
    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.proveCommonCredentialRootStage(request: request)
    }
    #expect(await transport.dispatchCount == 1)
  }

  @Test
  func closedCanonicalStageCannotDispatch() async throws {
    let fixture = try canonicalStageFixture()
    let request = try ReallyMeZKCommonCredentialRootStageProveRequest(
      canonicalRequestBytes: fixture)
    request.close()
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.proveCommonCredentialRootStage(request: request)
    }
    #expect(await transport.operationCases.isEmpty)
  }

  @Test
  func objectBuiltNineStagePresentationDoesNotReachNativeTransport() async throws {
    let request = try ReallyMeZKCommonCredentialRootPresentationProveRequest(
      operation: commonCredentialRootPresentationOperation()
    )
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.proveCommonCredentialRootPresentation(request: request)
    }
    #expect(await transport.operationCases.isEmpty)
  }

  @Test
  func encodedNineStagePresentationDispatchesOriginalBytesOnlyOnce() async throws {
    var operationRequest = Reallyme_Zk_V1_ZkProviderOperationRequest()
    operationRequest.proveCommonCredentialRootPresentation =
      try commonCredentialRootPresentationOperation()
    let bytes = try operationRequest.serializedData()
    let request = try ReallyMeZKCommonCredentialRootPresentationProveRequest(
      canonicalRequestBytes: bytes)
    let transport = CanonicalStageRecordingTransport(expectedRequest: bytes)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)

    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      _ = try await provider.proveCommonCredentialRootPresentation(request: request)
    }
    #expect(await transport.receivedExactRequest)
    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await provider.proveCommonCredentialRootPresentation(request: request)
    }
    #expect(await transport.dispatchCount == 1)
  }

  @Test
  func preparedVerificationRequestReconstructionPreservesItsFields() throws {
    let bytes = try canonicalPreparedFixture()
    let parsed = try Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: bytes)
    guard case .verifyCommonCredentialRoot(let verify)? = parsed.operation else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    var reconstructed = Reallyme_Zk_V1_ZkCommonCredentialRootVerifyOperation()
    reconstructed.presentation = verify.presentation
    reconstructed.joinPolicy = verify.joinPolicy
    reconstructed.expectedProofSuite = .barretenbergUltraHonkKeccakZkNoIpa
    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.verifyCommonCredentialRoot = reconstructed
    // Protobuf field order differs across runtimes. Original-byte forwarding
    // is tested at native dispatch; reconstruction must preserve the fields.
    #expect(
      try Reallyme_Zk_V1_ZkProviderOperationRequest(
        serializedBytes: request.serializedData()
      ) == parsed)
  }
}

private func canonicalPreparedFixture() throws -> Data {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  return try Data(
    contentsOf: repositoryRoot.appendingPathComponent(
      "vectors/common-credential-root-mobile-fixtures-v1/common-credential-root-sha256-private.pb"
    ))
}

private func commonCredentialRootPresentationOperation() throws
  -> Reallyme_Zk_V1_ZkCommonCredentialRootPresentationProveOperation
{
  let stages = try (0..<9).map {
    index -> Reallyme_Zk_V1_ZkCommonCredentialRootStageProveOperation in
    let bytes = try canonicalStageFixture(slotIndex: index)
    let parsed = try Reallyme_Zk_V1_ZkProviderOperationRequest(serializedBytes: bytes)
    guard case .proveCommonCredentialRootStage(let stage)? = parsed.operation else {
      throw ReallyMeZKError.providerRejected(.malformedWitness)
    }
    return stage
  }
  var operation = Reallyme_Zk_V1_ZkCommonCredentialRootPresentationProveOperation()
  operation.personaMode = .privatePersonaV1
  operation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  operation.expectedBinding = stages[0].expectedBinding
  operation.rootAttestation = stages[0]
  operation.rootStatus = stages[1]
  operation.lineage0 = stages[2]
  operation.lineage1 = stages[3]
  operation.selectedClaim0 = stages[4]
  operation.selectedClaim1 = stages[5]
  operation.session = stages[6]
  operation.issuerCredentialStatus0 = stages[7]
  operation.issuerCredentialStatus1 = stages[8]
  return operation
}

private actor CanonicalStageRecordingTransport: ReallyMeZKNativeTransport {
  private let expectedRequest: Data
  private(set) var receivedExactRequest = false
  private(set) var dispatchCount = 0

  init(expectedRequest: Data) {
    self.expectedRequest = expectedRequest
  }

  func dispatch(
    contextHandle: UInt64,
    request: Data
  ) async throws(ReallyMeZKError) -> Data {
    dispatchCount += 1
    receivedExactRequest = contextHandle == 7 && request == expectedRequest
    throw ReallyMeZKError.providerUnavailable
  }
}

private func canonicalStageFixture(slotIndex: Int = 0) throws -> Data {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  return try Data(
    contentsOf: repositoryRoot.appendingPathComponent(
      "vectors/common-credential-root-stage-requests-v1/sha256-private-\(slotIndex).pb"
    ))
}

private func commonCredentialRootStageOperation()
  -> Reallyme_Zk_V1_ZkCommonCredentialRootStageProveOperation
{
  let bindingBytes = Data(repeating: 1, count: 32)
  var operation = Reallyme_Zk_V1_ZkCommonCredentialRootStageProveOperation()
  operation.personaMode = .privatePersonaV1
  operation.slot = .rootAttestation
  operation.circuitRef.credentialHashAlgorithm = .sha256
  operation.circuitRef.family = .commonCredentialRootV1
  operation.circuitRef.stage = .rootAttestation
  operation.circuitRef.circuitRevision = 1
  operation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  operation.expectedBinding.nonceHash = bindingBytes
  operation.expectedBinding.audienceHash = bindingBytes
  operation.expectedBinding.transactionDataHash = bindingBytes
  operation.input = .rootAttestation(Reallyme_Zk_V1_ZkCommonCredentialRootAttestationInput())
  return operation
}

private func makeCommonCredentialRootInput() -> (
  Reallyme_Zk_V1_ZkCommonCredentialRootPresentation,
  Reallyme_Zk_V1_ZkCommonCredentialRootJoinPolicy
) {
  let digest = Data(repeating: 1, count: 32)
  let slots = commonCredentialRootProofSlots
  var presentation = Reallyme_Zk_V1_ZkCommonCredentialRootPresentation()
  presentation.personaMode = .privatePersonaV1
  presentation.credentialHashAlgorithm = .sha256
  presentation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  presentation.sessionBinding.nonceHash = digest
  presentation.sessionBinding.audienceHash = digest
  presentation.sessionBinding.transactionDataHash = digest
  presentation.proofs = slots.map { slot in
    var circuitRef = Reallyme_Zk_V1_ZkCircuitRef()
    circuitRef.credentialHashAlgorithm = .sha256
    circuitRef.family = .commonCredentialRootV1
    circuitRef.stage = .rootAttestation
    circuitRef.circuitRevision = 1

    var inputs = Reallyme_Zk_V1_ZkCommonCredentialRootRawPublicInputs()
    inputs.personaMode = .privatePersonaV1
    inputs.slot = slot
    inputs.circuitRef = circuitRef
    inputs.rawFields = Data(repeating: 0, count: 32)

    var proof = Reallyme_Zk_V1_ZkCommonCredentialRootRawProofPackage()
    proof.personaMode = .privatePersonaV1
    proof.slot = slot
    proof.circuitRef = circuitRef
    proof.publicInputs = inputs
    proof.proof = Data([1])
    proof.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
    proof.artifactSetIdentitySha256.value = digest
    return proof
  }

  var signer = Reallyme_Zk_V1_ZkP256PublicKey()
  signer.x = digest
  signer.y = digest
  var policy = Reallyme_Zk_V1_ZkCommonCredentialRootJoinPolicy()
  policy.challenge = digest
  policy.audienceHash = digest
  policy.transactionDataHash = digest
  policy.requestTimeUnix = 1
  policy.attestationSigner = signer
  policy.assurancePolicyID = digest
  policy.statusRoot = digest
  policy.claims = (0..<2).map { _ in
    var claim = Reallyme_Zk_V1_ZkCommonCredentialRootClaimExpectation()
    claim.issuer = signer
    claim.claimNameHash = digest
    claim.claimValue = Data([1])
    claim.claimValueLength = 1
    return claim
  }
  policy.issuerStatus = (0..<2).map { _ in
    var status = Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation()
    status.root = digest
    status.length = 1
    status.listID = digest
    status.urlHash = digest
    status.purpose = .revocation
    return status
  }
  return (presentation, policy)
}
