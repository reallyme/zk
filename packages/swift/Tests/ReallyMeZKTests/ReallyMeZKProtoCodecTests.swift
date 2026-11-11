// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing

@Suite
struct ReallyMeZKProtoCodecTests {
  @Test
  func missingOperationIsRejected() throws {
    #expect(throws: ReallyMeZKProtoCodecError.missingOperation) {
      _ = try ReallyMeZKProviderOperation(
        request: Reallyme_Zk_V1_ZkProviderOperationRequest()
      )
    }
  }

  @Test
  func personaCredentialEvidenceStageVerificationRequiresNativeProofValidation() throws {
    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.verifyPersonaCredentialEvidenceStage =
      Reallyme_Zk_V1_ZkPersonaCredentialEvidenceStageVerifyOperation()

    #expect(throws: ReallyMeZKProtoCodecError.unsupportedOperation) {
      _ = try ReallyMeZKProviderOperation(request: request)
    }
  }

  @Test
  func personaCredentialEvidenceProofOperationsRequireNativeValidation() throws {
    var issuerEnvelope = Reallyme_Zk_V1_ZkProviderOperationRequest()
    issuerEnvelope.provePersonaCredentialEvidenceIssuerEnvelope =
      Reallyme_Zk_V1_ZkPersonaCredentialEvidenceIssuerEnvelopeProveOperation()
    var claimRoot = Reallyme_Zk_V1_ZkProviderOperationRequest()
    claimRoot.provePersonaCredentialEvidenceClaimRoot =
      Reallyme_Zk_V1_ZkPersonaCredentialEvidenceClaimRootProveOperation()
    var signedValidity = Reallyme_Zk_V1_ZkProviderOperationRequest()
    signedValidity.provePersonaCredentialEvidenceSignedValidity =
      Reallyme_Zk_V1_ZkPersonaCredentialEvidenceSignedValidityProveOperation()
    var selectedClaim = Reallyme_Zk_V1_ZkProviderOperationRequest()
    selectedClaim.provePersonaCredentialEvidenceSelectedClaim =
      Reallyme_Zk_V1_ZkPersonaCredentialEvidenceSelectedClaimProveOperation()

    for request in [issuerEnvelope, claimRoot, signedValidity, selectedClaim] {
      #expect(throws: ReallyMeZKProtoCodecError.unsupportedOperation) {
        _ = try ReallyMeZKProviderOperation(request: request)
      }
    }
  }

  @Test
  func unsupportedProofSuiteIsRejected() throws {
    var operation = Reallyme_Zk_V1_ZkArtifactManifestOperation()
    operation.proofSuite = .barretenbergUltraHonkPoseidon2ZkNoIpa

    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.getArtifactManifest = operation

    #expect(throws: ReallyMeZKProtoCodecError.unsupportedProofSuite) {
      _ = try ReallyMeZKProviderOperation(request: request)
    }
  }

  @Test
  func artifactManifestRequestAdmitsCanonicalSuite() throws {
    var operation = Reallyme_Zk_V1_ZkArtifactManifestOperation()
    operation.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa

    var request = Reallyme_Zk_V1_ZkProviderOperationRequest()
    request.getArtifactManifest = operation

    let admitted = try ReallyMeZKProviderOperation(request: request)

    #expect(
      admitted == .artifactManifestRequest(proofSuite: .barretenbergUltraHonkKeccakZkNoIpa)
    )
  }

  @Test
  func emptySuccessResultIsRejected() throws {
    var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
    response.result = Reallyme_Zk_V1_ZkProviderOperationResult()

    #expect(throws: ReallyMeZKProtoCodecError.missingResult) {
      _ = try ReallyMeZKProviderResponse(response: response)
    }
  }

  @Test
  func structuredFailureMapsToAuthoredReason() throws {
    var error = Reallyme_Zk_V1_ZkError()
    error.reason = .backendUnavailable

    var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
    response.error = error

    let admitted = try ReallyMeZKProviderResponse(response: response)

    #expect(admitted == .failure(.backendUnavailable))
  }

  @Test
  func unspecifiedFailureReasonIsRejected() throws {
    var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
    response.error = Reallyme_Zk_V1_ZkError()

    #expect(throws: ReallyMeZKProtoCodecError.missingErrorReason) {
      _ = try ReallyMeZKProviderResponse(response: response)
    }
  }

  @Test
  func unrecognizedFailureReasonIsRejected() throws {
    var error = Reallyme_Zk_V1_ZkError()
    error.reason = .UNRECOGNIZED(99)

    var response = Reallyme_Zk_V1_ZkProviderOperationResponse()
    response.error = error

    #expect(throws: ReallyMeZKProtoCodecError.unrecognizedErrorReason) {
      _ = try ReallyMeZKProviderResponse(response: response)
    }
  }
}
