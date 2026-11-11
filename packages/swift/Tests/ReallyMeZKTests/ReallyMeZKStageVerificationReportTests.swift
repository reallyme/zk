// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKStageVerificationReportTests {
  @Test
  func matchingReportVerifiesDiagnosticStage() async throws {
    let verified = try await verifyDiagnosticStage(report: .matching)

    #expect(verified)
  }

  @Test
  func emptyReportIsMalformedProviderResponse() async throws {
    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await verifyDiagnosticStage(report: .empty)
    }
  }

  @Test
  func substitutedReportFieldsAreMalformedProviderResponse() async throws {
    let reports: [RecordingStageVerificationReport] = [
      .wrongCircuitRef,
      .wrongCircuitID,
      .wrongBundleKind,
      .wrongProofSuite,
      .unspecifiedProofSuite,
    ]

    for report in reports {
      await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
        _ = try await verifyDiagnosticStage(report: report)
      }
    }
  }

  @Test
  func typedProofRejectionStillReportsUnverified() async throws {
    let verified = try await verifyDiagnosticStage(
      report: .empty,
      expectedSessionBinding: expectedSessionBinding(
        transactionDataHash: Data(repeating: 3, count: 32)
      )
    )

    #expect(verified == false)
  }

  @Test
  func productionTransportRefusalSurfacesTypedError() async throws {
    await #expect(throws: ReallyMeZKError.providerRejected(.unsupportedTransport)) {
      _ = try await verifyDiagnosticStage(report: .unsupportedTransport)
    }
  }

  @Test
  func malformedProofPreservesBooleanRejection() async throws {
    let verified = try await verifyDiagnosticStage(report: .malformedProof)

    #expect(verified == false)
  }

  private func verifyDiagnosticStage(
    report: RecordingStageVerificationReport,
    expectedSessionBinding: Reallyme_Zk_V1_ZkSessionBinding = expectedSessionBinding()
  ) async throws -> Bool {
    let transport = RecordingNativeTransport(stageVerificationReport: report)
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    var input = Reallyme_Zk_V1_ZkStageWitnessInput()
    input.credentialSubjectClaimSession = Reallyme_Zk_V1_ZkCredentialSubjectClaimSessionInput()
    let coordinate = ReallyMeZKStageCoordinate(
      credentialHashAlgorithm: .sha256,
      family: .credentialSubjectClaimV1,
      stage: .session,
      circuitRevision: 1,
      proofSuite: .barretenbergUltraHonkKeccakZkNoIpa
    )
    let witness = try await provider.generateWitness(
      request: ReallyMeZKWitnessRequest(coordinate: coordinate, input: input)
    )
    let proof = try await provider.prove(
      request: ReallyMeZKStageProveRequest(coordinate: coordinate),
      witness: witness.handle
    )
    return try await provider.verifyDiagnosticStage(
      request: ReallyMeZKStageVerifyRequest(
        coordinate: coordinate,
        expectedSessionBinding: expectedSessionBinding
      ),
      proof: proof.handle
    )
  }
}
