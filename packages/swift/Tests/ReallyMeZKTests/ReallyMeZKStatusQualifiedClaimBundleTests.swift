// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKProtoCodec
import ReallyMeZkProtoGenerated
import Testing

@testable import ReallyMeZKKit

@Suite
struct ReallyMeZKStatusQualifiedClaimBundleTests {
  @Test
  func nativeProviderVerifiesStatusQualifiedBundle() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = boundSessionBinding()
    let bundle = try await statusQualifiedBundle(provider: provider, binding: binding)
    let status = currentIssuerStatus(purpose: .suspension)
    let verified: ReallyMeZKStatusQualifiedClaimBundleVerification =
      try await provider.verifyStatusQualifiedClaimBundle(
        request: try verifyRequest(binding: binding, currentIssuerStatus: status),
        statusQualifiedClaimProofBundle: bundle
      )

    #expect(verified.bundleKind == .credentialSubjectClaim)
    #expect(verified.verifiedProofCount == 5)
    #expect(verified.statusPurpose == .suspension)
    #expect(verified.issuer == trustedIssuer())
    #expect(verified.persona == nil)
    #expect(verified.claimValueLength == 3)
    #expect(verified.presentationExpiryUnix == 400)
    #expect(verified.sessionBinding == binding)
    verified.claimNameHash.withUnsafeBytes { bytes in
      #expect(Array(bytes) == Array(repeating: 11, count: 32))
    }
    verified.claimValue.withUnsafeBytes { bytes in
      #expect(Array(bytes.prefix(3)) == [1, 2, 3])
    }
    verified.credentialBinding.withUnsafeBytes { bytes in
      #expect(Array(bytes) == Array(repeating: 13, count: 32))
    }
    verified.sessionLinkCommitment.withUnsafeBytes { bytes in
      #expect(Array(bytes) == Array(repeating: 12, count: 32))
    }
    #expect(await transport.operationCases.last == .nativeStatusQualifiedBundleVerify)
    let operations = await transport.statusQualifiedVerifyOperations
    #expect(operations.count == 1)
    #expect(
      operations.first?.statusQualifiedClaimProofBundle == bundle.statusQualifiedClaimProofBundle
    )
    #expect(operations.first?.expectedBinding == binding)
    #expect(operations.first?.expectedIssuer == trustedIssuer())
    #expect(operations.first?.trustedIssuers == [trustedIssuer()])
    #expect(operations.first?.verificationTimeUnix == 100)
    #expect(operations.first?.expectedProofSuite == .barretenbergUltraHonkKeccakZkNoIpa)
    #expect(operations.first?.currentIssuerStatus == status)
  }

  @Test
  func verifyRequestAcceptsBoundaryStatusListLengths() throws {
    for length: UInt64 in [1, 1_000_000] {
      let request = try verifyRequest(currentIssuerStatus: currentIssuerStatus(length: length))
      #expect(request.currentIssuerStatus.length == length)
    }
  }

  @Test
  func verifyRequestRejectsEmptyTrustedIssuers() throws {
    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try ReallyMeZKStatusQualifiedClaimBundleVerifyRequest(
        expectedSessionBinding: expectedSessionBinding(),
        expectedIssuer: trustedIssuer(),
        trustedIssuers: [],
        verificationTimeUnix: 100,
        currentIssuerStatus: currentIssuerStatus()
      )
    }
  }

  @Test
  func verifyRequestRejectsExpectedIssuerOutsideTrustPolicy() throws {
    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try verifyRequest(expectedIssuer: wrongIssuer())
    }
  }

  @Test
  func anotherTrustedIssuerCannotUseTheSelectedStatusFeed() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = boundSessionBinding()
    let bundle = try await statusQualifiedBundle(provider: provider, binding: binding)
    let request = try verifyRequest(
      binding: binding,
      trustedIssuers: [trustedIssuer(), wrongIssuer()],
      expectedIssuer: wrongIssuer()
    )
    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try await provider.verifyStatusQualifiedClaimBundle(
        request: request, statusQualifiedClaimProofBundle: bundle
      )
    }
  }

  @Test
  func verifyRequestRejectsZeroVerifierTime() throws {
    #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      try ReallyMeZKStatusQualifiedClaimBundleVerifyRequest(
        expectedSessionBinding: expectedSessionBinding(),
        expectedIssuer: trustedIssuer(),
        trustedIssuers: [trustedIssuer()],
        verificationTimeUnix: 0,
        currentIssuerStatus: currentIssuerStatus()
      )
    }
  }

  @Test
  func verifyRequestRejectsMalformedStatusDigests() throws {
    let malformedDigests = [
      Data(),
      Data(repeating: 21, count: 31),
      Data(repeating: 21, count: 33),
      Data(repeating: 0, count: 32),
    ]
    for digest in malformedDigests {
      let statuses = [
        currentIssuerStatus(root: digest),
        currentIssuerStatus(listID: digest),
        currentIssuerStatus(urlHash: digest),
      ]
      for status in statuses {
        #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
          try verifyRequest(currentIssuerStatus: status)
        }
      }
    }
  }

  @Test
  func verifyRequestRejectsOutOfRangeStatusListLength() throws {
    for length: UInt64 in [0, 1_000_001, UInt64.max] {
      #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
        try verifyRequest(currentIssuerStatus: currentIssuerStatus(length: length))
      }
    }
  }

  @Test
  func verifyRequestRejectsUnspecifiedOrUnrecognizedStatusPurpose() throws {
    let purposes: [Reallyme_Zk_V1_ZkIssuerStatusPurpose] = [.unspecified, .UNRECOGNIZED(3)]
    for purpose in purposes {
      #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
        try verifyRequest(currentIssuerStatus: currentIssuerStatus(purpose: purpose))
      }
    }
  }

  @Test
  func fourProofResultIsMalformedProviderResponse() async throws {
    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await verify(report: .fourProofResult)
    }
  }

  @Test
  func substitutedReportFieldsAreMalformedProviderResponse() async throws {
    let reports: [RecordingStatusQualifiedVerificationReport] = [
      .fourVerifiedProofs,
      .wrongStatusPurpose,
      .unspecifiedStatusPurpose,
      .wrongBundleKind,
      .wrongProofSuite,
      .missingStatement,
    ]

    for report in reports {
      await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
        _ = try await verify(report: report)
      }
    }
  }

  @Test
  func malformedStatementFieldIsMalformedProviderResponse() async throws {
    let transport = RecordingNativeTransport(
      bundleCredentialBinding: Data(repeating: 13, count: 31)
    )

    await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
      _ = try await verify(transport: transport)
    }
  }

  @Test
  func untrustedStatementIssuerIsRejected() async throws {
    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try await verify(report: .untrustedStatementIssuer)
    }
  }

  @Test
  func typedProviderErrorPropagatesAsProofRejection() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = boundSessionBinding()
    let bundle = try await statusQualifiedBundle(provider: provider, binding: binding)
    let fourProofBundle = ReallyMeZKNativeClaimProofBundleHandle(
      claimProofBundle: bundle.statusQualifiedClaimProofBundle.claimProofBundle
    )

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try await provider.verifyStatusQualifiedClaimBundle(
        request: try verifyRequest(binding: binding, trustedIssuers: [wrongIssuer()]),
        statusQualifiedClaimProofBundle: bundle
      )
    }
    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try await provider.verifyPresentationBoundClaimBundle(
        request: try ReallyMeZKPresentationBoundClaimBundleVerifyRequest(
          expectedSessionBinding: binding,
          trustedIssuers: [wrongIssuer()],
          verificationTimeUnix: 100
        ),
        claimProofBundle: fourProofBundle
      )
    }
  }

  @Test
  func sessionBindingMismatchIsRejected() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let bundle = try await statusQualifiedBundle(provider: provider, binding: boundSessionBinding())
    let otherBinding = expectedSessionBinding(transactionDataHash: Data(repeating: 4, count: 32))

    await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
      _ = try await provider.verifyStatusQualifiedClaimBundle(
        request: try verifyRequest(binding: otherBinding),
        statusQualifiedClaimProofBundle: bundle
      )
    }
  }

  @Test
  func expiredOrOverlongPresentationIsRejected() async throws {
    for expiry: UInt64 in [99, 100, 401] {
      let transport = RecordingNativeTransport(bundlePresentationExpiryUnix: expiry)

      await #expect(throws: ReallyMeZKError.providerRejected(.proofRejected)) {
        _ = try await verify(transport: transport)
      }
    }
  }

  @Test
  func incompleteBundleIsMalformedProviderResponse() async throws {
    let transport = RecordingNativeTransport()
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = boundSessionBinding()
    let complete = try await statusQualifiedBundle(provider: provider, binding: binding)

    var missingStatusProof = complete.statusQualifiedClaimProofBundle
    missingStatusProof.clearIssuerCredentialStatus()
    var wrongStatusProofSuite = complete.statusQualifiedClaimProofBundle
    wrongStatusProofSuite.issuerCredentialStatus.proofSuite = .barretenbergUltraHonkPoseidon2ZkNoIpa
    var missingStage = complete.statusQualifiedClaimProofBundle
    missingStage.claimProofBundle.stages.removeLast()

    for bundle in [missingStatusProof, wrongStatusProofSuite, missingStage] {
      await #expect(throws: ReallyMeZKError.invalidProviderResponse(.malformedProof)) {
        _ = try await provider.verifyStatusQualifiedClaimBundle(
          request: try verifyRequest(binding: binding),
          statusQualifiedClaimProofBundle: ReallyMeZKNativeStatusQualifiedClaimProofBundleHandle(
            statusQualifiedClaimProofBundle: bundle
          )
        )
      }
    }
  }

  @Test
  func unsupportedVerifiersFailClosed() async throws {
    let verifier = UnsupportedReallyMeZKStatusQualifiedClaimBundleVerifier()
    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      _ = try await verifier.verifyStatusQualifiedClaimBundle(
        request: try verifyRequest(),
        statusQualifiedClaimProofBundle:
          UnsupportedReallyMeZKStatusQualifiedClaimBundleVerifier
          .UnsupportedStatusQualifiedClaimProofBundleHandle()
      )
    }

    let provider = UnsupportedReallyMeZKClaimProofBundleProvider()
    await #expect(throws: ReallyMeZKError.providerUnavailable) {
      _ = try await provider.verifyStatusQualifiedClaimBundle(
        request: try verifyRequest(),
        statusQualifiedClaimProofBundle:
          UnsupportedReallyMeZKClaimProofBundleProvider
          .UnsupportedStatusQualifiedClaimProofBundleHandle()
      )
    }
  }

  @Test
  func presentationBoundResultIsNotAStatusQualifiedResult() async throws {
    let fourProof = try verifiedClaimProofBundle(
      bundleKind: .credentialSubjectClaim,
      binding: expectedSessionBinding()
    )
    let fiveProof = try await verify()

    #expect(isStatusQualifiedVerification(fourProof) == false)
    #expect(isPresentationBoundVerification(fiveProof) == false)
    #expect(acceptsCredential(fiveProof) == 5)
  }

  @Test
  func requestAndResultDescriptionsAreRedacted() async throws {
    let request = try verifyRequest(binding: boundSessionBinding())
    let verified = try await verify()

    #expect(
      request.description
        == "ReallyMeZKStatusQualifiedClaimBundleVerifyRequest(expectedSessionBinding: <redacted>, expectedIssuer: <redacted>, trustedIssuers: <redacted>, verificationTimeUnix: 100, currentIssuerStatus: <redacted>)"
    )
    #expect(request.debugDescription == request.description)
    #expect(
      verified.description
        == "ReallyMeZKStatusQualifiedClaimBundleVerification(bundleKind: \(ZKClaimProofBundleKind.credentialSubjectClaim.rawValue), verifiedProofCount: 5, statusPurpose: revocation, sessionBinding: <redacted>, issuer: <redacted>, persona: <redacted>, claimNameHash: <redacted>, claimValue: <redacted>, claimValueLength: 3, credentialBinding: <redacted>, sessionLinkCommitment: <redacted>, presentationExpiryUnix: 400)"
    )
    #expect(verified.debugDescription == verified.description)
    #expect(String(reflecting: verified) == verified.description)
  }

  private func verify(
    report: RecordingStatusQualifiedVerificationReport = .matching
  ) async throws -> ReallyMeZKStatusQualifiedClaimBundleVerification {
    try await verify(
      transport: RecordingNativeTransport(statusQualifiedVerificationReport: report)
    )
  }

  private func verify(
    transport: RecordingNativeTransport
  ) async throws -> ReallyMeZKStatusQualifiedClaimBundleVerification {
    let provider = try ReallyMeZKNativeProvider(contextHandle: 7, transport: transport)
    let binding = boundSessionBinding()
    let bundle = try await statusQualifiedBundle(provider: provider, binding: binding)
    return try await provider.verifyStatusQualifiedClaimBundle(
      request: try verifyRequest(binding: binding),
      statusQualifiedClaimProofBundle: bundle
    )
  }
}

/// Compiles only for the five-proof result: credential acceptance code that
/// takes this parameter type cannot be handed a presentation-bound result.
private func acceptsCredential(
  _ verification: ReallyMeZKStatusQualifiedClaimBundleVerification
) -> Int {
  verification.verifiedProofCount
}

private func isStatusQualifiedVerification(_ value: Any) -> Bool {
  value is ReallyMeZKStatusQualifiedClaimBundleVerification
}

private func isPresentationBoundVerification(_ value: Any) -> Bool {
  value is ReallyMeZKPresentationBoundClaimBundleVerification
}

private func boundSessionBinding() -> Reallyme_Zk_V1_ZkSessionBinding {
  expectedSessionBinding(transactionDataHash: Data(repeating: 3, count: 32))
}

private func currentIssuerStatus(
  root: Data = Data(repeating: 21, count: 32),
  length: UInt64 = 1024,
  listID: Data = Data(repeating: 22, count: 32),
  urlHash: Data = Data(repeating: 23, count: 32),
  purpose: Reallyme_Zk_V1_ZkIssuerStatusPurpose = .revocation
) -> Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation {
  var status = Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation()
  status.root = root
  status.length = length
  status.listID = listID
  status.urlHash = urlHash
  status.purpose = purpose
  return status
}

private func verifyRequest(
  binding: Reallyme_Zk_V1_ZkSessionBinding = expectedSessionBinding(),
  trustedIssuers: [Reallyme_Zk_V1_ZkP256PublicKey] = [trustedIssuer()],
  expectedIssuer: Reallyme_Zk_V1_ZkP256PublicKey = trustedIssuer(),
  currentIssuerStatus status: Reallyme_Zk_V1_ZkCommonCredentialRootIssuerStatusExpectation =
    currentIssuerStatus()
) throws(ReallyMeZKError) -> ReallyMeZKStatusQualifiedClaimBundleVerifyRequest {
  try ReallyMeZKStatusQualifiedClaimBundleVerifyRequest(
    expectedSessionBinding: binding,
    expectedIssuer: expectedIssuer,
    trustedIssuers: trustedIssuers,
    verificationTimeUnix: 100,
    currentIssuerStatus: status
  )
}

private func statusQualifiedBundle<Transport: ReallyMeZKNativeTransport>(
  provider: ReallyMeZKNativeProvider<Transport>,
  binding: Reallyme_Zk_V1_ZkSessionBinding
) async throws(ReallyMeZKError) -> ReallyMeZKNativeStatusQualifiedClaimProofBundleHandle {
  let claimProofBundle = try await credentialSubjectClaimProofBundle(
    provider: provider,
    binding: binding
  )
  var statusProof = Reallyme_Zk_V1_ZkCredentialStatusProofPackage()
  statusProof.proofSuite = .barretenbergUltraHonkKeccakZkNoIpa
  statusProof.proof = Data(repeating: 6, count: 96)
  var bundle = Reallyme_Zk_V1_ZkStatusQualifiedClaimProofBundle()
  bundle.claimProofBundle = claimProofBundle.handle.claimProofBundle
  bundle.issuerCredentialStatus = statusProof
  return ReallyMeZKNativeStatusQualifiedClaimProofBundleHandle(
    statusQualifiedClaimProofBundle: bundle
  )
}
