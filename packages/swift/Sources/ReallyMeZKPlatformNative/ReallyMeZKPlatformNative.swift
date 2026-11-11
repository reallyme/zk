// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import ReallyMeZKKit
import ReallyMeZKPlatformFFI

public enum ReallyMeZKPlatformCRSMode: UInt32, Sendable {
  case verifierOnly = 1
  case fullProver = 2
}

public final class ReallyMeZKPlatformContext: Sendable {
  public let contextHandle: UInt64
  public let transport: ReallyMeZKPlatformTransport

  public convenience init(
    artifactRoot: URL,
    releaseIndexURL: URL,
    approvedReleaseIndexSHA256: Data,
    crsG1URL: URL,
    crsG2URL: URL,
    crsMode: ReallyMeZKPlatformCRSMode
  ) throws(ReallyMeZKError) {
    let releaseIndex = try readMappedData(releaseIndexURL)
    try self.init(
      artifactRoot: artifactRoot,
      releaseIndex: releaseIndex,
      approvedReleaseIndexSHA256: approvedReleaseIndexSHA256,
      crsG1URL: crsG1URL,
      crsG2URL: crsG2URL,
      crsMode: crsMode
    )
  }

  public init(
    artifactRoot: URL,
    releaseIndex: Data,
    approvedReleaseIndexSHA256: Data,
    crsG1URL: URL,
    crsG2URL: URL,
    crsMode: ReallyMeZKPlatformCRSMode
  ) throws(ReallyMeZKError) {
    let artifactRootBytes = Data(artifactRoot.path.utf8)
    let crsG1PathBytes = Data(crsG1URL.path.utf8)
    let crsG2PathBytes = Data(crsG2URL.path.utf8)
    guard artifactRootBytes.isEmpty == false,
      releaseIndex.isEmpty == false,
      approvedReleaseIndexSHA256.count == digestSHA256Bytes,
      crsG1PathBytes.isEmpty == false,
      crsG2PathBytes.isEmpty == false
    else {
      throw ReallyMeZKError.providerUnavailable
    }
    let context = try Self.createContextWithCRSFiles(
      artifactRoot: artifactRootBytes,
      releaseIndex: releaseIndex,
      approvedIndexDigest: approvedReleaseIndexSHA256,
      crsG1Path: crsG1PathBytes,
      crsG2Path: crsG2PathBytes,
      crsMode: crsMode
    )
    self.contextHandle = UInt64(UInt(bitPattern: context))
    self.transport = ReallyMeZKPlatformTransport(context: context)
  }

  public init(
    artifactRoot: URL,
    releaseIndex: Data,
    approvedReleaseIndexSHA256: Data,
    crsG1: Data,
    crsG2: Data,
    crsMode: ReallyMeZKPlatformCRSMode
  ) throws(ReallyMeZKError) {
    let artifactRootBytes = Data(artifactRoot.path.utf8)
    guard artifactRootBytes.isEmpty == false,
      releaseIndex.isEmpty == false,
      approvedReleaseIndexSHA256.count == digestSHA256Bytes,
      crsG1.isEmpty == false,
      crsG2.isEmpty == false
    else {
      throw ReallyMeZKError.providerUnavailable
    }
    let context = try Self.createContext(
      artifactRoot: artifactRootBytes,
      releaseIndex: releaseIndex,
      approvedIndexDigest: approvedReleaseIndexSHA256,
      crsG1: crsG1,
      crsG2: crsG2,
      crsMode: crsMode
    )
    self.contextHandle = UInt64(UInt(bitPattern: context))
    self.transport = ReallyMeZKPlatformTransport(context: context)
  }

  public func close() async throws(ReallyMeZKError) {
    try await transport.close()
  }

  private static func createContext(
    artifactRoot: Data,
    releaseIndex: Data,
    approvedIndexDigest: Data,
    crsG1: Data,
    crsG2: Data,
    crsMode: ReallyMeZKPlatformCRSMode
  ) throws(ReallyMeZKError) -> OpaquePointer {
    do {
      return try artifactRoot.withUnsafeBytes { artifactRootBytes in
        try releaseIndex.withUnsafeBytes { releaseIndexBytes in
          try approvedIndexDigest.withUnsafeBytes { digestBytes in
            try crsG1.withUnsafeBytes { g1Bytes in
              try crsG2.withUnsafeBytes { g2Bytes in
                let result = reallyme_zk_platform_context_create(
                  artifactRootBytes.bindMemory(to: UInt8.self).baseAddress,
                  artifactRoot.count,
                  releaseIndexBytes.bindMemory(to: UInt8.self).baseAddress,
                  releaseIndex.count,
                  digestBytes.bindMemory(to: UInt8.self).baseAddress,
                  approvedIndexDigest.count,
                  g1Bytes.bindMemory(to: UInt8.self).baseAddress,
                  crsG1.count,
                  g2Bytes.bindMemory(to: UInt8.self).baseAddress,
                  crsG2.count,
                  crsMode.rawValue
                )
                guard result.status_code == REALLYME_ZK_PLATFORM_STATUS_OK,
                  let context = result.context
                else {
                  throw ReallyMeZKError.providerRejected(
                    providerReason(
                      status: result.status_code,
                      errorReasonCode: result.error_reason_code
                    )
                  )
                }
                return context
              }
            }
          }
        }
      }
    } catch let error as ReallyMeZKError {
      throw error
    } catch {
      throw ReallyMeZKError.providerUnavailable
    }
  }

  private static func createContextWithCRSFiles(
    artifactRoot: Data,
    releaseIndex: Data,
    approvedIndexDigest: Data,
    crsG1Path: Data,
    crsG2Path: Data,
    crsMode: ReallyMeZKPlatformCRSMode
  ) throws(ReallyMeZKError) -> OpaquePointer {
    do {
      return try artifactRoot.withUnsafeBytes { artifactRootBytes in
        try releaseIndex.withUnsafeBytes { releaseIndexBytes in
          try approvedIndexDigest.withUnsafeBytes { digestBytes in
            try crsG1Path.withUnsafeBytes { g1PathBytes in
              try crsG2Path.withUnsafeBytes { g2PathBytes in
                let result = reallyme_zk_platform_context_create_with_crs_files(
                  artifactRootBytes.bindMemory(to: UInt8.self).baseAddress,
                  artifactRoot.count,
                  releaseIndexBytes.bindMemory(to: UInt8.self).baseAddress,
                  releaseIndex.count,
                  digestBytes.bindMemory(to: UInt8.self).baseAddress,
                  approvedIndexDigest.count,
                  g1PathBytes.bindMemory(to: UInt8.self).baseAddress,
                  crsG1Path.count,
                  g2PathBytes.bindMemory(to: UInt8.self).baseAddress,
                  crsG2Path.count,
                  crsMode.rawValue
                )
                guard result.status_code == REALLYME_ZK_PLATFORM_STATUS_OK,
                  let context = result.context
                else {
                  throw ReallyMeZKError.providerRejected(
                    providerReason(
                      status: result.status_code,
                      errorReasonCode: result.error_reason_code
                    )
                  )
                }
                return context
              }
            }
          }
        }
      }
    } catch let error as ReallyMeZKError {
      throw error
    } catch {
      throw ReallyMeZKError.providerUnavailable
    }
  }
}

public actor ReallyMeZKPlatformTransport: ReallyMeZKNativeTransport {
  private let contextAddress: UInt
  private var closed = false

  public init(context: OpaquePointer) {
    self.contextAddress = UInt(bitPattern: context)
  }

  deinit {
    if closed == false, let context = contextPointer() {
      // Explicit close reports typed failures. This finalizer is a last-resort
      // ownership guard so an abandoned consumer context does not leak.
      _ = reallyme_zk_platform_context_destroy(context)
    }
  }

  public func dispatch(
    contextHandle: UInt64,
    request: Data
  ) async throws(ReallyMeZKError) -> Data {
    guard closed == false else {
      throw ReallyMeZKError.providerUnavailable
    }
    guard contextHandle == UInt64(contextAddress),
      request.isEmpty == false,
      let context = contextPointer()
    else {
      throw ReallyMeZKError.providerUnavailable
    }
    do {
      return try request.withUnsafeBytes { requestBytes in
        let result = reallyme_zk_platform_dispatch(
          context,
          requestBytes.bindMemory(to: UInt8.self).baseAddress,
          request.count
        )
        guard result.status_code == REALLYME_ZK_PLATFORM_STATUS_OK else {
          if result.output.ptr != nil {
            _ = reallyme_zk_platform_buffer_destroy(result.output)
          }
          if result.status_code == REALLYME_ZK_PLATFORM_STATUS_DISPATCH_BUSY {
            throw ReallyMeZKError.alreadyRunning
          }
          throw ReallyMeZKError.providerRejected(providerReason(status: result.status_code))
        }
        guard let pointer = result.output.ptr else {
          throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
        }
        guard result.output.len > 0 else {
          let destroyStatus = reallyme_zk_platform_buffer_destroy(result.output)
          guard destroyStatus.status_code == REALLYME_ZK_PLATFORM_STATUS_OK else {
            throw ReallyMeZKError.providerRejected(
              providerReason(status: destroyStatus.status_code)
            )
          }
          throw ReallyMeZKError.invalidProviderResponse(.emptyBuffer)
        }
        let response = Data(bytes: pointer, count: result.output.len)
        let destroyStatus = reallyme_zk_platform_buffer_destroy(result.output)
        guard destroyStatus.status_code == REALLYME_ZK_PLATFORM_STATUS_OK else {
          throw ReallyMeZKError.providerRejected(providerReason(status: destroyStatus.status_code))
        }
        return response
      }
    } catch let error as ReallyMeZKError {
      throw error
    } catch {
      throw ReallyMeZKError.invalidProviderResponse(.internalFailure)
    }
  }

  public func close() throws(ReallyMeZKError) {
    if closed {
      return
    }
    guard let context = contextPointer() else {
      throw ReallyMeZKError.providerUnavailable
    }
    let status = reallyme_zk_platform_context_destroy(context)
    guard status.status_code == REALLYME_ZK_PLATFORM_STATUS_OK else {
      throw ReallyMeZKError.providerRejected(providerReason(status: status.status_code))
    }
    closed = true
  }

  private nonisolated func contextPointer() -> OpaquePointer? {
    OpaquePointer(bitPattern: contextAddress)
  }
}

private func readMappedData(_ url: URL) throws(ReallyMeZKError) -> Data {
  do {
    let data = try Data(contentsOf: url, options: [.mappedIfSafe])
    guard data.isEmpty == false else {
      throw ReallyMeZKError.providerUnavailable
    }
    return data
  } catch let error as ReallyMeZKError {
    throw error
  } catch {
    throw ReallyMeZKError.providerUnavailable
  }
}

private let artifactMismatchReasonCode: UInt32 = 10

private func providerReason(
  status: UInt32,
  errorReasonCode: UInt32 = 0
) -> ZKProviderFailureReason {
  // The context ABI carries a stable ZkErrorReason alongside its coarse status.
  // Preserve an artifact mismatch so a stale binary cannot look like a missing provider.
  if errorReasonCode == artifactMismatchReasonCode {
    return .artifactMismatch
  }
  switch status {
  case REALLYME_ZK_PLATFORM_STATUS_REQUEST_TOO_LARGE:
    return .oversizedBuffer
  case REALLYME_ZK_PLATFORM_STATUS_INVALID_BUFFER:
    return .malformedProof
  case REALLYME_ZK_PLATFORM_STATUS_INVALID_CONTEXT:
    return .crsMissing
  default:
    return .internalFailure
  }
}

private let digestSHA256Bytes = 32
