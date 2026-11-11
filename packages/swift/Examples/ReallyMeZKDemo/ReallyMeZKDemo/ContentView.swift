// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import ReallyMeZKKit
import SwiftUI

struct ContentView: View {
  @Environment(\.scenePhase) private var scenePhase
  @State private var isRunning = false
  @State private var runTask: Task<Void, Never>?
  @State private var selectedCircuitHash: ZKCredentialHashAlgorithm = .sha256
  @State private var selectedSubject: Subject = .claim
  @State private var selectedPersonaMode: ZKCommonCredentialRootPersonaMode = .privatePersona
  @State private var selectedTiming: Timing = .now
  @State private var preparedPublicProofs: PersonaCredentialEvidenceSampleProofs?
  @State private var preparedPrivateProofs: PersonaCredentialEvidenceSampleProofs?
  @State private var publicPreparedChecks = 0
  @State private var headline = "Ready to generate proof"
  @State private var detail = "Choose a proof type and continue."
  @State private var progress: Double = 0
  @State private var totalSteps: Int = 0
  @State private var completedSteps: Int = 0
  @State private var updates: [String] = []

  var body: some View {
    NavigationView {
      ScrollView {
        VStack(alignment: .leading, spacing: 20) {
          Text("Zero-Knowledge Proofs")
            .font(.largeTitle.weight(.bold))

          Text("Choose a claim or relationship to prove with on-device synthetic credentials.")
            .font(.subheadline)
            .foregroundStyle(.secondary)

          VStack(alignment: .leading, spacing: 12) {
            Text("1. What are you presenting?")
              .font(.headline)
            Picker("Proof subject", selection: $selectedSubject) {
              ForEach(Subject.allCases) { subject in
                Text(subject.rawValue).tag(subject)
              }
            }
            .pickerStyle(.segmented)
            .disabled(isRunning)
            .accessibilityIdentifier("proofSubjectPicker")
          }
          if selectedSubject != .claim {
            VStack(alignment: .leading, spacing: 12) {
              Text("2. Who can see the persona?")
                .font(.headline)
              Picker("Persona visibility", selection: $selectedPersonaMode) {
                Text("Private").tag(ZKCommonCredentialRootPersonaMode.privatePersona)
                Text("Public").tag(ZKCommonCredentialRootPersonaMode.publicPersona)
              }
              .pickerStyle(.segmented)
              .disabled(isRunning)
              .accessibilityIdentifier("personaVisibilityPicker")
            }
          }

          if selectedSubject == .persona && selectedPersonaMode == .privatePersona {
            VStack(alignment: .leading, spacing: 12) {
              Text("3. When will you prove it?")
                .font(.headline)
              Picker("Proof timing", selection: $selectedTiming) {
                ForEach(Timing.allCases) { timing in
                  Text(timing.rawValue).tag(timing)
                }
              }
              .pickerStyle(.segmented)
              .disabled(isRunning)
              .accessibilityIdentifier("proofTimingPicker")
            }
          }

          VStack(alignment: .leading, spacing: 12) {
            Text("Proof settings")
              .font(.headline)
            Picker("Circuit Hash", selection: $selectedCircuitHash) {
              ForEach(ZKCredentialHashAlgorithm.allCases) { strategy in
                Text(strategy.displayName).tag(strategy)
              }
            }
            .pickerStyle(.segmented)
            .disabled(isRunning)
          }

          VStack(alignment: .leading, spacing: 12) {
            Text(selectedFlowTitle)
              .font(.title3.weight(.semibold))
            Text(selectedFlowDescription)
              .font(.subheadline)
              .foregroundStyle(.secondary)
            selectedFlowActions
          }
          .padding(16)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(Color(.secondarySystemBackground))
          .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))
          .onChange(of: selectedCircuitHash) { _, _ in
            preparedPublicProofs = nil
            preparedPrivateProofs = nil
            publicPreparedChecks = 0
            resetResultForSelection()
          }
          .onChange(of: selectedSubject) { _, _ in resetResultForSelection() }
          .onChange(of: selectedPersonaMode) { _, _ in resetResultForSelection() }
          .onChange(of: selectedTiming) { _, _ in resetResultForSelection() }

          VStack(alignment: .leading, spacing: 10) {
            Text(headline)
              .font(.title3.weight(.semibold))
              .accessibilityIdentifier("proofResultHeadline")
            Text(detail)
              .font(.subheadline)
              .foregroundStyle(.secondary)
              .accessibilityIdentifier("proofResultDetail")

            ProgressView(value: progress)
              .tint(.blue)

            Text(progressCaption)
              .font(.caption)
              .foregroundStyle(.secondary)
          }
          .padding(16)
          .background(Color(.secondarySystemBackground))
          .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))

          if updates.isEmpty == false {
            VStack(alignment: .leading, spacing: 10) {
              Text("Status")
                .font(.headline)
              ForEach(Array(updates.enumerated()), id: \.offset) { _, line in
                HStack(alignment: .top, spacing: 8) {
                  Circle()
                    .fill(Color.blue.opacity(0.9))
                    .frame(width: 6, height: 6)
                    .padding(.top, 6)
                  Text(line)
                    .font(.subheadline)
                    .foregroundStyle(.primary)
                }
              }
            }
          }
        }
        .padding(20)
      }
      .navigationTitle("ReallyMeZK Demo")
    }
    .onChange(of: scenePhase) { _, phase in
      if phase != .active {
        cancelRun()
      }
    }
    .onDisappear {
      cancelRun()
    }
  }

  private var selectedFlowTitle: String {
    ProofFlowCopy.title(
      subject: selectedSubject, personaMode: selectedPersonaMode, timing: selectedTiming
    )
  }

  private var selectedFlowDescription: String {
    ProofFlowCopy.description(
      subject: selectedSubject, personaMode: selectedPersonaMode, timing: selectedTiming
    )
  }

  @ViewBuilder
  private var selectedFlowActions: some View {
    switch selectedSubject {
    case .claim:
      Button("Generate and verify proof") { runSample(.credentialSubjectClaim) }
        .buttonStyle(.borderedProminent)
        .disabled(isRunning)
        .accessibilityIdentifier("credentialSubjectClaimGenerateButton")
    case .commonCredentialRoot:
      Button("Generate and verify nine proofs", action: generateCommonCredentialRootSample)
        .buttonStyle(.borderedProminent)
        .disabled(isRunning)
        .accessibilityIdentifier("commonCredentialRootGenerateButton")
    case .persona where selectedTiming == .now && selectedPersonaMode == .privatePersona:
      Button("Generate and verify proof") { runSample(.privatePersona) }
        .buttonStyle(.borderedProminent)
        .disabled(isRunning)
        .accessibilityIdentifier("privatePersonaRequestBoundButton")
    case .persona:
      if selectedPersonaMode == .privatePersona {
        Button("1. Prepare private proof stages") {
          preparePersonaSample(mode: .privatePersona)
        }
        .buttonStyle(.borderedProminent)
        .disabled(isRunning)
        .accessibilityIdentifier("preparedPrivateGenerateButton")
        Button("2. Check cached stages once") {
          verifyPersonaCredentialEvidenceSample(mode: .privatePersona)
        }
        .disabled(isRunning || preparedPrivateProofs == nil)
        .accessibilityIdentifier("preparedPrivateVerifyButton")
      } else {
        Button("1. Prepare public proof stages") {
          preparePersonaSample(mode: .publicPersona)
        }
        .buttonStyle(.borderedProminent)
        .disabled(isRunning)
        .accessibilityIdentifier("preparedPublicGenerateButton")
        Button(
          publicPreparedChecks == 0
            ? "2. Check cached stages"
            : "Check cached stages again (\(publicPreparedChecks) checks)"
        ) {
          verifyPersonaCredentialEvidenceSample(mode: .publicPersona)
        }
        .disabled(isRunning || preparedPublicProofs == nil)
        .accessibilityIdentifier("preparedPublicVerifyButton")
      }
      Text(
        "Stage checks only. A complete presentation requires independently verified current issuer status, a fresh protected-key signature, and verifier replay protection."
      )
      .font(.caption)
      .foregroundStyle(.secondary)
    }
  }

  private var progressCaption: String {
    if totalSteps <= 0 {
      return "Waiting to start"
    }
    return "\(completedSteps) of \(totalSteps) steps complete"
  }

  private func resetResultForSelection() {
    guard isRunning == false else { return }
    headline = "Ready to generate proof"
    detail = "Choose a proof type and continue."
    progress = 0
    completedSteps = 0
    totalSteps = 0
    updates = []
  }

  private func runSample(_ bundleKind: ReallyMeZKDemoSampleRunner.BundleKind) {
    guard isRunning == false, runTask == nil else {
      return
    }
    isRunning = true
    progress = 0
    totalSteps = 0
    completedSteps = 0
    updates = []
    headline = "Generating proof..."
    detail = "Preparing secure proving context."

    let circuitHash = selectedCircuitHash
    runTask = Task(priority: .userInitiated) {
      do {
        let result = try await ReallyMeZKDemoSampleRunner.runFlow(
          bundleKind: bundleKind,
          bundle: .main,
          options: ProofOptions(
            ipaAccumulation: false,
            disableZk: false,
            oracleHash: .keccak,
            circuitCredentialHashAlgorithm: circuitHash,
            threadCount: ProofFlowCopy.proofThreadCount
          ),
          progress: { line in
            Task { @MainActor in
              handleProgressLine(line)
            }
          }
        )

        let timingSummary = String(
          format: "Witness %.2f s · proving %.2f s · verification %.2f ms",
          result.witnessMilliseconds / 1_000.0,
          result.proveMilliseconds / 1_000.0,
          result.verifyMilliseconds
        )

        await MainActor.run {
          headline = "Claim proofs verified"
          detail = timingSummary
          updates.append(
            "Four claim proofs verified. Issuer validity and current status are checked "
              + "with a separate fifth proof and signed status list."
          )
          updates.append("Timing: \(timingSummary)")
          progress = 1
          completedSteps = totalSteps
          isRunning = false
          runTask = nil
        }
      } catch {
        await MainActor.run {
          headline = "Could not generate proof"
          detail = ProofFlowCopy.safeErrorDetail(for: error)
          updates.append("Failed: \(ProofFlowCopy.safeErrorStatus(for: error))")
          isRunning = false
          runTask = nil
        }
      }
    }
  }

  private func generateCommonCredentialRootSample() {
    guard isRunning == false, runTask == nil else {
      return
    }
    isRunning = true
    progress = 0
    completedSteps = 0
    totalSteps = 10
    updates = []
    headline = "Generating common-credential-root presentation..."
    detail = "Synthetic credentials and a fixed sample verifier request."
    let mode = selectedPersonaMode
    let hash = selectedCircuitHash
    runTask = Task(priority: .userInitiated) {
      do {
        let result = try await ReallyMeZKDemoCommonCredentialRootRunner.generateSample(
          mode: mode,
          credentialHashAlgorithm: hash,
          bundle: .main,
          progress: { count in
            Task { @MainActor in
              completedSteps = count
              progress = Double(count) / 10
            }
          }
        )
        await MainActor.run {
          headline = "Nine proofs generated and verified"
          detail = String(
            format: "Generation %.2f ms · verification %.2f ms",
            result.generationMilliseconds,
            result.verificationMilliseconds
          )
          updates.append(
            "Generated and verified \(result.verifiedProofCount) proofs and common-credential-root joins."
          )
          completedSteps = totalSteps
          progress = 1
          isRunning = false
          runTask = nil
        }
      } catch {
        await MainActor.run {
          headline = "Could not generate presentation"
          detail = ProofFlowCopy.safeErrorDetail(for: error)
          updates.append("Failed: \(ProofFlowCopy.safeErrorStatus(for: error))")
          isRunning = false
          runTask = nil
        }
      }
    }
  }

  private func preparePersonaSample(mode: ZKCommonCredentialRootPersonaMode) {
    guard isRunning == false, runTask == nil else { return }
    isRunning = true
    if mode == .publicPersona {
      preparedPublicProofs = nil
    } else {
      preparedPrivateProofs = nil
    }
    progress = 0
    totalSteps = 5
    completedSteps = 0
    updates = []
    headline = "Preparing persona proofs..."
    detail = "Generating four credential proofs and a current-status proof."
    let hash = selectedCircuitHash
    runTask = Task(priority: .userInitiated) {
      do {
        let proofs = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.prepare(
          mode: mode, credentialHashAlgorithm: hash, bundle: .main
        )
        await MainActor.run {
          if mode == .publicPersona {
            preparedPublicProofs = proofs
            publicPreparedChecks = 0
          } else {
            preparedPrivateProofs = proofs
          }
          headline =
            mode == .publicPersona
            ? "Public prepared proofs ready" : "Private prepared sample ready"
          detail = String(format: "Generation %.2f ms", proofs.generationMilliseconds)
          updates.append("Four credential proofs and one current-status proof are ready.")
          progress = 1
          completedSteps = 5
          isRunning = false
          runTask = nil
        }
      } catch {
        await MainActor.run {
          headline = "Could not prepare proof"
          detail = ProofFlowCopy.safeErrorDetail(for: error)
          isRunning = false
          runTask = nil
        }
      }
    }
  }

  private func verifyPersonaCredentialEvidenceSample(mode: ZKCommonCredentialRootPersonaMode) {
    let cached = mode == .publicPersona ? preparedPublicProofs : preparedPrivateProofs
    guard isRunning == false, runTask == nil, let proofs = cached else { return }
    isRunning = true
    if proofs.mode == .privatePersona {
      // A failed or interrupted local check still consumes this sample instance.
      preparedPrivateProofs = nil
    }
    progress = 0
    totalSteps = 5
    completedSteps = 0
    updates = []
    headline = "Verifying cached proofs..."
    detail = "No new claim proof is being generated."
    runTask = Task(priority: .userInitiated) {
      do {
        let elapsed = try await ReallyMeZKDemoPersonaCredentialEvidenceRunner.verifyCachedStages(
          proofs, bundle: .main
        )
        await MainActor.run {
          headline =
            proofs.mode == .publicPersona
            ? "Cached public proof stages verified" : "Cached private proof stages verified"
          detail = String(format: "Verification %.2f ms; no new proving", elapsed)
          updates.append("Four credential and one current-status proof verified.")
          if proofs.mode == .privatePersona {
            updates.append("Private sample consumed; prepare a new one for another local check.")
          } else {
            if publicPreparedChecks < Int.max {
              publicPreparedChecks += 1
            }
            updates.append("Public cached stages can be checked again without new proving.")
          }
          progress = 1
          completedSteps = 5
          isRunning = false
          runTask = nil
        }
      } catch {
        await MainActor.run {
          headline = "Cached proof verification failed"
          detail = ProofFlowCopy.safeErrorDetail(for: error)
          isRunning = false
          runTask = nil
        }
      }
    }
  }

  private func cancelRun() {
    guard let task = runTask else {
      return
    }
    task.cancel()
    detail = "Cancelling proof job."
  }

  @MainActor
  private func handleProgressLine(_ line: String) {
    if line.hasPrefix("UI_PROGRESS|") {
      let parts = line.split(separator: "|", maxSplits: 3, omittingEmptySubsequences: false)
      if parts.count == 4,
        let current = Int(parts[1]),
        let total = Int(parts[2])
      {
        totalSteps = max(total, 1)
        completedSteps = min(max(current, 0), totalSteps)
        progress = Double(completedSteps) / Double(totalSteps)
        let message = String(parts[3])
        detail = message
        updates.append(message)
      }
      return
    }

    if line.hasPrefix("UI_STATUS|") {
      let message = String(line.dropFirst("UI_STATUS|".count))
      detail = message
      updates.append(message)
    }
  }

}
