// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest

final class ReallyMeZKDemoCommonCredentialRootUITests: XCTestCase {
  @MainActor
  func testGuidedChooserShowsOnlyTheSelectedPresentationActions() {
    let app = XCUIApplication()
    app.launch()

    let subject = app.segmentedControls["proofSubjectPicker"]
    XCTAssertTrue(subject.waitForExistence(timeout: 10))
    XCTAssertTrue(app.buttons["credentialSubjectClaimGenerateButton"].waitForExistence(timeout: 10))
    XCTAssertFalse(app.buttons["commonCredentialRootGenerateButton"].exists)

    subject.buttons["Persona"].tap()
    XCTAssertTrue(app.buttons["privatePersonaRequestBoundButton"].waitForExistence(timeout: 10))
    let privacy = app.segmentedControls["personaVisibilityPicker"]
    privacy.buttons["Public"].tap()
    XCTAssertTrue(app.buttons["preparedPublicGenerateButton"].waitForExistence(timeout: 10))
    XCTAssertFalse(app.buttons["publicPersonaRequestBoundButton"].exists)
    XCTAssertFalse(app.segmentedControls["proofTimingPicker"].exists)
    XCTAssertTrue(app.buttons["preparedPublicVerifyButton"].exists)
    XCTAssertFalse(app.buttons["preparedPublicVerifyButton"].isEnabled)
    privacy.buttons["Private"].tap()
    let timing = app.segmentedControls["proofTimingPicker"]
    XCTAssertTrue(timing.waitForExistence(timeout: 10))
    timing.buttons["Prepare ahead"].tap()
    XCTAssertTrue(app.buttons["preparedPrivateGenerateButton"].waitForExistence(timeout: 10))
    XCTAssertTrue(app.buttons["preparedPrivateVerifyButton"].exists)

    subject.buttons["Common credential root"].tap()
    XCTAssertTrue(app.buttons["commonCredentialRootGenerateButton"].waitForExistence(timeout: 10))
    XCTAssertFalse(app.buttons["preparedPrivateGenerateButton"].exists)
  }

  @MainActor
  func testPublicPreparedProofCanBeCheckedThreeTimesFromVisibleControl() {
    let app = XCUIApplication()
    app.launch()

    let subject = app.segmentedControls["proofSubjectPicker"]
    XCTAssertTrue(subject.waitForExistence(timeout: 10))
    subject.buttons["Persona"].tap()
    app.segmentedControls["personaVisibilityPicker"].buttons["Public"].tap()

    let prepareButton = app.buttons["preparedPublicGenerateButton"]
    let verifyButton = app.buttons["preparedPublicVerifyButton"]
    prepareButton.tap()
    let result = app.staticTexts["proofResultHeadline"]
    let finished = XCTNSPredicateExpectation(
      predicate: NSPredicate(
        format: "label == %@ OR label == %@",
        "Public prepared proofs ready",
        "Could not prepare proof"
      ),
      object: result
    )
    XCTAssertEqual(XCTWaiter.wait(for: [finished], timeout: 120), .completed)
    guard verifyButton.isEnabled else {
      XCTFail("\(result.label): \(app.staticTexts["proofResultDetail"].label)")
      return
    }

    for count in 1...3 {
      verifyButton.tap()
      let repeated = XCTNSPredicateExpectation(
        predicate: NSPredicate(
          format: "label == %@", "Check cached stages again (\(count) checks)"
        ),
        object: verifyButton
      )
      XCTAssertEqual(XCTWaiter.wait(for: [repeated], timeout: 120), .completed)
      XCTAssertTrue(verifyButton.isEnabled)
    }
  }

  @MainActor
  func testPrivatePreparedSampleIsConsumedAfterOneCheck() {
    let app = XCUIApplication()
    app.launch()

    let subject = app.segmentedControls["proofSubjectPicker"]
    XCTAssertTrue(subject.waitForExistence(timeout: 10))
    subject.buttons["Persona"].tap()
    app.segmentedControls["personaVisibilityPicker"].buttons["Private"].tap()
    app.segmentedControls["proofTimingPicker"].buttons["Prepare ahead"].tap()

    let prepareButton = app.buttons["preparedPrivateGenerateButton"]
    let verifyButton = app.buttons["preparedPrivateVerifyButton"]
    XCTAssertFalse(verifyButton.isEnabled)
    prepareButton.tap()

    let result = app.staticTexts["proofResultHeadline"]
    let prepared = XCTNSPredicateExpectation(
      predicate: NSPredicate(
        format: "label == %@ OR label == %@",
        "Private prepared sample ready",
        "Could not prepare proof"
      ),
      object: result
    )
    XCTAssertEqual(XCTWaiter.wait(for: [prepared], timeout: 120), .completed)
    guard verifyButton.isEnabled else {
      XCTFail("\(result.label): \(app.staticTexts["proofResultDetail"].label)")
      return
    }

    verifyButton.tap()
    let verified = XCTNSPredicateExpectation(
      predicate: NSPredicate(
        format: "label == %@ OR label == %@",
        "Cached private proof stages verified",
        "Cached proof verification failed"
      ),
      object: result
    )
    XCTAssertEqual(XCTWaiter.wait(for: [verified], timeout: 120), .completed)
    XCTAssertEqual(result.label, "Cached private proof stages verified")
    XCTAssertFalse(verifyButton.isEnabled)
    XCTAssertTrue(prepareButton.isEnabled)
  }

  @MainActor
  func testNineProofPresentationGeneratesAndVerifiesFromVisibleControl() {
    let app = XCUIApplication()
    app.launch()

    let subject = app.segmentedControls["proofSubjectPicker"]
    XCTAssertTrue(subject.waitForExistence(timeout: 10))
    subject.buttons["Common credential root"].tap()
    let generateButton = app.buttons["commonCredentialRootGenerateButton"]
    XCTAssertTrue(generateButton.waitForExistence(timeout: 10))
    generateButton.tap()

    let result = app.staticTexts["proofResultHeadline"]
    let verified = XCTNSPredicateExpectation(
      predicate: NSPredicate(format: "label == %@", "Nine proofs generated and verified"),
      object: result
    )
    XCTAssertEqual(XCTWaiter.wait(for: [verified], timeout: 120), .completed)
  }
}
