// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.content.Intent
import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.RadioGroup
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

public class ReallyMeZKDemoUiInstrumentationTest {
    @Test
    public fun guidedChooserShowsOnlyTheSelectedPresentationActions() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val targetContext = instrumentation.targetContext
        val intent = Intent(targetContext, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val activity = instrumentation.startActivitySync(intent) as MainActivity
        try {
            instrumentation.runOnMainSync {
                val root = activity.window.decorView
                val subject = root.findViewWithTag<RadioGroup>("proofSubjectGroup")
                val privacy = root.findViewWithTag<RadioGroup>("personaVisibilityGroup")
                val timing = root.findViewWithTag<RadioGroup>("proofTimingGroup")
                val actionTags =
                    listOf(
                        "credentialSubjectClaimGenerateButton",
                        "privatePersonaRequestBoundButton",
                        "preparedPublicGenerateButton",
                        "preparedPublicVerifyButton",
                        "preparedPrivateGenerateButton",
                        "preparedPrivateVerifyButton",
                        "commonCredentialRootGenerateButton",
                    )

                fun visibleActions(): Set<String> =
                    actionTags
                        .filter { tag -> root.findViewWithTag<Button>(tag).visibility == View.VISIBLE }
                        .toSet()

                assertEquals(setOf("credentialSubjectClaimGenerateButton"), visibleActions())
                subject.getChildAt(1).performClick()
                assertEquals(setOf("privatePersonaRequestBoundButton"), visibleActions())
                privacy.getChildAt(1).performClick()
                assertEquals(setOf("preparedPublicGenerateButton", "preparedPublicVerifyButton"), visibleActions())
                assertTrue("timing choices must be hidden for a public persona", !timing.isShown)
                privacy.getChildAt(0).performClick()
                timing.getChildAt(1).performClick()
                assertEquals(setOf("preparedPrivateGenerateButton", "preparedPrivateVerifyButton"), visibleActions())
                subject.getChildAt(2).performClick()
                assertEquals(setOf("commonCredentialRootGenerateButton"), visibleActions())
            }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
        }
    }

    @Test
    public fun publicPreparedActionRemainsAvailableAfterThreeChecks() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val targetContext = instrumentation.targetContext
        val intent = Intent(targetContext, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val activity = instrumentation.startActivitySync(intent) as MainActivity
        try {
            lateinit var verifyButton: Button
            instrumentation.runOnMainSync {
                val root = activity.window.decorView
                root.findViewWithTag<RadioGroup>("proofSubjectGroup").getChildAt(1).performClick()
                root.findViewWithTag<RadioGroup>("personaVisibilityGroup").getChildAt(1).performClick()
                verifyButton = root.findViewWithTag("preparedPublicVerifyButton")
                root.findViewWithTag<Button>("preparedPublicGenerateButton").performClick()
            }

            fun awaitReady(expectedCount: Int) {
                val started = SystemClock.uptimeMillis()
                var ready = false
                while (!ready && SystemClock.uptimeMillis() - started < PREPARED_UI_TIMEOUT_MILLISECONDS) {
                    instrumentation.runOnMainSync {
                        ready =
                            verifyButton.isEnabled &&
                            (expectedCount == 0 || verifyButton.text.contains("$expectedCount checks"))
                    }
                    if (!ready) SystemClock.sleep(PREPARED_UI_POLL_MILLISECONDS)
                }
                assertTrue("public prepared check $expectedCount did not finish", ready)
            }

            awaitReady(0)
            for (count in 1..3) {
                instrumentation.runOnMainSync { verifyButton.performClick() }
                awaitReady(count)
            }
            instrumentation.runOnMainSync { assertTrue(verifyButton.isEnabled) }
        } finally {
            instrumentation.runOnMainSync { activity.finish() }
        }
    }
}

private const val PREPARED_UI_TIMEOUT_MILLISECONDS = 120_000L
private const val PREPARED_UI_POLL_MILLISECONDS = 100L
