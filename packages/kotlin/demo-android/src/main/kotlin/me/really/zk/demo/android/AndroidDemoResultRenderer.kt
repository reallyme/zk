// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.app.Activity
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode

internal class AndroidDemoResultRenderer(
    private val context: Activity,
    private val headlineView: TextView,
    private val detailView: TextView,
    private val statusList: LinearLayout,
    private val progressCaptionView: TextView,
    private val progressBar: ProgressBar,
    private val bodyTextSizeSp: Int,
    private val totalProgressUnits: Int,
    private val waitingProgressCaption: String,
) {
    fun resetForSelection() {
        headlineView.text = AndroidDemoStrings.readyHeadline
        detailView.text = AndroidDemoStrings.readyDetail
        progressBar.progress = 0
        progressCaptionView.text = waitingProgressCaption
        statusList.removeAllViews()
    }

    fun renderRunningState(
        commonCredentialRoot: Boolean,
        prepared: Boolean,
    ) {
        when {
            commonCredentialRoot -> {
                headlineView.text = "Generating common-credential-root presentation..."
                detailView.text = "Synthetic credentials and a fixed sample verifier request."
            }
            prepared -> {
                headlineView.text = "Working on prepared proofs..."
                detailView.text = "The selected proof stages run locally on this phone."
            }
            else -> {
                headlineView.text = AndroidDemoStrings.runningHeadline
                detailView.text = AndroidDemoStrings.runningDetail
            }
        }
        progressBar.progress = 0
        progressCaptionView.text = waitingProgressCaption
        statusList.removeAllViews()
    }

    fun renderProgressLine(
        line: String,
        observedProgressTotal: Int,
    ): Int {
        val progressLine = parseDemoProgressLine(line)
        if (progressLine != null) {
            progressBar.progress = (progressLine.completedSteps * totalProgressUnits) / progressLine.totalSteps
            progressCaptionView.text = completedProgressCaption(progressLine.completedSteps, progressLine.totalSteps)
            detailView.text = progressLine.message
            statusList.addStatusLine(context, progressLine.message, bodyTextSizeSp)
            return progressLine.totalSteps
        }
        if (line.startsWith(STATUS_PREFIX)) {
            val message = line.removePrefix(STATUS_PREFIX)
            detailView.text = message
            statusList.addStatusLine(context, message, bodyTextSizeSp)
        }
        return observedProgressTotal
    }

    // Keep each result's wording next to the exact action it reports.
    fun renderSuccessState(
        success: DemoSuccess,
        observedProgressTotal: Int,
    ) {
        when (success) {
            is DemoSuccess.Prepared -> {
                if (success.verificationMilliseconds == null) {
                    headlineView.text =
                        if (success.mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                            "Public prepared proofs ready"
                        } else {
                            "Private prepared sample ready"
                        }
                    detailView.text = "Generation %.2f ms".format(success.generationMilliseconds)
                    statusList.addStatusLine(
                        context,
                        "Four credential proofs and one current-status proof are ready.",
                        bodyTextSizeSp,
                    )
                } else {
                    headlineView.text =
                        if (success.mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                            "Cached public proof stages verified"
                        } else {
                            "Cached private proof stages verified"
                        }
                    detailView.text =
                        "Verification %.2f ms; no new proving".format(success.verificationMilliseconds)
                    statusList.addStatusLine(
                        context,
                        "Four credential and one current-status proof verified.",
                        bodyTextSizeSp,
                    )
                    if (success.mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                        statusList.addStatusLine(
                            context,
                            "Public cached stages can be checked again without new proving.",
                            bodyTextSizeSp,
                        )
                    }
                }
                progressCaptionView.text = "5 of 5 stages complete"
            }
            is DemoSuccess.CommonCredentialRoot -> {
                val result = success.result
                headlineView.text = "Nine proofs generated and verified"
                detailView.text =
                    "Generation %.2f ms · verification %.2f ms".format(
                        result.generationMilliseconds,
                        result.verificationMilliseconds,
                    )
                statusList.addStatusLine(
                    context,
                    "Generated and verified ${result.verifiedProofCount} proofs and common-credential-root joins.",
                    bodyTextSizeSp,
                )
                progressCaptionView.text =
                    completedProgressCaption(result.verifiedProofCount, result.verifiedProofCount)
            }
            is DemoSuccess.Bundle -> {
                val timingSummary =
                    AndroidDemoStrings.timingSummary(
                        success.witnessMilliseconds,
                        success.proveMilliseconds,
                        success.verifyMilliseconds,
                    )
                headlineView.text = AndroidDemoStrings.successHeadline
                detailView.text = timingSummary
                statusList.addStatusLine(
                    context,
                    "Four claim proofs verified. Issuer validity and current status require the fifth proof " +
                        "and signed status list.",
                    bodyTextSizeSp,
                )
                statusList.addStatusLine(context, "Timing: $timingSummary", bodyTextSizeSp)
                progressCaptionView.text =
                    if (observedProgressTotal > 0) {
                        completedProgressCaption(observedProgressTotal, observedProgressTotal)
                    } else {
                        "Verification complete"
                    }
            }
        }
        progressBar.progress = totalProgressUnits
    }

    fun renderFailureState(
        message: String,
        commonCredentialRoot: Boolean = false,
    ) {
        headlineView.text =
            if (commonCredentialRoot) {
                "Could not verify presentation"
            } else {
                AndroidDemoStrings.failureHeadline
            }
        detailView.text = message
        progressBar.progress = 0
        progressCaptionView.text = waitingProgressCaption
        statusList.addStatusLine(context, message, bodyTextSizeSp)
    }
}

internal sealed interface DemoSuccess {
    data class Prepared(
        val mode: ZkCommonCredentialRootPersonaMode,
        val generationMilliseconds: Double,
        val verificationMilliseconds: Double?,
    ) : DemoSuccess

    data class Bundle(
        val witnessMilliseconds: Double,
        val proveMilliseconds: Double,
        val verifyMilliseconds: Double,
    ) : DemoSuccess

    data class CommonCredentialRoot(
        val result: CommonCredentialRootSampleResult,
    ) : DemoSuccess
}
