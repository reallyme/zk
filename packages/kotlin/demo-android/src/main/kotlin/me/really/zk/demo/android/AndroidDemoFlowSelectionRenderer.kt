// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode

internal enum class Subject { CLAIM, PERSONA, COMMON_CREDENTIAL_ROOT }

internal enum class Timing { REQUEST_BOUND, PREPARED }

internal class AndroidDemoFlowSelectionRenderer(
    private val personaModeSection: LinearLayout,
    private val timingSection: LinearLayout,
    private val credentialSubjectClaimButton: Button,
    private val privatePersonaButton: Button,
    private val preparedPrivateGenerateButton: Button,
    private val preparedPrivateVerifyButton: Button,
    private val preparedPublicGenerateButton: Button,
    private val preparedPublicVerifyButton: Button,
    private val preparedLimitView: TextView,
    private val commonCredentialRootButton: Button,
    private val flowTitleView: TextView,
    private val flowDescriptionView: TextView,
) {
    fun setActionsEnabled(
        enabled: Boolean,
        hasPublicProofs: Boolean,
        hasPrivateProofs: Boolean,
    ) {
        credentialSubjectClaimButton.isEnabled = enabled
        privatePersonaButton.isEnabled = enabled
        commonCredentialRootButton.isEnabled = enabled
        preparedPublicGenerateButton.isEnabled = enabled
        preparedPrivateGenerateButton.isEnabled = enabled
        preparedPublicVerifyButton.isEnabled = enabled && hasPublicProofs
        preparedPrivateVerifyButton.isEnabled = enabled && hasPrivateProofs
    }

    // This is the complete user-facing flow matrix; keep choices explicit.
    fun renderFlowSelection(
        selectedSubject: Subject,
        selectedPersonaMode: ZkCommonCredentialRootPersonaMode,
        selectedTiming: Timing,
    ) {
        val persona = selectedSubject == Subject.PERSONA
        val commonCredentialRoot = selectedSubject == Subject.COMMON_CREDENTIAL_ROOT
        val privatePersona = selectedPersonaMode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA
        val prepared = persona && (!privatePersona || selectedTiming == Timing.PREPARED)
        val commonCredentialRootVisibility =
            if (privatePersona) {
                "The presenting persona stays hidden. "
            } else {
                "The presenting persona is public and linkable. "
            }
        personaModeSection.visibility = if (persona || commonCredentialRoot) View.VISIBLE else View.GONE
        timingSection.visibility = if (persona && privatePersona) View.VISIBLE else View.GONE
        credentialSubjectClaimButton.visibility = if (selectedSubject == Subject.CLAIM) View.VISIBLE else View.GONE
        privatePersonaButton.visibility = if (persona && !prepared && privatePersona) View.VISIBLE else View.GONE
        preparedPrivateGenerateButton.visibility = if (prepared && privatePersona) View.VISIBLE else View.GONE
        preparedPrivateVerifyButton.visibility = preparedPrivateGenerateButton.visibility
        preparedPublicGenerateButton.visibility = if (prepared && !privatePersona) View.VISIBLE else View.GONE
        preparedPublicVerifyButton.visibility = preparedPublicGenerateButton.visibility
        preparedLimitView.visibility = if (prepared) View.VISIBLE else View.GONE
        commonCredentialRootButton.visibility = if (commonCredentialRoot) View.VISIBLE else View.GONE
        flowTitleView.text =
            when (selectedSubject) {
                Subject.CLAIM -> "Credential subject claim"
                Subject.COMMON_CREDENTIAL_ROOT ->
                    "Common credential root · " +
                        "${if (privatePersona) "private" else "public"} persona"
                Subject.PERSONA ->
                    "${if (privatePersona) "Private" else "Public"} persona · " +
                        (if (prepared) "prepared" else "request-bound")
            }
        flowDescriptionView.text =
            when (selectedSubject) {
                Subject.CLAIM -> "Prove a claim for this request without presenting a persona."
                Subject.COMMON_CREDENTIAL_ROOT ->
                    "Prove that two issuer credentials share one assured root. " +
                        commonCredentialRootVisibility +
                        "This sample generates and verifies nine request-bound proofs."
                Subject.PERSONA ->
                    when {
                        !privatePersona ->
                            "Prepare public proof stages once and recheck the same sample proofs. " +
                                "The sample does not fetch current issuer status or sign a live request."
                        prepared ->
                            "Prepare a private proof sample, then check it once without new proving. " +
                                "The fixed sample key is not a one-time token stock."
                        else -> "Generate a fresh proof while keeping the persona hidden."
                    }
            }
    }
}
