// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.app.Activity
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RadioGroup
import android.widget.ScrollView
import android.widget.TextView
import me.really.zk.ReallyMeZk
import me.really.zk.ReallyMeZkProviderException
import me.really.zk.circuits.ZkCredentialHashAlgorithm
import me.really.zk.claimbundle.ZkClaimProofBundleKind
import me.really.zk.commonroot.ZkCommonCredentialRootPersonaMode
import me.really.zk.displayName
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean

// Each action remains explicit so a proof-stage check cannot be mistaken for acceptance.
public class MainActivity : Activity() {
    private val singleFlight = AtomicBoolean(false)
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val demoRuntime: AndroidDemoRuntime by lazy { AndroidDemoRuntime(applicationContext) }

    @Volatile private var runFuture: Future<*>? = null
    private var observedProgressTotal: Int = 0
    private var selectedCircuitHash: ZkCredentialHashAlgorithm =
        ZkCredentialHashAlgorithm.ZK_CREDENTIAL_HASH_ALGORITHM_SHA256
    private var selectedSubject: Subject = Subject.CLAIM
    private var selectedPersonaMode: ZkCommonCredentialRootPersonaMode =
        ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA
    private var selectedTiming: Timing = Timing.REQUEST_BOUND
    private var preparedPublicProofs: PersonaCredentialEvidenceSampleProofs? = null
    private var preparedPrivateProofs: PersonaCredentialEvidenceSampleProofs? = null
    private var publicPreparedChecks: Int = 0
    private val circuitHashGroup: RadioGroup by lazy {
        demoRadioGroup(
            values = ReallyMeZk.credentialHashAlgorithms,
            selectedValue = selectedCircuitHash,
            radioIdOffset = AndroidDemoUiSpec.circuitHashRadioIdOffset,
            label = { credentialHashAlgorithm -> credentialHashAlgorithm.displayName },
            onSelected = { credentialHashAlgorithm ->
                selectedCircuitHash = credentialHashAlgorithm
                preparedPublicProofs = null
                preparedPrivateProofs = null
                publicPreparedChecks = 0
                preparedPublicVerifyButton.isEnabled = false
                preparedPrivateVerifyButton.isEnabled = false
                resetResultForSelection()
            },
        )
    }
    private val subjectGroup: RadioGroup by lazy {
        demoRadioGroup(
            values = Subject.entries,
            selectedValue = selectedSubject,
            radioIdOffset = AndroidDemoUiSpec.subjectRadioIdOffset,
            label = { subject ->
                when (subject) {
                    Subject.CLAIM -> "Claim"
                    Subject.PERSONA -> "Persona"
                    Subject.COMMON_CREDENTIAL_ROOT -> "Common credential root"
                }
            },
            onSelected = { subject ->
                selectedSubject = subject
                renderFlowSelection()
                resetResultForSelection()
            },
        ).also { it.tag = "proofSubjectGroup" }
    }
    private val personaModeGroup: RadioGroup by lazy {
        demoRadioGroup(
            values = ZkCommonCredentialRootPersonaMode.entries,
            selectedValue = selectedPersonaMode,
            radioIdOffset = AndroidDemoUiSpec.personaModeRadioIdOffset,
            label = { mode -> if (mode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA) "Private" else "Public" },
            onSelected = { mode ->
                selectedPersonaMode = mode
                renderFlowSelection()
                resetResultForSelection()
            },
        ).also { it.tag = "personaVisibilityGroup" }
    }
    private val timingGroup: RadioGroup by lazy {
        demoRadioGroup(
            values = Timing.entries,
            selectedValue = selectedTiming,
            radioIdOffset = AndroidDemoUiSpec.timingRadioIdOffset,
            label = { timing -> if (timing == Timing.REQUEST_BOUND) "For this request" else "Prepare ahead" },
            onSelected = { timing ->
                selectedTiming = timing
                renderFlowSelection()
                resetResultForSelection()
            },
        ).also { it.tag = "proofTimingGroup" }
    }
    private val personaModeSection: LinearLayout by lazy {
        LinearLayout(this).also { it.orientation = LinearLayout.VERTICAL }
    }
    private val timingSection: LinearLayout by lazy {
        LinearLayout(this).also { it.orientation = LinearLayout.VERTICAL }
    }
    private val flowTitleView: TextView by lazy {
        demoText("Credential subject claim", AndroidDemoUiSpec.headlineTextSizeSp, Color.BLACK, true)
    }
    private val flowDescriptionView: TextView by lazy {
        demoText("", AndroidDemoUiSpec.bodyTextSizeSp, Color.DKGRAY, false)
    }
    private val preparedLimitView: TextView by lazy {
        demoText(
            "Stage checks only. A complete presentation requires independently verified current issuer " +
                "status, a fresh protected-key signature, and verifier replay protection.",
            AndroidDemoUiSpec.captionTextSizeSp,
            Color.DKGRAY,
            false,
        )
    }
    private val credentialSubjectClaimButton: Button by lazy { Button(this) }
    private val privatePersonaButton: Button by lazy { Button(this) }
    private val commonCredentialRootButton: Button by lazy { Button(this) }
    private val preparedPublicGenerateButton: Button by lazy { Button(this) }
    private val preparedPublicVerifyButton: Button by lazy { Button(this) }
    private val preparedPrivateGenerateButton: Button by lazy { Button(this) }
    private val preparedPrivateVerifyButton: Button by lazy { Button(this) }
    private val headlineView: TextView by lazy {
        demoText(AndroidDemoStrings.readyHeadline, AndroidDemoUiSpec.headlineTextSizeSp, Color.BLACK, true)
    }
    private val detailView: TextView by lazy {
        demoText(AndroidDemoStrings.readyDetail, AndroidDemoUiSpec.bodyTextSizeSp, Color.DKGRAY, false)
    }
    private val progressBar: ProgressBar by lazy {
        ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal)
    }
    private val progressCaptionView: TextView by lazy {
        demoText(AndroidDemoUiSpec.waitingProgressCaption, AndroidDemoUiSpec.captionTextSizeSp, Color.DKGRAY, false)
    }
    private val statusList: LinearLayout by lazy { LinearLayout(this).also { it.orientation = LinearLayout.VERTICAL } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = AndroidDemoStrings.navigationTitle
        setContentView(buildContentView())
        headlineView.text = AndroidDemoStrings.readyHeadline
        detailView.text = AndroidDemoStrings.readyDetail
        progressBar.progress = 0
        observedProgressTotal = 0
        progressCaptionView.text = AndroidDemoUiSpec.waitingProgressCaption
        statusList.removeAllViews()
    }

    override fun onStop() {
        runFuture?.cancel(true)
        super.onStop()
    }

    override fun onDestroy() {
        runFuture?.cancel(true)
        executor.shutdownNow()
        super.onDestroy()
    }

    // The fixed screen order makes every sample mode visible to instrumentation.
    private fun buildContentView(): View {
        val scrollView = ScrollView(this)
        val root = demoScreenContent()
        scrollView.addView(root)

        root.addView(demoText(AndroidDemoStrings.title, AndroidDemoUiSpec.titleTextSizeSp, Color.BLACK, true))
        root.addView(
            demoText(
                "Choose a claim or relationship to prove with on-device synthetic credentials.",
                AndroidDemoUiSpec.bodyTextSizeSp,
                Color.DKGRAY,
                false,
            ),
        )
        root.addView(
            demoText("1. What are you presenting?", AndroidDemoUiSpec.statusTitleTextSizeSp, Color.BLACK, true),
            fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp),
        )
        root.addView(subjectGroup)
        personaModeSection.addView(
            demoText("2. Who can see the persona?", AndroidDemoUiSpec.statusTitleTextSizeSp, Color.BLACK, true),
        )
        personaModeSection.addView(personaModeGroup)
        root.addView(personaModeSection, fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp))
        timingSection.addView(
            demoText("3. When will you prove it?", AndroidDemoUiSpec.statusTitleTextSizeSp, Color.BLACK, true),
        )
        timingSection.addView(timingGroup)
        root.addView(timingSection, fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp))
        root.addView(
            demoText("Proof settings", AndroidDemoUiSpec.statusTitleTextSizeSp, Color.BLACK, true),
            fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp),
        )
        root.addView(circuitHashGroup)

        val flowPanel = demoPanel()
        root.addView(flowPanel, fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp))
        flowPanel.addView(flowTitleView)
        flowPanel.addView(flowDescriptionView, fullWidthLayoutParams())
        credentialSubjectClaimButton.text = "Prove and Verify Credential Subject Claim"
        credentialSubjectClaimButton.tag = "credentialSubjectClaimGenerateButton"
        credentialSubjectClaimButton.setOnClickListener {
            runSample(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_CREDENTIAL_SUBJECT_CLAIM_V1)
        }
        flowPanel.addView(credentialSubjectClaimButton, fullWidthLayoutParams())
        privatePersonaButton.text = "Prove and Verify Private Persona"
        privatePersonaButton.tag = "privatePersonaRequestBoundButton"
        privatePersonaButton.setOnClickListener {
            runSample(ZkClaimProofBundleKind.ZK_CLAIM_PROOF_BUNDLE_KIND_PRIVATE_PERSONA_CLAIM_V1)
        }
        flowPanel.addView(privatePersonaButton, fullWidthLayoutParams())
        preparedPublicGenerateButton.text = "1. Prepare public proof stages"
        preparedPublicGenerateButton.tag = "preparedPublicGenerateButton"
        preparedPublicGenerateButton.setOnClickListener {
            preparePersonaSample(ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA)
        }
        flowPanel.addView(preparedPublicGenerateButton, fullWidthLayoutParams())
        preparedPublicVerifyButton.text = "2. Check cached stages"
        preparedPublicVerifyButton.tag = "preparedPublicVerifyButton"
        preparedPublicVerifyButton.isEnabled = false
        preparedPublicVerifyButton.setOnClickListener {
            verifyPersonaEvidenceSample(ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA)
        }
        flowPanel.addView(preparedPublicVerifyButton, fullWidthLayoutParams())
        preparedPrivateGenerateButton.text = "1. Prepare private proof stages"
        preparedPrivateGenerateButton.tag = "preparedPrivateGenerateButton"
        preparedPrivateGenerateButton.setOnClickListener {
            preparePersonaSample(ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA)
        }
        flowPanel.addView(preparedPrivateGenerateButton, fullWidthLayoutParams())
        preparedPrivateVerifyButton.text = "2. Check cached stages once"
        preparedPrivateVerifyButton.tag = "preparedPrivateVerifyButton"
        preparedPrivateVerifyButton.isEnabled = false
        preparedPrivateVerifyButton.setOnClickListener {
            verifyPersonaEvidenceSample(ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA)
        }
        flowPanel.addView(preparedPrivateVerifyButton, fullWidthLayoutParams())
        flowPanel.addView(preparedLimitView, fullWidthLayoutParams())
        commonCredentialRootButton.text = "Generate and Verify Nine Proofs"
        commonCredentialRootButton.tag = "commonCredentialRootGenerateButton"
        commonCredentialRootButton.setOnClickListener { generateCommonCredentialRootSample() }
        flowPanel.addView(commonCredentialRootButton, fullWidthLayoutParams())

        val progressPanel = demoPanel()
        root.addView(progressPanel, fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp))

        progressBar.max = AndroidDemoUiSpec.totalProgressUnits
        progressPanel.addView(headlineView)
        progressPanel.addView(detailView)
        progressPanel.addView(progressBar, fullWidthLayoutParams())
        progressPanel.addView(progressCaptionView)

        val statusTitle = demoText("Status", AndroidDemoUiSpec.statusTitleTextSizeSp, Color.BLACK, true)
        root.addView(statusTitle, fullWidthLayoutParams(topMargin = AndroidDemoUiSpec.sectionTopMarginDp))
        root.addView(statusList, fullWidthLayoutParams())

        renderFlowSelection()
        return scrollView
    }

    private val selectionRenderer: AndroidDemoFlowSelectionRenderer by lazy {
        AndroidDemoFlowSelectionRenderer(
            personaModeSection = personaModeSection,
            timingSection = timingSection,
            credentialSubjectClaimButton = credentialSubjectClaimButton,
            privatePersonaButton = privatePersonaButton,
            preparedPrivateGenerateButton = preparedPrivateGenerateButton,
            preparedPrivateVerifyButton = preparedPrivateVerifyButton,
            preparedPublicGenerateButton = preparedPublicGenerateButton,
            preparedPublicVerifyButton = preparedPublicVerifyButton,
            preparedLimitView = preparedLimitView,
            commonCredentialRootButton = commonCredentialRootButton,
            flowTitleView = flowTitleView,
            flowDescriptionView = flowDescriptionView,
        )
    }

    private fun renderFlowSelection() {
        selectionRenderer.renderFlowSelection(selectedSubject, selectedPersonaMode, selectedTiming)
    }

    private fun resetResultForSelection() {
        if (singleFlight.get()) return
        resultRenderer.resetForSelection()
    }

    private fun runSample(bundleKind: ZkClaimProofBundleKind) {
        if (singleFlight.compareAndSet(false, true) == false) {
            return
        }
        renderControls(running = true)
        val circuitHash = selectedCircuitHash
        runFuture =
            executor.submit {
                try {
                    val result =
                        demoRuntime.runFlow(bundleKind, circuitHash) { line ->
                            runOnUiThread { handleProgressLine(line) }
                        }
                    runOnUiThread {
                        renderSuccessState(
                            DemoSuccess.Bundle(
                                result.witnessMilliseconds,
                                result.proveMilliseconds,
                                result.verifyMilliseconds,
                            ),
                        )
                    }
                } catch (error: ReallyMeZkProviderException) {
                    val message = AndroidDemoStrings.providerFailureDetail(error.reason)
                    runOnUiThread {
                        renderFailureState(message)
                    }
                } catch (ignored: RuntimeException) {
                    runOnUiThread {
                        renderFailureState(AndroidDemoStrings.failureDetail)
                    }
                }
            }
    }

    private fun generateCommonCredentialRootSample() {
        if (singleFlight.compareAndSet(false, true) == false) {
            return
        }
        renderControls(running = true, commonCredentialRoot = true)
        val mode = selectedPersonaMode
        val hash = selectedCircuitHash
        runFuture =
            executor.submit {
                try {
                    val result =
                        demoRuntime.generateCommonCredentialRootSample(mode, hash) { completed ->
                            runOnUiThread {
                                progressBar.progress =
                                    completed * AndroidDemoUiSpec.totalProgressUnits /
                                    AndroidDemoUiSpec.COMMON_CREDENTIAL_ROOT_PROGRESS_STEPS
                                progressCaptionView.text =
                                    "$completed of ${AndroidDemoUiSpec.COMMON_CREDENTIAL_ROOT_PROOF_COUNT} " +
                                    "proofs generated"
                            }
                        }
                    runOnUiThread { renderSuccessState(DemoSuccess.CommonCredentialRoot(result)) }
                } catch (error: ReallyMeZkProviderException) {
                    val message = AndroidDemoStrings.providerFailureDetail(error.reason)
                    runOnUiThread { renderFailureState(message, isRoot = true) }
                } catch (ignored: RuntimeException) {
                    runOnUiThread { renderFailureState(AndroidDemoStrings.failureDetail, isRoot = true) }
                }
            }
    }

    private fun preparePersonaSample(mode: ZkCommonCredentialRootPersonaMode) {
        if (singleFlight.compareAndSet(false, true) == false) return
        if (mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
            preparedPublicProofs = null
            publicPreparedChecks = 0
            preparedPublicVerifyButton.text = "2. Check cached stages"
        } else {
            preparedPrivateProofs = null
        }
        renderControls(running = true, prepared = true)
        val hash = selectedCircuitHash
        runFuture =
            executor.submit {
                try {
                    val proofs = demoRuntime.preparePersonaSample(mode, hash)
                    runOnUiThread {
                        if (mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                            preparedPublicProofs = proofs
                        } else {
                            preparedPrivateProofs = proofs
                        }
                        renderSuccessState(DemoSuccess.Prepared(mode, proofs.generationMilliseconds, null))
                    }
                } catch (error: ReallyMeZkProviderException) {
                    runOnUiThread { renderFailureState(AndroidDemoStrings.providerFailureDetail(error.reason)) }
                } catch (ignored: RuntimeException) {
                    runOnUiThread { renderFailureState(AndroidDemoStrings.failureDetail) }
                }
            }
    }

    private fun verifyPersonaEvidenceSample(mode: ZkCommonCredentialRootPersonaMode) {
        if (singleFlight.compareAndSet(false, true) == false) return
        val selectedProofs =
            if (mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                preparedPublicProofs
            } else {
                preparedPrivateProofs
            }
        val proofs =
            selectedProofs ?: run {
                singleFlight.set(false)
                return
            }
        if (proofs.mode == ZkCommonCredentialRootPersonaMode.PRIVATE_PERSONA) {
            // A failed or interrupted local check still consumes this sample instance.
            preparedPrivateProofs = null
        }
        renderControls(running = true, prepared = true)
        runFuture =
            executor.submit {
                try {
                    val elapsed = demoRuntime.verifyCachedPersonaCredentialEvidenceStages(proofs)
                    runOnUiThread {
                        if (mode == ZkCommonCredentialRootPersonaMode.PUBLIC_PERSONA) {
                            if (publicPreparedChecks < Int.MAX_VALUE) {
                                publicPreparedChecks += 1
                            }
                            preparedPublicVerifyButton.text = "Check cached stages again ($publicPreparedChecks checks)"
                        }
                        renderSuccessState(DemoSuccess.Prepared(mode, proofs.generationMilliseconds, elapsed))
                    }
                } catch (error: ReallyMeZkProviderException) {
                    runOnUiThread { renderFailureState(AndroidDemoStrings.providerFailureDetail(error.reason)) }
                } catch (ignored: RuntimeException) {
                    runOnUiThread { renderFailureState(AndroidDemoStrings.failureDetail) }
                }
            }
    }

    private fun renderControls(
        running: Boolean,
        commonCredentialRoot: Boolean = false,
        prepared: Boolean = false,
    ) {
        selectionRenderer.setActionsEnabled(
            enabled = !running,
            hasPublicProofs = preparedPublicProofs != null,
            hasPrivateProofs = preparedPrivateProofs != null,
        )
        circuitHashGroup.setChoicesEnabled(!running)
        subjectGroup.setChoicesEnabled(!running)
        personaModeGroup.setChoicesEnabled(!running)
        timingGroup.setChoicesEnabled(!running)
        if (running) {
            resultRenderer.renderRunningState(commonCredentialRoot = commonCredentialRoot, prepared = prepared)
            if (commonCredentialRoot) commonCredentialRootButton.text = "Generating..."
            observedProgressTotal = 0
        } else {
            commonCredentialRootButton.text = "Generate and Verify Nine Proofs"
            runFuture = null
            singleFlight.set(false)
        }
    }

    private val resultRenderer: AndroidDemoResultRenderer by lazy {
        AndroidDemoResultRenderer(
            context = this,
            headlineView = headlineView,
            detailView = detailView,
            statusList = statusList,
            progressCaptionView = progressCaptionView,
            progressBar = progressBar,
            bodyTextSizeSp = AndroidDemoUiSpec.bodyTextSizeSp,
            totalProgressUnits = AndroidDemoUiSpec.totalProgressUnits,
            waitingProgressCaption = AndroidDemoUiSpec.waitingProgressCaption,
        )
    }

    private fun renderSuccessState(success: DemoSuccess) {
        resultRenderer.renderSuccessState(success, observedProgressTotal)
        renderControls(running = false)
    }

    private fun renderFailureState(
        message: String,
        isRoot: Boolean = false,
    ) {
        resultRenderer.renderFailureState(message, isRoot)
        renderControls(running = false)
    }

    private fun handleProgressLine(line: String) {
        observedProgressTotal = resultRenderer.renderProgressLine(line, observedProgressTotal)
    }
}
