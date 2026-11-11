// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.graphics.Color

/** Layout and progress-display values shared by the example activity. */
internal object AndroidDemoUiSpec {
    const val screenPaddingDp = 20
    const val panelPaddingDp = 16
    const val sectionTopMarginDp = 20
    const val titleTextSizeSp = 30
    const val headlineTextSizeSp = 20
    const val statusTitleTextSizeSp = 18
    const val bodyTextSizeSp = 14
    const val captionTextSizeSp = 12
    private const val PROGRESS_PANEL_RED = 242
    private const val PROGRESS_PANEL_GREEN = 242
    private const val PROGRESS_PANEL_BLUE = 247
    val progressPanelBackground: Int = Color.rgb(PROGRESS_PANEL_RED, PROGRESS_PANEL_GREEN, PROGRESS_PANEL_BLUE)
    const val circuitHashRadioIdOffset = 20_000
    const val personaModeRadioIdOffset = 30_000
    const val subjectRadioIdOffset = 40_000
    const val timingRadioIdOffset = 50_000
    const val totalProgressUnits = 1_000
    const val COMMON_CREDENTIAL_ROOT_PROOF_COUNT = 9
    const val COMMON_CREDENTIAL_ROOT_PROGRESS_STEPS = COMMON_CREDENTIAL_ROOT_PROOF_COUNT + 1
    const val waitingProgressCaption = "Waiting to start"
}
