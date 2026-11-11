// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.app.Activity
import android.widget.LinearLayout

/** Keep the action and progress panels visually consistent. */
internal fun Activity.demoPanel(): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val padding = dp(AndroidDemoUiSpec.panelPaddingDp)
        setPadding(padding, padding, padding, padding)
        setBackgroundColor(AndroidDemoUiSpec.progressPanelBackground)
    }

internal fun Activity.demoScreenContent(): LinearLayout =
    LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        val padding = dp(AndroidDemoUiSpec.screenPaddingDp)
        setPadding(padding, padding, padding, padding)
    }
