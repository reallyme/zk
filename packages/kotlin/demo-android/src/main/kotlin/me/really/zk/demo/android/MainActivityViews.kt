// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
//
// SPDX-License-Identifier: MIT OR Apache-2.0

package me.really.zk.demo.android

import android.app.Activity
import android.graphics.Color
import android.graphics.Typeface
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.TextView

internal fun Activity.demoText(
    value: String,
    sizeSp: Int,
    color: Int,
    bold: Boolean,
): TextView {
    val view = TextView(this)
    view.text = value
    view.textSize = sizeSp.toFloat()
    view.setTextColor(color)
    if (bold) {
        view.typeface = Typeface.DEFAULT_BOLD
    }
    return view
}

internal fun Activity.fullWidthLayoutParams(topMargin: Int = DEFAULT_TOP_MARGIN_DP): LinearLayout.LayoutParams {
    val params =
        LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            LinearLayout.LayoutParams.WRAP_CONTENT,
        )
    params.topMargin = dp(topMargin)
    return params
}

internal fun Activity.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

internal fun <Selection : Any> Activity.demoRadioGroup(
    values: List<Selection>,
    selectedValue: Selection,
    radioIdOffset: Int,
    label: (Selection) -> String,
    onSelected: (Selection) -> Unit,
): RadioGroup {
    val group = RadioGroup(this)
    group.gravity = Gravity.CENTER
    for ((index, value) in values.withIndex()) {
        val radio = RadioButton(this)
        radio.id = index + radioIdOffset
        radio.text = label(value)
        radio.isChecked = value == selectedValue
        group.addView(radio)
    }
    group.setOnCheckedChangeListener { _, checkedId ->
        val index = checkedId - radioIdOffset
        val value = values.getOrNull(index)
        if (value != null) {
            onSelected(value)
        }
    }
    return group
}

internal fun RadioGroup.setChoicesEnabled(enabled: Boolean) {
    isEnabled = enabled
    for (index in 0 until childCount) {
        getChildAt(index).isEnabled = enabled
    }
}

internal fun LinearLayout.addStatusLine(
    activity: Activity,
    message: String,
    textSizeSp: Int,
) {
    val line = TextView(activity)
    line.text = "• $message"
    line.textSize = textSizeSp.toFloat()
    line.setTextColor(Color.BLACK)
    addView(line, activity.fullWidthLayoutParams(topMargin = STATUS_LINE_TOP_MARGIN_DP))
}

internal data class DemoProgressLine(
    val completedSteps: Int,
    val totalSteps: Int,
    val message: String,
)

internal fun parseDemoProgressLine(line: String): DemoProgressLine? {
    if (!line.startsWith(PROGRESS_PREFIX)) {
        return null
    }
    val parts = line.split("|", limit = PROGRESS_PART_COUNT)
    return parseDemoProgressParts(parts)
}

internal fun completedProgressCaption(
    completedSteps: Int,
    totalSteps: Int,
): String = "$completedSteps of $totalSteps steps complete"

internal const val STATUS_PREFIX: String = "UI_STATUS|"

private const val DEFAULT_TOP_MARGIN_DP = 12
private const val STATUS_LINE_TOP_MARGIN_DP = 6
private const val PROGRESS_PREFIX = "UI_PROGRESS|"
private const val PROGRESS_PART_COUNT = 4
private const val PROGRESS_CURRENT_INDEX = 1
private const val PROGRESS_TOTAL_INDEX = 2
private const val PROGRESS_MESSAGE_INDEX = 3

private fun parseDemoProgressParts(parts: List<String>): DemoProgressLine? {
    var parsed: DemoProgressLine? = null
    if (parts.size == PROGRESS_PART_COUNT) {
        parsed = parseExpectedDemoProgressParts(parts)
    }
    return parsed
}

private fun parseExpectedDemoProgressParts(parts: List<String>): DemoProgressLine? {
    val current = parts[PROGRESS_CURRENT_INDEX].toIntOrNull()
    val total = parts[PROGRESS_TOTAL_INDEX].toIntOrNull()
    return if (current != null && total != null && total > 0) {
        DemoProgressLine(
            completedSteps = current.coerceIn(0, total),
            totalSteps = total,
            message = parts[PROGRESS_MESSAGE_INDEX],
        )
    } else {
        null
    }
}
