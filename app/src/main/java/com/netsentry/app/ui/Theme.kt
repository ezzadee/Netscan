package com.netsentry.app.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import com.netsentry.app.scan.Severity

object Palette {
    val Bg = Color(0xFF0E1116)
    val Surface = Color(0xFF171B22)
    val SurfaceHigh = Color(0xFF20262F)
    val Line = Color(0xFF2A313C)
    val Text = Color(0xFFE6EAF0)
    val Muted = Color(0xFF8D96A5)
    val Accent = Color(0xFF2BD9A0)

    val High = Color(0xFFFF5C5C)
    val Medium = Color(0xFFFFA94D)
    val Low = Color(0xFFFFD43B)
    val Info = Color(0xFF74C0FC)
    val Pass = Accent

    fun of(s: Severity): Color = when (s) {
        Severity.HIGH -> High
        Severity.MEDIUM -> Medium
        Severity.LOW -> Low
        Severity.INFO -> Info
        Severity.PASS -> Pass
    }
}

@Composable
fun NetSentryTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Palette.Accent,
            onPrimary = Palette.Bg,
            background = Palette.Bg,
            onBackground = Palette.Text,
            surface = Palette.Surface,
            onSurface = Palette.Text,
            surfaceVariant = Palette.SurfaceHigh,
            onSurfaceVariant = Palette.Muted,
        ),
        content = content,
    )
}
