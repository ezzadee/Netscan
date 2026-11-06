package com.netsentry.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun Panel(modifier: Modifier = Modifier, onClick: (() -> Unit)? = null, content: @Composable () -> Unit) {
    val shape = RoundedCornerShape(16.dp)
    var m = modifier
        .fillMaxWidth()
        .clip(shape)
        .background(Palette.Surface)
        .border(1.dp, Palette.Line, shape)
    if (onClick != null) m = m.clickable(onClick = onClick)
    Box(m.padding(16.dp)) { content() }
}

@Composable
fun Badge(text: String, color: Color) {
    Text(
        text, color = color, fontSize = 11.sp, fontWeight = FontWeight.SemiBold, maxLines = 1,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(color.copy(alpha = 0.14f))
            .padding(horizontal = 6.dp, vertical = 2.dp),
    )
}

@Composable
fun Dot(color: Color, size: Int = 8) {
    Box(Modifier.size(size.dp).clip(CircleShape).background(color))
}

@Composable
fun SegmentedTabs(labels: List<String>, selected: Int, onSelect: (Int) -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(Palette.Surface)
            .padding(4.dp)
    ) {
        labels.forEachIndexed { i, label ->
            val on = i == selected
            Box(
                Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(9.dp))
                    .background(if (on) Palette.SurfaceHigh else Color.Transparent)
                    .clickable { onSelect(i) }
                    .padding(vertical = 10.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(label, color = if (on) Palette.Text else Palette.Muted, fontSize = 13.sp, maxLines = 1,
                    fontWeight = if (on) FontWeight.SemiBold else FontWeight.Normal)
            }
        }
    }
}

@Composable
fun SectionLabel(text: String) {
    Text(text.uppercase(), color = Palette.Muted, fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
        letterSpacing = 1.sp, modifier = Modifier.padding(top = 8.dp))
}

@Composable
fun EmptyNote(text: String) {
    Panel { Text(text, color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp) }
}

@Composable
fun PrimaryButton(text: String, enabled: Boolean = true, color: Color = Palette.Accent, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth().height(48.dp),
        shape = RoundedCornerShape(12.dp),
        colors = ButtonDefaults.buttonColors(containerColor = color, contentColor = Palette.Bg),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

@Composable
fun SmallHeading(text: String) {
    Text(text, color = Palette.Text, fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
}
