package com.netsentry.app.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.netsentry.app.ScanViewModel
import com.netsentry.app.scan.Category
import com.netsentry.app.scan.CellTower
import com.netsentry.app.scan.Finding
import com.netsentry.app.scan.ScanReport
import com.netsentry.app.scan.Severity
import com.netsentry.app.scan.WifiNetwork
import com.netsentry.app.scan.WifiSecurity
import java.text.DateFormat
import java.util.Date

private fun requiredPermissions(): List<String> = buildList {
    add(Manifest.permission.ACCESS_FINE_LOCATION)
    add(Manifest.permission.ACCESS_COARSE_LOCATION)
    add(Manifest.permission.READ_PHONE_STATE)
    if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.NEARBY_WIFI_DEVICES)
}

@Composable
fun ScanScreen(vm: ScanViewModel) {
    val state by vm.state.collectAsState()
    val context = LocalContext.current
    val perms = remember { requiredPermissions() }
    fun missing() = perms.filter {
        ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
    }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { vm.scan(missing()) }
    val startScan = {
        val m = missing()
        if (m.isEmpty()) vm.scan(emptyList()) else launcher.launch(m.toTypedArray())
    }
    var tab by remember { mutableIntStateOf(0) }
    val report = state.report

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { ScoreCard(report, state.scanning, startScan) }

        if (report != null) {
            item {
                SegmentedTabs(
                    listOf("Findings", "Wi-Fi (${report.wifiNetworks.size})", "Towers (${report.cells.size})"),
                    tab,
                ) { tab = it }
            }
            when (tab) {
                0 -> {
                    Category.entries.forEach { cat ->
                        val list = report.findings.filter { it.category == cat }.sortedBy { it.severity.ordinal }
                        if (list.isNotEmpty()) {
                            item(key = "h-$cat") { SectionLabel(cat.title) }
                            items(list) { FindingCard(it) }
                        }
                    }
                }
                1 -> {
                    if (report.wifiNetworks.isEmpty()) item { EmptyNote("No Wi-Fi networks in the last scan.") }
                    items(report.wifiNetworks) { WifiRow(it, it.ssid == report.connectedSsid) }
                }
                else -> {
                    if (report.cells.isEmpty()) item { EmptyNote("No cell towers reported. Location and Phone permissions are required.") }
                    items(report.cells) { CellRow(it) }
                }
            }
        } else if (!state.scanning) {
            item { IntroCard() }
        }
        item { LimitsCard(onReset = vm::resetBaseline) }
    }
}

@Composable
private fun ScoreCard(report: ScanReport?, scanning: Boolean, onScan: () -> Unit) {
    Panel {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                ScoreRing(report?.score, scanning)
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    val (headline, sub) = when {
                        scanning -> "Scanning…" to "Checking this phone, nearby Wi-Fi and cell towers."
                        report == null -> "Not scanned yet" to "Tap Scan to check your surroundings."
                        else -> verdict(report)
                    }
                    Text(headline, color = Palette.Text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(4.dp))
                    Text(sub, color = Palette.Muted, fontSize = 13.sp)
                    if (report != null && !scanning) {
                        Spacer(Modifier.height(8.dp))
                        Counts(report.findings)
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            PrimaryButton(if (report == null) "Scan" else "Scan again", enabled = !scanning, onClick = onScan)
            if (report != null) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "Last scan ${DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(report.timestamp))}",
                    color = Palette.Muted, fontSize = 12.sp,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                )
            }
        }
    }
}

private fun verdict(r: ScanReport): Pair<String, String> {
    val high = r.findings.count { it.severity == Severity.HIGH }
    val med = r.findings.count { it.severity == Severity.MEDIUM }
    return when {
        high > 0 -> "Needs attention" to "$high serious issue(s) found. Start with the red items."
        med > 0 -> "Mostly OK" to "No serious threats, but $med thing(s) worth fixing."
        else -> "Looking good" to "No threats detected in this scan."
    }
}

@Composable
private fun ScoreRing(score: Int?, scanning: Boolean) {
    Box(Modifier.size(96.dp), contentAlignment = Alignment.Center) {
        if (scanning) {
            CircularProgressIndicator(Modifier.size(88.dp), color = Palette.Accent, strokeWidth = 8.dp)
        } else {
            val color = when {
                score == null -> Palette.Line
                score >= 85 -> Palette.Pass
                score >= 60 -> Palette.Low
                score >= 40 -> Palette.Medium
                else -> Palette.High
            }
            Canvas(Modifier.size(88.dp)) {
                val stroke = Stroke(width = 8.dp.toPx(), cap = StrokeCap.Round)
                drawArc(Palette.Line, -90f, 360f, false, style = stroke)
                if (score != null) drawArc(color, -90f, 360f * score / 100f, false, style = stroke)
            }
            Text(score?.toString() ?: "–", color = Palette.Text, fontSize = 28.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
private fun Counts(findings: List<Finding>) {
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        listOf(Severity.HIGH, Severity.MEDIUM, Severity.LOW).forEach { s ->
            val n = findings.count { it.severity == s }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Dot(Palette.of(s))
                Spacer(Modifier.width(4.dp))
                Text("$n ${s.label}", color = Palette.Muted, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun FindingCard(f: Finding) {
    val c = Palette.of(f.severity)
    Panel {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Dot(c)
                Spacer(Modifier.width(6.dp))
                Text(f.severity.label.uppercase(), color = c, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.8.sp)
            }
            Spacer(Modifier.height(6.dp))
            Text(f.title, color = Palette.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(f.detail, color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp)
            f.fix?.let {
                Spacer(Modifier.height(10.dp))
                Box(
                    Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(10.dp))
                        .background(Palette.SurfaceHigh)
                        .padding(10.dp)
                ) {
                    Text("Fix: $it", color = Palette.Text, fontSize = 13.sp, lineHeight = 18.sp)
                }
            }
        }
    }
}

@Composable
private fun WifiRow(n: WifiNetwork, connected: Boolean) {
    val secColor = when {
        n.security.isWeak -> Palette.High
        n.security == WifiSecurity.WPA -> Palette.Medium
        n.security == WifiSecurity.OWE -> Palette.Low
        else -> Palette.Pass
    }
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(n.ssid.ifEmpty { "(hidden network)" }, color = Palette.Text, fontSize = 15.sp,
                        fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f, fill = false))
                    if (connected) Badge("Connected", Palette.Info)
                    if (n.flagged) Badge("Suspicious", Palette.High)
                }
                Spacer(Modifier.height(4.dp))
                Text("${n.bssid} · ${n.band}", color = Palette.Muted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Badge(n.security.label + if (n.wps) " · WPS" else "", secColor)
                Spacer(Modifier.height(4.dp))
                Text("${n.levelDbm} dBm", color = Palette.Muted, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun CellRow(c: CellTower) {
    val genColor = when (c.generation) {
        "2G" -> Palette.High
        "3G" -> Palette.Medium
        else -> Palette.Pass
    }
    Panel {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("${c.radio} ${c.generation}", color = Palette.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
                    if (c.serving) Badge("Serving", Palette.Info)
                    if (c.firstSeenNow) Badge("New", Palette.Low)
                }
                Spacer(Modifier.height(4.dp))
                val parts = listOfNotNull(
                    c.mcc?.let { m -> "MCC-MNC $m-${c.mnc ?: "?"}" },
                    c.areaCode?.let { "Area $it" },
                    c.cellId?.let { "Cell $it" },
                    c.pci?.let { "PCI $it" },
                )
                Text(parts.joinToString(" · ").ifEmpty { "Neighbor cell (no ID reported)" },
                    color = Palette.Muted, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
            }
            Spacer(Modifier.width(8.dp))
            Column(horizontalAlignment = Alignment.End) {
                Badge(c.generation, genColor)
                Spacer(Modifier.height(4.dp))
                Text(c.dbm?.let { "$it dBm" } ?: "—", color = Palette.Muted, fontSize = 12.sp)
            }
        }
    }
}

@Composable
private fun IntroCard() {
    Panel {
        Column {
            Text("What gets checked", color = Palette.Text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(8.dp))
            listOf(
                "This phone — patch level, screen lock, rooting, USB debugging, sideloaded apps, Private DNS",
                "Your Wi-Fi — encryption type, WPS, captive portals, new access points",
                "Nearby Wi-Fi — open copies of secured networks (evil twins), weak encryption",
                "Cell towers — 2G downgrades, area-code changes, unknown towers (signs of fake towers)",
            ).forEach {
                Text("• $it", color = Palette.Muted, fontSize = 13.sp, lineHeight = 19.sp)
            }
            Spacer(Modifier.height(8.dp))
            Text("Android asks for Location and Phone access because it only shares Wi-Fi and tower lists with apps that have them. Nothing leaves your phone.",
                color = Palette.Muted, fontSize = 12.sp, lineHeight = 17.sp)
        }
    }
}

@Composable
private fun LimitsCard(onReset: () -> Unit) {
    Panel {
        Column {
            Text("Limits", color = Palette.Text, fontSize = 14.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            Text(
                "A phone app can't prove a tower or hotspot is fake — these are warning signs. Tower checks " +
                    "get more useful after a few days of scans in your usual places.",
                color = Palette.Muted, fontSize = 12.sp, lineHeight = 17.sp,
            )
            TextButton(onClick = onReset, contentPadding = PaddingValues(0.dp)) {
                Text("Forget learned networks and towers", color = Palette.Info, fontSize = 12.sp)
            }
        }
    }
}
