package com.netsentry.app.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netsentry.app.apps.AppReport
import com.netsentry.app.apps.AppsViewModel
import com.netsentry.app.apps.Trackers
import com.netsentry.app.monitor.DnsEvent
import com.netsentry.app.monitor.MonitorRepository
import com.netsentry.app.scan.Severity

@Composable
fun AppsScreen(vm: AppsViewModel) {
    val state by vm.state.collectAsState()
    val events by MonitorRepository.events.collectAsState()
    var filter by rememberSaveable { mutableIntStateOf(0) }
    val apps = state.apps

    val liveByPkg = remember(events) { events.groupBy { it.packageName } }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item {
            Panel {
                Column {
                    Text("Installed apps", color = Palette.Text, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Reads each app's code for the servers built into it and for known tracking and ad " +
                            "SDKs, and lists the sensitive access it has. Nothing is uploaded. The first scan " +
                            "can take a few minutes; later scans only re-read apps that changed.",
                        color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp,
                    )
                    Spacer(Modifier.height(14.dp))
                    if (state.scanning) {
                        val progress = if (state.total == 0) 0f else state.done.toFloat() / state.total
                        LinearProgressIndicator(
                            progress = { progress },
                            modifier = Modifier.fillMaxWidth(),
                            color = Palette.Accent,
                            trackColor = Palette.Line,
                        )
                        Spacer(Modifier.height(8.dp))
                        Text("${state.done} of ${state.total} · ${state.current}", color = Palette.Muted,
                            fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    } else {
                        PrimaryButton(if (apps == null) "Scan apps" else "Scan apps again") { vm.scan() }
                    }
                }
            }
        }

        if (apps != null) {
            item { AppsSummary(apps) }
            item {
                SegmentedTabs(listOf("Review", "Trackers", "All (${apps.size})"), filter) { filter = it }
            }
            val shown = when (filter) {
                0 -> apps.filter { it.risk == Severity.HIGH || it.risk == Severity.MEDIUM }
                1 -> apps.filter { it.trackers.isNotEmpty() }.sortedByDescending { it.trackers.size }
                else -> apps
            }
            if (shown.isEmpty()) {
                item { EmptyNote(if (filter == 0) "No apps need review." else "No apps with known trackers.") }
            }
            items(shown, key = { it.packageName }) { app ->
                AppCard(app, liveByPkg[app.packageName].orEmpty())
            }
        }
    }
}

@Composable
private fun AppsSummary(apps: List<AppReport>) {
    val sideloaded = apps.count { !it.fromStore && !it.isSystem }
    val withTrackers = apps.count { it.trackers.isNotEmpty() }
    val powerful = apps.count { a -> a.specialAccess.any { !it.startsWith("Can ask") } }
    Panel {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Stat("${apps.size}", "apps")
            Stat("$withTrackers", "with trackers")
            Stat("$powerful", "powerful access")
            Stat("$sideloaded", "sideloaded")
        }
    }
}

@Composable
private fun Stat(value: String, label: String) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = Palette.Text, fontSize = 20.sp, fontWeight = FontWeight.Bold)
        Text(label, color = Palette.Muted, fontSize = 11.sp)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AppCard(app: AppReport, live: List<DnsEvent>) {
    var open by rememberSaveable(app.packageName) { mutableStateOf(false) }
    var allHosts by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val c = Palette.of(app.risk)

    Panel(onClick = { open = !open }) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Dot(c, 10)
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(app.label, color = Palette.Text, fontSize = 15.sp, fontWeight = FontWeight.SemiBold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(app.packageName, color = Palette.Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Spacer(Modifier.width(8.dp))
                Text(if (open) "▲" else "▼", color = Palette.Muted, fontSize = 12.sp)
            }
            Spacer(Modifier.height(8.dp))
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (app.risk != Severity.PASS) Badge(app.risk.label, c)
                Badge(if (app.fromStore || app.isSystem) "App store" else "Sideloaded",
                    if (app.fromStore || app.isSystem) Palette.Muted else Palette.Medium)
                if (app.trackers.isNotEmpty()) Badge("${app.trackers.size} trackers", Palette.Low)
                if (app.hosts.isNotEmpty()) Badge("${app.hosts.size} servers", Palette.Info)
                if (live.isNotEmpty()) Badge("Live", Palette.Accent)
            }

            if (open) {
                if (app.riskReasons.isNotEmpty()) {
                    SmallHeading("Why it's flagged")
                    app.riskReasons.forEach { Bullet(it) }
                }
                if (app.specialAccess.isNotEmpty()) {
                    SmallHeading("Special access")
                    app.specialAccess.forEach { Bullet(it) }
                }
                if (app.sensitiveGranted.isNotEmpty()) {
                    SmallHeading("Permissions granted")
                    Bullet(app.sensitiveGranted.joinToString())
                }
                SmallHeading("Tracking & ad SDKs in its code")
                if (app.trackers.isEmpty()) Bullet("None of the ${Trackers.sdks.size} known SDKs found")
                else app.trackers.forEach { Bullet("${it.name} — ${it.category}") }

                SmallHeading("Servers built into its code (${app.hosts.size})")
                if (app.hosts.isEmpty()) {
                    Bullet(if (app.hasInternet) "No web addresses found in its code (it may build them at runtime or be obfuscated)"
                    else "This app has no internet permission")
                } else {
                    val list = if (allHosts) app.hosts else app.hosts.take(25)
                    list.forEach { h -> HostLine(h.host, h.trackerOwner, null) }
                    if (app.hosts.size > 25) {
                        TextButton(onClick = { allHosts = !allHosts }, contentPadding = PaddingValues(0.dp)) {
                            Text(if (allHosts) "Show fewer" else "Show all ${app.hosts.size}", color = Palette.Info, fontSize = 12.sp)
                        }
                    }
                }

                SmallHeading("Seen live by the monitor")
                if (live.isEmpty()) {
                    Bullet("Nothing yet. Start the Monitor tab and use this app to see the servers it actually contacts.")
                } else {
                    live.groupBy { it.domain }
                        .map { (d, ev) -> Triple(d, ev.size, Trackers.ownerOf(d)) }
                        .sortedByDescending { it.second }
                        .take(40)
                        .forEach { (d, n, owner) -> HostLine(d, owner, "${n}×") }
                }

                Spacer(Modifier.height(8.dp))
                TextButton(
                    onClick = {
                        context.startActivity(
                            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:${app.packageName}"))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    },
                    contentPadding = PaddingValues(0.dp),
                ) { Text("Open app settings (permissions, uninstall)", color = Palette.Info, fontSize = 13.sp) }
            }
        }
    }
}

@Composable
fun Bullet(text: String) {
    Text("• $text", color = Palette.Muted, fontSize = 13.sp, lineHeight = 18.sp,
        modifier = Modifier.padding(vertical = 1.dp))
}

@Composable
fun HostLine(host: String, trackerOwner: String?, trailing: String?) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(host, color = Palette.Text, fontSize = 12.sp, fontFamily = FontFamily.Monospace,
            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
        if (trackerOwner != null) Badge(trackerOwner, Palette.Low)
        if (trailing != null) Text(trailing, color = Palette.Muted, fontSize = 12.sp)
    }
}
